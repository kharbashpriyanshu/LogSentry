"""
LogSentry — Threat Intelligence & Observable Reputation Engine (TIORE Phase 5)
=============================================================================
Unified orchestration engine combining observable extraction, local resolution,
privacy gating, asynchronous background external provider fan-out, match generation,
operational telemetry, and strict PII access controls.
"""

import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from sqlalchemy.orm import Session

from app.core.crypto import decrypt_pii
from app.database.session import SessionLocal
from app.repositories.threat_intel_repository import ThreatIntelRepository
from app.tiore.extractor import ObservableExtractor
from app.tiore.metrics import tiore_metrics
from app.tiore.models import (
    ObservableType,
    ThreatClassification,
)
from app.tiore.providers.manager import ProviderManager
from app.tiore.resolver import IntelligenceResolver, ResolvedIntelligence

logger = logging.getLogger(__name__)


class TIOREEngine:
    """
    Core TIORE Engine orchestrating indicator lifecycle across LogSentry.
    """

    def __init__(
        self,
        extractor: ObservableExtractor | None = None,
        resolver: IntelligenceResolver | None = None,
        provider_manager: ProviderManager | None = None,
    ):
        self.extractor = extractor or ObservableExtractor()
        self.resolver = resolver or IntelligenceResolver()
        self.provider_manager = provider_manager or ProviderManager()
        self._executor = ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="tiore-bg"
        )

    # -------------------------------------------------------------------------
    # Ingestion Pipeline Integration (< 2ms synchronous path)
    # -------------------------------------------------------------------------

    def process_event_observables(
        self,
        event_id: str,
        event_data: dict[str, Any],
        tenant_id: str,
        db: Session,
        alert_id: str | None = None,
        incident_id: str | None = None,
    ) -> list[ResolvedIntelligence]:
        """
        Extracts observables from an incoming event, maps event-observable links,
        resolves reputation from local intelligence/cache, and records threat matches.
        Batches database writes and dispatches asynchronous background external lookups
        for eligible public indicators without blocking log ingestion.
        """
        try:
            extracted = self.extractor.extract_from_event(event_data)
        except Exception as exc:
            tiore_metrics.record_error(
                "extraction_error",
                str(exc),
                {"event_id": event_id, "tenant_id": tenant_id},
            )
            logger.warning(
                "TIORE extraction failed on event %s: %s",
                event_id,
                exc,
                exc_info=True,
            )
            return []

        if not extracted:
            return []

        tiore_metrics.record_event_processed(len(extracted))
        repo = ThreatIntelRepository(db)
        resolved_list: list[ResolvedIntelligence] = []
        eligible_for_external: list[tuple[Any, str]] = []

        for obs in extracted:
            try:
                # 1. Canonical observable record (batched without commit per observable)
                obs_model = repo.get_or_create_observable(
                    obs,
                    tenant_id=tenant_id,
                    is_shared=False,
                    commit=False,
                )

                # 2. Link event to observable
                repo.link_event_observable(
                    event_id=event_id,
                    observable_id=obs_model.id,
                    field_name=obs.source_field,
                    tenant_id=tenant_id,
                    commit=False,
                )

                # 3. Resolve intelligence (hot memory cache or local DB)
                resolved = self.resolver.resolve(obs, tenant_id=tenant_id, db=db)
                resolved_list.append(resolved)

                # 4. If matched as a known threat, create a tenant-scoped threat match
                if resolved.is_match and resolved.classification in (
                    ThreatClassification.MALICIOUS,
                    ThreatClassification.SUSPICIOUS,
                    ThreatClassification.EXPOSED,
                ):
                    repo.create_match(
                        observable_id=obs_model.id,
                        classification=resolved.classification.value,
                        confidence=resolved.confidence,
                        verdict_reason=resolved.verdict_reason,
                        tenant_id=tenant_id,
                        event_id=event_id,
                        alert_id=alert_id,
                        incident_id=incident_id,
                        commit=False,
                    )
                    tiore_metrics.record_match()

                # 5. Check if eligible for asynchronous external background lookup
                if obs.is_eligible_for_external_lookup:
                    cache_key = f"{tenant_id}:{obs.fingerprint}"
                    cached_val = self.resolver.cache.get(cache_key)
                    # If not cached or unresolved, queue background enrichment
                    if (
                        cached_val is None
                        or cached_val.classification == ThreatClassification.UNKNOWN
                    ):
                        job = repo.enqueue_enrichment_job(
                            observable_id=obs_model.id,
                            observable_value=obs.normalized_value,
                            observable_type=obs.observable_type.value,
                            tenant_id=tenant_id,
                            event_id=event_id,
                            alert_id=alert_id,
                            commit=False,
                        )
                        eligible_for_external.append((obs, job.id))

            except Exception as exc:
                tiore_metrics.record_error(
                    "observable_processing_error",
                    str(exc),
                    {"event_id": event_id, "observable": obs.masked_value},
                )
                logger.warning(
                    "TIORE observable processing error on %s in event %s: %s",
                    obs.masked_value,
                    event_id,
                    exc,
                    exc_info=True,
                )

        # Batch commit all link & match records for this event in a single transaction
        try:
            db.commit()
        except Exception as exc:
            db.rollback()
            tiore_metrics.record_error(
                "db_commit_error",
                str(exc),
                {"event_id": event_id, "tenant_id": tenant_id},
            )
            logger.warning(
                "TIORE DB batch commit failed for event %s: %s",
                event_id,
                exc,
                exc_info=True,
            )

        # Dispatch background external lookups asynchronously (non-blocking)
        for public_obs, job_id in eligible_for_external:
            self.schedule_background_enrichment(
                observable=public_obs,
                tenant_id=tenant_id,
                job_id=job_id,
                event_id=event_id,
                alert_id=alert_id,
            )

        return resolved_list

    # -------------------------------------------------------------------------
    # Asynchronous External Threat Enrichment
    # -------------------------------------------------------------------------

    def schedule_background_enrichment(
        self,
        observable: Any,
        tenant_id: str,
        job_id: str | None = None,
        event_id: str | None = None,
        alert_id: str | None = None,
    ) -> None:
        """
        Schedules non-blocking asynchronous external threat intelligence lookups
        for eligible public indicators.
        """
        if not getattr(observable, "is_eligible_for_external_lookup", False):
            return

        tiore_metrics.record_background_queued()
        try:
            self._executor.submit(
                self._background_enrichment_worker,
                observable,
                tenant_id,
                job_id,
                event_id,
                alert_id,
            )
        except Exception as exc:
            tiore_metrics.record_error(
                "background_queue_error",
                str(exc),
                {"observable": getattr(observable, "masked_value", "unknown")},
            )
            logger.warning("Failed to queue background enrichment: %s", exc)

    def _background_enrichment_worker(
        self,
        observable: Any,
        tenant_id: str,
        job_id: str | None = None,
        event_id: str | None = None,
        alert_id: str | None = None,
    ) -> None:
        """
        Worker executed in thread pool: queries external feeds, stores results,
        refreshes local cache, and creates match records if newly classified as malicious.
        """
        db = SessionLocal()
        repo = ThreatIntelRepository(db)
        if job_id:
            repo.mark_enrichment_job_processing(job_id)
        try:
            results = self.provider_manager.query_providers(observable)
            if results:
                self.provider_manager.persist_results(observable, results, db=db)
                resolved = self.resolver.resolve(
                    observable,
                    tenant_id=tenant_id,
                    db=db,
                    bypass_cache=True,
                )

                if resolved.is_match and resolved.classification in (
                    ThreatClassification.MALICIOUS,
                    ThreatClassification.SUSPICIOUS,
                ):
                    obs_model = repo.get_or_create_observable(
                        observable, tenant_id=tenant_id
                    )
                    repo.create_match(
                        observable_id=obs_model.id,
                        classification=resolved.classification.value,
                        confidence=resolved.confidence,
                        verdict_reason=f"[External Feed Consensus] {resolved.verdict_reason}",
                        tenant_id=tenant_id,
                        event_id=event_id,
                        alert_id=alert_id,
                    )
                    tiore_metrics.record_match()

            if job_id:
                repo.mark_enrichment_job_completed(job_id)
            tiore_metrics.record_background_completed()
        except Exception as exc:
            if job_id:
                try:
                    repo.mark_enrichment_job_failed(job_id, str(exc))
                except Exception:
                    pass
            tiore_metrics.record_error(
                "background_execution_error",
                str(exc),
                {"observable": getattr(observable, "masked_value", "unknown")},
            )
            logger.warning(
                "Background enrichment execution failed for %s: %s",
                getattr(observable, "masked_value", "unknown"),
                exc,
                exc_info=True,
            )
        finally:
            db.close()

    def reconcile_pending_enrichment_jobs(self, limit: int = 50) -> int:
        """
        Reconciles any uncompleted or crashed enrichment jobs from the database
        on startup, scheduling them for execution.
        """
        db = SessionLocal()
        count = 0
        try:
            repo = ThreatIntelRepository(db)
            jobs = repo.get_pending_enrichment_jobs(limit=limit)
            for job in jobs:
                extracted_list = self.extractor.extract_from_text(job.observable_value)
                if extracted_list:
                    obs = extracted_list[0]
                    self.schedule_background_enrichment(
                        observable=obs,
                        tenant_id=job.tenant_id,
                        job_id=job.id,
                        event_id=job.event_id,
                        alert_id=job.alert_id,
                    )
                    count += 1
                else:
                    repo.mark_enrichment_job_failed(
                        job.id, "Unable to parse observable value"
                    )
        except Exception as exc:
            logger.error("Failed to reconcile pending enrichment jobs: %s", exc)
        finally:
            db.close()
        return count

    # -------------------------------------------------------------------------
    # Manual Analyst Investigation API
    # -------------------------------------------------------------------------

    def investigate_indicator(
        self,
        indicator_raw: str,
        tenant_id: str,
        actor_id: str,
        actor_username: str,
        actor_role: str,
        db: Session,
        force_external: bool = False,
    ) -> dict[str, Any]:
        """
        Performs in-depth indicator analysis for SOC analysts.
        Audits every query and enforces strict privacy checks on external lookups.
        Always masks PII identifiers by default.
        """
        extracted_list = self.extractor.extract_from_text(indicator_raw)
        if not extracted_list:
            return {
                "status": "error",
                "message": "No valid security observable (IP, Domain, URL, Hash, Email, Phone) identified in input.",
            }

        observable = extracted_list[0]
        repo = ThreatIntelRepository(db)
        obs_model = repo.get_or_create_observable(
            observable, tenant_id=tenant_id, is_shared=False
        )

        external_disclosed = False
        disclosed_to: list[str] = []

        # Check if external provider query is requested and permissible
        if force_external:
            if observable.is_eligible_for_external_lookup or (
                observable.observable_type == ObservableType.EMAIL
            ):
                results = self.provider_manager.query_providers(observable)
                if results:
                    self.provider_manager.persist_results(observable, results, db=db)
                    external_disclosed = True
                    disclosed_to = [
                        r.source_id for r in results if r.status == "success"
                    ]

        # Audit the investigation query
        repo.record_audit(
            actor_id=actor_id,
            actor_username=actor_username,
            actor_role=actor_role,
            tenant_id=tenant_id,
            observable_type=observable.observable_type.value,
            masked_value=observable.masked_value,
            fingerprint=observable.fingerprint,
            lookup_method="manual_investigation",
            external_disclosed=external_disclosed,
            disclosed_to=disclosed_to,
        )

        # Resolve updated intelligence
        resolved = self.resolver.resolve(
            observable, tenant_id=tenant_id, db=db, bypass_cache=force_external
        )

        # Default display value: PII indicators MUST remain masked unless explicitly unmasked
        is_pii = observable.observable_type in (
            ObservableType.EMAIL,
            ObservableType.PHONE,
        )
        safe_display_value = (
            observable.masked_value if is_pii else observable.normalized_value
        )

        return {
            "status": "success",
            "observable": {
                "id": obs_model.id,
                "type": observable.observable_type.value,
                "value": safe_display_value,
                "masked_value": observable.masked_value,
                "fingerprint": observable.fingerprint,
                "validation_status": observable.validation_status.value,
                "privacy_classification": observable.privacy_classification.value,
                "is_eligible_for_external_lookup": observable.is_eligible_for_external_lookup,
                "is_pii": is_pii,
                "first_seen": (
                    obs_model.first_seen.isoformat() if obs_model.first_seen else None
                ),
                "last_seen": (
                    obs_model.last_seen.isoformat() if obs_model.last_seen else None
                ),
            },
            "reputation": resolved.to_dict(),
            "audit": {
                "audited": True,
                "actor_username": actor_username,
                "tenant_id": tenant_id,
                "external_disclosed": external_disclosed,
                "disclosed_to": disclosed_to,
            },
        }

    def unmask_pii_observable(
        self,
        observable_id: str,
        tenant_id: str,
        actor_id: str,
        actor_username: str,
        actor_role: str,
        db: Session,
        is_admin: bool = False,
    ) -> dict[str, Any]:
        """
        Decrypts retained PII observable value for authorized personnel.
        Enforces tenant authorization and records a non-repudiable audit event.
        """
        repo = ThreatIntelRepository(db)
        obs = repo.get_observable_by_id(
            observable_id, tenant_id=tenant_id, is_admin=is_admin
        )
        if not obs:
            return {
                "status": "error",
                "message": "Observable not found or access denied.",
            }

        if not obs.encrypted_value:
            # Non-PII or not encrypted
            return {
                "status": "success",
                "observable_id": obs.id,
                "unmasked_value": obs.value,
                "masked_value": obs.raw_masked,
            }

        try:
            unmasked = decrypt_pii(obs.encrypted_value)
        except Exception as exc:
            tiore_metrics.record_error(
                "decryption_error", str(exc), {"observable_id": obs.id}
            )
            logger.error("Failed to decrypt PII observable %s: %s", obs.id, exc)
            return {
                "status": "error",
                "message": "Failed to decrypt PII observable value.",
            }

        # Audit the unmask operation
        repo.record_audit(
            actor_id=actor_id,
            actor_username=actor_username,
            actor_role=actor_role,
            tenant_id=tenant_id,
            observable_type=obs.type,
            masked_value=obs.raw_masked,
            fingerprint=obs.fingerprint,
            lookup_method="pii_unmask_authorized",
            external_disclosed=False,
            disclosed_to=[],
        )

        return {
            "status": "success",
            "observable_id": obs.id,
            "unmasked_value": unmasked,
            "masked_value": obs.raw_masked,
        }


# Singleton engine instance
tiore_engine = TIOREEngine()
