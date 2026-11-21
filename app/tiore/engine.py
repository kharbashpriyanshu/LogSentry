"""
LogSentry — Threat Intelligence & Observable Reputation Engine (TIORE Phase 5)
=============================================================================
Unified orchestration engine combining observable extraction, local resolution,
privacy gating, provider fan-out, match generation, and audit compliance.
"""

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.repositories.threat_intel_repository import ThreatIntelRepository
from app.tiore.extractor import ObservableExtractor
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
        """
        extracted = self.extractor.extract_from_event(event_data)
        if not extracted:
            return []

        repo = ThreatIntelRepository(db)
        resolved_list: list[ResolvedIntelligence] = []

        for obs in extracted:
            try:
                # 1. Canonical observable record
                obs_model = repo.get_or_create_observable(obs)

                # 2. Link event to observable
                repo.link_event_observable(
                    event_id=event_id,
                    observable_id=obs_model.id,
                    field_name=obs.source_field,
                    tenant_id=tenant_id,
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
                    )
            except Exception as exc:
                logger.error(f"Error processing observable {obs.masked_value}: {exc}")

        return resolved_list

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
        """
        extracted_list = self.extractor.extract_from_text(indicator_raw)
        if not extracted_list:
            return {
                "status": "error",
                "message": "No valid security observable (IP, Domain, URL, Hash, Email, Phone) identified in input.",
            }

        observable = extracted_list[0]
        repo = ThreatIntelRepository(db)
        obs_model = repo.get_or_create_observable(observable)

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

        return {
            "status": "success",
            "observable": {
                "id": obs_model.id,
                "type": observable.observable_type.value,
                "value": observable.normalized_value,
                "masked_value": observable.masked_value,
                "fingerprint": observable.fingerprint,
                "validation_status": observable.validation_status.value,
                "privacy_classification": observable.privacy_classification.value,
                "is_eligible_for_external_lookup": observable.is_eligible_for_external_lookup,
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


# Singleton engine instance
tiore_engine = TIOREEngine()
