"""
LogSentry — TIORE Provider Manager (TIORE Phase 4)
==================================================
Orchestrates parallel provider queries with bounded concurrency,
aggregates feed responses, updates source health states, and
persists findings to the threat database repository.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime, timedelta
import logging
from typing import Any

from sqlalchemy.orm import Session

from app.models.threat_intel import ObservableModel
from app.repositories.threat_intel_repository import ThreatIntelRepository
from app.tiore.models import ExtractedObservable, ThreatClassification
from app.tiore.providers.abuseipdb import AbuseIPDBAdapter
from app.tiore.providers.alienvault import AlienVaultOTXAdapter
from app.tiore.providers.base import BaseObservableAdapter, ProviderLookupResult
from app.tiore.providers.hibp import HIBPPrefixAdapter
from app.tiore.providers.threatfox import ThreatFoxAdapter
from app.tiore.providers.urlhaus import URLhausAdapter
from app.tiore.providers.virustotal import VirusTotalAdapter

logger = logging.getLogger(__name__)


class ProviderManager:
    """
    Central coordinator for threat intelligence provider queries.
    """

    def __init__(self, adapters: list[BaseObservableAdapter] | None = None):
        if adapters is not None:
            self.adapters = adapters
        else:
            self.adapters = [
                AbuseIPDBAdapter(),
                AlienVaultOTXAdapter(),
                URLhausAdapter(),
                ThreatFoxAdapter(),
                VirusTotalAdapter(),
                HIBPPrefixAdapter(),
            ]

    def register_adapter(self, adapter: BaseObservableAdapter) -> None:
        self.adapters.append(adapter)

    def get_eligible_adapters(self, observable: ExtractedObservable) -> list[BaseObservableAdapter]:
        return [adapter for adapter in self.adapters if adapter.is_eligible(observable)]

    def query_providers(
        self,
        observable: ExtractedObservable,
        max_workers: int = 4,
        overall_timeout_sec: float = 3.5,
    ) -> list[ProviderLookupResult]:
        """
        Executes parallel lookups across all eligible providers with bounded latency.
        """
        eligible = self.get_eligible_adapters(observable)
        if not eligible:
            return []

        results: list[ProviderLookupResult] = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_adapter = {
                executor.submit(adapter.lookup, observable): adapter
                for adapter in eligible
            }

            try:
                for future in as_completed(future_to_adapter, timeout=overall_timeout_sec):
                    adapter = future_to_adapter[future]
                    try:
                        res = future.result()
                        results.append(res)
                    except Exception as exc:
                        logger.warning(f"Error querying provider {adapter.source_id}: {exc}")
                        results.append(
                            ProviderLookupResult(
                                source_id=adapter.source_id,
                                classification=ThreatClassification.UNKNOWN,
                                confidence=0.0,
                                status="error",
                                error_message=str(exc),
                            )
                        )
            except TimeoutError:
                logger.warning(f"Overall timeout exceeded during provider queries for {observable.masked_value}")

        return results

    def persist_results(
        self,
        observable: ExtractedObservable,
        results: list[ProviderLookupResult],
        db: Session,
        ttl_days: int = 14,
    ) -> list[str]:
        """
        Persists successful provider results into the database threat records.
        Updates threat source health status.
        """
        if not results:
            return []

        repo = ThreatIntelRepository(db)
        obs_record: ObservableModel = repo.get_or_create_observable(observable)
        now = datetime.now(UTC)
        expires_at = now + timedelta(days=ttl_days)
        saved_record_ids: list[str] = []

        for r in results:
            if r.status in ("success", "not_found"):
                rec = repo.save_record(
                    observable_id=obs_record.id,
                    source_id=r.source_id,
                    classification=r.classification.value,
                    confidence=r.confidence,
                    threat_types=r.threat_types,
                    evidence=r.evidence,
                    raw_payload=r.raw_payload,
                    first_reported=now,
                    last_reported=now,
                    expires_at=expires_at,
                )
                saved_record_ids.append(rec.id)
                repo.update_source_health(r.source_id, health_status="healthy")
            elif r.status == "rate_limited":
                repo.update_source_health(
                    r.source_id,
                    health_status="degraded",
                    rate_limit_state={"status": "rate_limited", "timestamp": now.isoformat()},
                )
            elif r.status == "error":
                repo.update_source_health(
                    r.source_id,
                    health_status="unhealthy",
                )

        return saved_record_ids
