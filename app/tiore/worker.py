"""
LogSentry — TIORE Continuous Database-Backed Threat Enrichment Worker
=====================================================================
Continuously processes background threat intelligence lookups with:
  1. Atomic job leasing (locked_until, locked_by) to prevent concurrent duplication.
  2. Crash recovery of stale processing jobs.
  3. Automatic exponential retry backoff.
  4. Bounded execution queues and graceful shutdown handling.
"""

import logging
import threading
import uuid
from typing import Any

from app.database.session import SessionLocal
from app.repositories.threat_intel_repository import ThreatIntelRepository
from app.tiore.extractor import ObservableExtractor
from app.tiore.metrics import tiore_metrics
from app.tiore.models import ThreatClassification
from app.tiore.providers.manager import ProviderManager
from app.tiore.resolver import IntelligenceResolver

logger = logging.getLogger(__name__)


class ThreatEnrichmentWorker:
    """
    Durable, continuously polling background worker for TIORE enrichment jobs.
    """

    def __init__(
        self,
        worker_id: str | None = None,
        poll_interval_seconds: float = 2.0,
        lease_duration_seconds: int = 60,
        batch_size: int = 5,
        extractor: ObservableExtractor | None = None,
        resolver: IntelligenceResolver | None = None,
        provider_manager: ProviderManager | None = None,
    ):
        self.worker_id = worker_id or f"tiore-worker-{uuid.uuid4().hex[:8]}"
        self.poll_interval = poll_interval_seconds
        self.lease_duration = lease_duration_seconds
        self.batch_size = batch_size

        self.extractor = extractor or ObservableExtractor()
        self.resolver = resolver or IntelligenceResolver()
        self.provider_manager = provider_manager or ProviderManager()

        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def start(self) -> None:
        """Starts the background worker thread."""
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._wake_event.clear()
            self._thread = threading.Thread(
                target=self._run_loop,
                name=f"ThreatEnrichment-{self.worker_id}",
                daemon=True,
            )
            self._thread.start()
            logger.info("ThreatEnrichmentWorker started (id=%s)", self.worker_id)

    def stop(self, timeout: float = 5.0) -> None:
        """Signals the worker to shut down gracefully and awaits termination."""
        with self._lock:
            if not self._thread or not self._thread.is_alive():
                return
            self._stop_event.set()
            self._wake_event.set()
            self._thread.join(timeout=timeout)
            logger.info("ThreatEnrichmentWorker stopped (id=%s)", self.worker_id)

    def trigger(self) -> None:
        """Notifies the worker to immediately wake and poll for new jobs."""
        self._wake_event.set()

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _run_loop(self) -> None:
        """Main continuous execution loop."""
        while not self._stop_event.is_set():
            try:
                processed_count = self.process_batch()
                if processed_count == 0:
                    # Sleep until next poll or until notified of a new job
                    self._wake_event.wait(timeout=self.poll_interval)
                    self._wake_event.clear()
            except Exception as exc:
                logger.error(
                    "Unexpected error in ThreatEnrichmentWorker loop: %s",
                    exc,
                    exc_info=True,
                )
                self._stop_event.wait(timeout=self.poll_interval)

    def process_batch(self) -> int:
        """
        Claims and processes one batch of pending or stale-recovered jobs.
        Returns the number of jobs processed.
        """
        db = SessionLocal()
        claimed_jobs: list[Any] = []
        try:
            repo = ThreatIntelRepository(db)
            claimed_jobs = repo.claim_pending_jobs(
                worker_id=self.worker_id,
                limit=self.batch_size,
                lease_duration_seconds=self.lease_duration,
            )
        except Exception as exc:
            logger.error("Failed to claim enrichment jobs: %s", exc)
            return 0
        finally:
            db.close()

        if not claimed_jobs:
            return 0

        for job in claimed_jobs:
            self._execute_job(
                job.id, job.observable_value, job.tenant_id, job.event_id, job.alert_id
            )

        return len(claimed_jobs)

    def _execute_job(
        self,
        job_id: str,
        observable_val: str,
        tenant_id: str,
        event_id: str | None,
        alert_id: str | None,
    ) -> None:
        """Executes a single claimed job with isolated database session and error handling."""
        db = SessionLocal()
        repo = ThreatIntelRepository(db)
        try:
            extracted_list = self.extractor.extract_from_text(observable_val)
            if not extracted_list:
                repo.mark_enrichment_job_failed(
                    job_id, f"Invalid observable payload: {observable_val}"
                )
                return

            observable = extracted_list[0]
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

            repo.mark_enrichment_job_completed(job_id)
            tiore_metrics.record_background_completed()
        except Exception as exc:
            repo.mark_enrichment_job_failed(job_id, str(exc))
            tiore_metrics.record_error(
                "background_worker_execution_error",
                str(exc),
                {"job_id": job_id, "observable": observable_val},
            )
            logger.warning(
                "Enrichment job %s execution failed: %s",
                job_id,
                exc,
                exc_info=True,
            )
        finally:
            db.close()


# Singleton background worker instance
tiore_worker = ThreatEnrichmentWorker()
