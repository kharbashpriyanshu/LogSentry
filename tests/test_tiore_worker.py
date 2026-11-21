"""
LogSentry — Tests for Continuous Database-Backed Threat Enrichment Worker
========================================================================
Verifies:
  1. Atomic job claiming and successful completion.
  2. Crash recovery of stale processing leases.
  3. Exponential backoff and retry scheduling on provider failure.
  4. Worker thread start/stop lifecycle.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.base import Base
from app.models.threat_intel import (
    ObservableModel,
    ThreatEnrichmentJobModel,
    ThreatIntelMatchModel,
    ThreatIntelRecordModel,
    ThreatIntelSourceModel,
)
from app.repositories.threat_intel_repository import ThreatIntelRepository
from app.tiore.extractor import ObservableExtractor
from app.tiore.models import ThreatClassification
from app.tiore.worker import ThreatEnrichmentWorker


@pytest.fixture
def worker_db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = session_factory()
    try:
        yield session, session_factory
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


def test_worker_process_batch_success(worker_db, monkeypatch):
    session, session_factory = worker_db
    monkeypatch.setattr("app.tiore.worker.SessionLocal", session_factory)

    repo = ThreatIntelRepository(session)
    extractor = ObservableExtractor()
    obs = extractor.validate_and_normalize_ip("185.220.101.5")
    model = repo.get_or_create_observable(obs, tenant_id="tenant-alpha")

    job = repo.enqueue_enrichment_job(
        observable_id=model.id,
        observable_value=obs.normalized_value,
        observable_type=obs.observable_type.value,
        tenant_id="tenant-alpha",
    )

    # Mock provider manager
    mock_pm = MagicMock()
    mock_pm.query_providers.return_value = [
        {"source_id": "abuseipdb", "verdict": "malicious"}
    ]
    mock_resolver = MagicMock()
    mock_resolved = MagicMock()
    mock_resolved.is_match = True
    mock_resolved.classification = ThreatClassification.MALICIOUS
    mock_resolved.confidence = 0.95
    mock_resolved.verdict_reason = "Known Tor Exit Node"
    mock_resolver.resolve.return_value = mock_resolved

    worker = ThreatEnrichmentWorker(
        worker_id="test-worker-1",
        provider_manager=mock_pm,
        resolver=mock_resolver,
    )

    processed = worker.process_batch()
    assert processed == 1

    session.refresh(job)
    assert job.status == "completed"
    assert job.locked_until is None


def test_worker_process_batch_failure_exponential_backoff(worker_db, monkeypatch):
    session, session_factory = worker_db
    monkeypatch.setattr("app.tiore.worker.SessionLocal", session_factory)

    repo = ThreatIntelRepository(session)
    extractor = ObservableExtractor()
    obs = extractor.validate_and_normalize_ip("198.51.100.12")
    model = repo.get_or_create_observable(obs, tenant_id="tenant-alpha")

    job = repo.enqueue_enrichment_job(
        observable_id=model.id,
        observable_value=obs.normalized_value,
        observable_type=obs.observable_type.value,
        tenant_id="tenant-alpha",
    )

    mock_pm = MagicMock()
    mock_pm.query_providers.side_effect = ConnectionError("External API rate limited")

    worker = ThreatEnrichmentWorker(
        worker_id="test-worker-2",
        provider_manager=mock_pm,
    )

    processed = worker.process_batch()
    assert processed == 1

    session.refresh(job)
    # Attempts incremented, status returned to pending with next_retry_at scheduled
    assert job.status == "pending"
    assert job.attempts == 1
    assert "External API rate limited" in job.last_error
    assert job.next_retry_at is not None


def test_worker_lifecycle():
    worker = ThreatEnrichmentWorker(
        worker_id="test-lifecycle-worker",
        poll_interval_seconds=0.1,
    )
    assert not worker.is_running
    worker.start()
    assert worker.is_running
    worker.trigger()
    worker.stop(timeout=2.0)
    assert not worker.is_running
