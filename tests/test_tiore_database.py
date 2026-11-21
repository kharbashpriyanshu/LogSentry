"""
LogSentry — TIORE Database Models & Multi-Tenant Repository Tests
=================================================================
Verifies SQLAlchemy persistence, entity relationships, cascade deletions,
idempotent observable tracking, and multi-tenant isolation.
"""

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.base import Base
from app.models.log_event import LogEventModel
from app.models.threat_intel import (
    EventObservableModel,
    ObservableModel,
    ThreatIntelAuditModel,
    ThreatIntelMatchModel,
    ThreatIntelRecordModel,
    ThreatIntelSourceModel,
)
from app.repositories.threat_intel_repository import ThreatIntelRepository
from app.tiore.extractor import ObservableExtractor
from app.tiore.models import ObservableType


@pytest.fixture
def db_session():
    """In-memory SQLite session with full table schema."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def repo(db_session):
    return ThreatIntelRepository(db_session)


@pytest.fixture
def extractor():
    return ObservableExtractor(hmac_key="test-tiore-db-salt")


# ==============================================================================
# 1. Observable Canonical Persistence & Idempotency
# ==============================================================================

def test_get_or_create_observable_idempotency(repo, extractor):
    extracted = extractor.validate_and_normalize_ip("198.51.100.42", source_field="source_ip")
    assert extracted is not None

    # First insert creates row
    obs1 = repo.get_or_create_observable(extracted)
    assert obs1.id is not None
    assert obs1.value == "198.51.100.42"
    assert obs1.type == ObservableType.IPV4.value
    assert obs1.fingerprint == extracted.fingerprint

    # Second insert updates last_seen without creating duplicate row
    obs2 = repo.get_or_create_observable(extracted)
    assert obs2.id == obs1.id
    assert repo.db.query(ObservableModel).count() == 1


def test_get_observable_queries(repo, extractor):
    extracted = extractor.validate_and_normalize_domain("evil-phish.net")
    assert extracted is not None
    created = repo.get_or_create_observable(extracted)

    by_fp = repo.get_observable_by_fingerprint(extracted.fingerprint)
    assert by_fp is not None
    assert by_fp.id == created.id

    by_val = repo.get_observable_by_value(ObservableType.DOMAIN.value, "evil-phish.net")
    assert by_val is not None
    assert by_val.id == created.id


# ==============================================================================
# 2. Threat Sources & Records
# ==============================================================================

def test_threat_source_and_record_retention(repo, extractor):
    # Setup source
    source = repo.get_or_create_source(
        source_id="abuseipdb",
        name="AbuseIPDB IP Reputation",
        category="reputation",
        reliability_tier=4,
        supported_types=["ipv4", "ipv6"],
    )
    assert source.id == "abuseipdb"
    assert source.reliability_tier == 4

    # Setup observable
    extracted = extractor.validate_and_normalize_ip("185.220.101.5")
    obs = repo.get_or_create_observable(extracted)

    # Save threat record
    record = repo.save_record(
        observable_id=obs.id,
        source_id=source.id,
        classification="MALICIOUS",
        confidence=0.95,
        threat_types=["brute_force", "ssh_scan"],
        evidence={"abuse_confidence_score": 95, "total_reports": 142},
    )
    assert record.id is not None
    assert record.classification == "MALICIOUS"
    assert record.confidence == 0.95

    # Fetch records
    records = repo.get_records_for_observable(obs.id)
    assert len(records) == 1
    assert records[0].source_id == "abuseipdb"
    assert records[0].threat_types == ["brute_force", "ssh_scan"]


# ==============================================================================
# 3. Multi-Tenant Event Linking & Match Isolation
# ==============================================================================

def test_event_observable_linking(repo, extractor, db_session):
    # Create fake log event
    log_event = LogEventModel(
        id=str(uuid.uuid4()),
        timestamp=datetime.now(UTC),
        raw_log="test log with ip 198.51.100.42",
        tenant_id="tenant-alpha",
    )
    db_session.add(log_event)
    db_session.commit()

    extracted = extractor.validate_and_normalize_ip("198.51.100.42")
    obs = repo.get_or_create_observable(extracted)

    link = repo.link_event_observable(
        event_id=log_event.id,
        observable_id=obs.id,
        field_name="raw_log",
        tenant_id="tenant-alpha",
    )
    assert link.id is not None
    assert link.tenant_id == "tenant-alpha"

    # Verify duplicate linking is idempotent
    link2 = repo.link_event_observable(
        event_id=log_event.id,
        observable_id=obs.id,
        field_name="raw_log",
        tenant_id="tenant-alpha",
    )
    assert link2.id == link.id


def test_multi_tenant_match_isolation(repo, extractor):
    obs = repo.get_or_create_observable(extractor.validate_and_normalize_ip("185.220.101.5"))

    # Create match for Tenant Alpha
    repo.create_match(
        observable_id=obs.id,
        classification="MALICIOUS",
        confidence=0.90,
        verdict_reason="Known SSH Scanner",
        tenant_id="tenant-alpha",
    )

    # Create match for Tenant Bravo
    repo.create_match(
        observable_id=obs.id,
        classification="SUSPICIOUS",
        confidence=0.55,
        verdict_reason="Recent Tor Exit Node",
        tenant_id="tenant-bravo",
    )

    # STRICT TENANT BOUNDARY: Tenant Alpha MUST NOT see Tenant Bravo's matches
    alpha_matches = repo.get_matches(tenant_id="tenant-alpha", is_admin=False)
    assert len(alpha_matches) == 1
    assert alpha_matches[0].tenant_id == "tenant-alpha"
    assert alpha_matches[0].verdict_reason == "Known SSH Scanner"

    bravo_matches = repo.get_matches(tenant_id="tenant-bravo", is_admin=False)
    assert len(bravo_matches) == 1
    assert bravo_matches[0].tenant_id == "tenant-bravo"

    # Admin can inspect all matches
    admin_matches = repo.get_matches(tenant_id="default", is_admin=True)
    assert len(admin_matches) == 2


# ==============================================================================
# 4. Multi-Tenant Audit Log Isolation
# ==============================================================================

def test_multi_tenant_audit_isolation(repo):
    repo.record_audit(
        actor_id="user-1",
        actor_username="analyst_alpha",
        actor_role="Tier1_Analyst",
        tenant_id="tenant-alpha",
        observable_type="email",
        masked_value="u***1@corp.com",
        fingerprint="hmac-hash-alpha",
        lookup_method="MANUAL_SEARCH",
        external_disclosed=False,
    )

    repo.record_audit(
        actor_id="user-2",
        actor_username="analyst_bravo",
        actor_role="Tier2_Analyst",
        tenant_id="tenant-bravo",
        observable_type="phone",
        masked_value="+18***-***4589",
        fingerprint="hmac-hash-bravo",
        lookup_method="MANUAL_SEARCH",
        external_disclosed=False,
    )

    # Strict isolation
    alpha_audits = repo.get_audits(tenant_id="tenant-alpha", is_admin=False)
    assert len(alpha_audits) == 1
    assert alpha_audits[0].actor_username == "analyst_alpha"

    bravo_audits = repo.get_audits(tenant_id="tenant-bravo", is_admin=False)
    assert len(bravo_audits) == 1
    assert bravo_audits[0].actor_username == "analyst_bravo"

    admin_audits = repo.get_audits(tenant_id="default", is_admin=True)
    assert len(admin_audits) == 2


# ==============================================================================
# 5. Cascade Deletion Integrity
# ==============================================================================

def test_observable_cascade_deletion(repo, extractor, db_session):
    obs = repo.get_or_create_observable(extractor.validate_and_normalize_ip("198.51.100.99"))
    source = repo.get_or_create_source("otx", "OTX", "feed")

    repo.save_record(obs.id, source.id, "MALICIOUS", 0.8)
    repo.create_match(obs.id, "MALICIOUS", 0.8, "Test match", "tenant-alpha")

    assert db_session.query(ThreatIntelRecordModel).count() == 1
    assert db_session.query(ThreatIntelMatchModel).count() == 1

    # Deleting observable cascades to records and matches
    db_session.delete(obs)
    db_session.commit()

    assert db_session.query(ThreatIntelRecordModel).count() == 0
    assert db_session.query(ThreatIntelMatchModel).count() == 0
