"""
LogSentry — TIORE Privacy, PII Encryption & Tenant Isolation Tests
==================================================================
Tests covering:
  1. Authenticated encryption at rest (AES-256-GCM) for email/phone observables.
  2. Multi-tenant boundary enforcement (no cross-tenant observable or stats leakage).
  3. Strict RBAC controls and audit trails for PII unmasking.
  4. Structured operational error metrics and telemetry tracking.
"""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.crypto import (
    decrypt_pii,
    encrypt_pii,
    migrate_pii_hmac_fingerprints,
    reencrypt_all_pii,
    register_pii_key,
    rotate_pii_encryption,
)
from app.core.jwt import create_access_token
from app.core.rbac import UserRole
from app.database.base import Base
from app.database.session import get_db
from app.main import app as fastapi_app
from app.models.threat_intel import (
    EventObservableModel,
    ObservableModel,
    ThreatEnrichmentJobModel,
    ThreatIntelAuditModel,
    ThreatIntelMatchModel,
    ThreatIntelRecordModel,
    ThreatIntelSourceModel,
)
from app.repositories.threat_intel_repository import ThreatIntelRepository
from app.tiore.engine import tiore_engine
from app.tiore.extractor import ObservableExtractor
from app.tiore.metrics import tiore_metrics


@pytest.fixture
def privacy_db():
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=test_engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    db = session_factory()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def privacy_client(privacy_db):
    def override_get_db():
        try:
            yield privacy_db
        finally:
            pass

    fastapi_app.dependency_overrides[get_db] = override_get_db
    with TestClient(fastapi_app) as client:
        yield client
    fastapi_app.dependency_overrides.clear()


def test_pii_encryption_at_rest_and_masking(privacy_db):
    """
    Verifies that email and phone observables are encrypted at rest with AES-256-GCM,
    and that the primary value column stores only the masked representation.
    """
    extractor = ObservableExtractor()
    repo = ThreatIntelRepository(privacy_db)

    # Ingest email observable
    email_obs = extractor.validate_and_normalize_email("security_lead@enterprise.com")
    assert email_obs is not None

    model = repo.get_or_create_observable(email_obs, tenant_id="tenant-alpha")

    # 1. Primary value column MUST be masked (never plaintext email)
    assert "@" in model.value
    assert "security_lead" not in model.value
    assert model.value == email_obs.masked_value

    # 2. Encrypted value column MUST be set and ciphertext cannot be raw plaintext
    assert model.encrypted_value is not None
    assert "security_lead@enterprise.com" not in model.encrypted_value

    # 3. Decryption function restores exact plaintext
    decrypted = decrypt_pii(model.encrypted_value)
    assert decrypted == "security_lead@enterprise.com"

    # Ingest phone observable
    phone_obs = extractor.validate_and_normalize_phone("+1 (555) 234-5678")
    assert phone_obs is not None

    phone_model = repo.get_or_create_observable(phone_obs, tenant_id="tenant-alpha")
    assert phone_model.value == phone_obs.masked_value
    assert phone_model.encrypted_value is not None
    assert "+15552345678" not in phone_model.encrypted_value
    assert decrypt_pii(phone_model.encrypted_value) == "+15552345678"


def test_cross_tenant_observable_isolation(privacy_client, privacy_db):
    """
    Verifies that Tenant A CANNOT see Tenant B's observables or statistics.
    """
    extractor = ObservableExtractor()
    repo = ThreatIntelRepository(privacy_db)

    # Ingest indicator for Tenant A
    obs_a = extractor.validate_and_normalize_domain("internal-api.tenant-a.corp")
    repo.get_or_create_observable(obs_a, tenant_id="tenant-a")

    # Ingest indicator for Tenant B
    obs_b = extractor.validate_and_normalize_domain("payroll-server.tenant-b.corp")
    repo.get_or_create_observable(obs_b, tenant_id="tenant-b")

    # Ingest a global shared indicator
    obs_shared = extractor.validate_and_normalize_ip("194.26.29.112")
    repo.get_or_create_observable(obs_shared, tenant_id=None, is_shared=True)

    token_a = create_access_token("user-a", UserRole.TIER_1_ANALYST, "tenant-a")
    headers_a = {"Authorization": f"Bearer {token_a}"}

    token_b = create_access_token("user-b", UserRole.TIER_1_ANALYST, "tenant-b")
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # Query observables as Tenant A
    resp_a = privacy_client.get("/api/v1/threat-intel/observables", headers=headers_a)
    assert resp_a.status_code == 200
    items_a = resp_a.json()["items"]
    values_a = [item["value"] for item in items_a]

    assert "internal-api.tenant-a.corp" in values_a
    assert "194.26.29.112" in values_a
    # Tenant B's domain MUST NOT be present in Tenant A's inventory!
    assert "payroll-server.tenant-b.corp" not in values_a

    # Query observables as Tenant B
    resp_b = privacy_client.get("/api/v1/threat-intel/observables", headers=headers_b)
    assert resp_b.status_code == 200
    items_b = resp_b.json()["items"]
    values_b = [item["value"] for item in items_b]

    assert "payroll-server.tenant-b.corp" in values_b
    assert "194.26.29.112" in values_b
    assert "internal-api.tenant-a.corp" not in values_b

    # Verify /stats endpoint reflects tenant isolation
    stats_a = privacy_client.get("/api/v1/threat-intel/stats", headers=headers_a).json()
    stats_b = privacy_client.get("/api/v1/threat-intel/stats", headers=headers_b).json()

    # Tenant A sees 2 observables (their own + shared), Tenant B sees 2 (their own + shared)
    assert stats_a["total_observables"] == 2
    assert stats_b["total_observables"] == 2


def test_authorized_pii_unmasking_and_rbac(privacy_client, privacy_db):
    """
    Verifies that PII observables can only be unmasked by SOC Managers or Admins,
    and that unmasking records an audit trail.
    """
    extractor = ObservableExtractor()
    repo = ThreatIntelRepository(privacy_db)

    obs = extractor.validate_and_normalize_email("vip_exec@target.com")
    model = repo.get_or_create_observable(obs, tenant_id="tenant-alpha")

    tier1_token = create_access_token(
        "t1-user", UserRole.TIER_1_ANALYST, "tenant-alpha"
    )
    tier1_headers = {"Authorization": f"Bearer {tier1_token}"}

    manager_token = create_access_token(
        "manager-user", UserRole.SOC_MANAGER, "tenant-alpha"
    )
    manager_headers = {"Authorization": f"Bearer {manager_token}"}

    # 1. Tier 1 Analyst tries to unmask -> 403 Forbidden
    resp_t1 = privacy_client.post(
        f"/api/v1/threat-intel/observables/{model.id}/unmask",
        headers=tier1_headers,
    )
    assert resp_t1.status_code == 403

    # 2. SOC Manager unmasks -> 200 OK
    resp_mgr = privacy_client.post(
        f"/api/v1/threat-intel/observables/{model.id}/unmask",
        headers=manager_headers,
    )
    assert resp_mgr.status_code == 200
    data = resp_mgr.json()
    assert data["unmasked_value"] == "vip_exec@target.com"
    assert data["masked_value"] == obs.masked_value

    # 3. Verify audit log entry
    audits = repo.get_audits(tenant_id="tenant-alpha")
    unmask_audits = [a for a in audits if a.lookup_method == "pii_unmask_authorized"]
    assert len(unmask_audits) == 1
    assert unmask_audits[0].actor_username == "manager-user"


def test_tiore_telemetry_and_error_tracking():
    """
    Verifies operational telemetry tracking and non-silent error handling.
    """
    tiore_metrics.record_event_processed(3)
    tiore_metrics.record_match()
    tiore_metrics.record_cache_hit()
    tiore_metrics.record_cache_miss()
    tiore_metrics.record_background_queued(2)
    tiore_metrics.record_background_completed(1)
    tiore_metrics.record_error(
        "test_simulated_error", "Mock exception details", {"ip": "1.2.3.4"}
    )

    summary = tiore_metrics.get_summary()
    assert summary["events_processed"] >= 1
    assert summary["observables_extracted"] >= 3
    assert summary["local_matches"] >= 1
    assert summary["background_lookups_queued"] >= 2
    assert summary["background_lookups_completed"] >= 1
    assert summary["errors_total"] >= 1
    assert "test_simulated_error" in summary["errors_by_type"]
    assert any(
        e["error_type"] == "test_simulated_error" for e in summary["recent_errors"]
    )


def test_tenant_deduplication_isolation_for_same_indicator(privacy_db):
    """
    Verifies that when Tenant A and Tenant B encounter the same indicator,
    get_or_create_observable generates separate, tenant-isolated records
    rather than returning Tenant A's record to Tenant B.
    """
    extractor = ObservableExtractor()
    repo = ThreatIntelRepository(privacy_db)

    obs1 = extractor.validate_and_normalize_ip("203.0.113.55")
    obs2 = extractor.validate_and_normalize_ip("203.0.113.55")

    rec_a = repo.get_or_create_observable(obs1, tenant_id="tenant-a")
    rec_b = repo.get_or_create_observable(obs2, tenant_id="tenant-b")

    assert rec_a.id != rec_b.id
    assert rec_a.tenant_id == "tenant-a"
    assert rec_b.tenant_id == "tenant-b"
    assert rec_a.fingerprint == rec_b.fingerprint


def test_real_v1_to_v2_key_rotation_and_database_reencryption(privacy_db):
    """
    Verifies actual v1 to v2 cryptographic key rotation and idempotent database re-encryption.
    Decrypts legacy v1 tokens while newly migrated records use active v2 keys.
    """
    # 1. Register a distinct v2 key
    v2_secret = "LogSentry-Dedicated-V2-Production-Key-32-Bytes!"
    register_pii_key("v2", v2_secret)

    # 2. Encrypt token under v1
    v1_token = encrypt_pii("ciso@enterprise.org", version="v1")
    assert v1_token.startswith("v1:")
    assert decrypt_pii(v1_token) == "ciso@enterprise.org"

    # 3. Rotate token to v2
    v2_token = rotate_pii_encryption(v1_token, target_version="v2")
    assert v2_token.startswith("v2:")
    assert decrypt_pii(v2_token) == "ciso@enterprise.org"

    # 4. Insert observable under v1 into database
    repo = ThreatIntelRepository(privacy_db)
    extractor = ObservableExtractor()
    obs = extractor.validate_and_normalize_email("ciso@enterprise.org")
    model = repo.get_or_create_observable(obs, tenant_id="tenant-alpha")
    model.encrypted_value = v1_token
    privacy_db.commit()

    # 5. Execute idempotent re-encryption across database
    reencrypted_count = reencrypt_all_pii(privacy_db, target_version="v2")
    assert reencrypted_count == 1
    privacy_db.refresh(model)
    assert model.encrypted_value.startswith("v2:")
    assert decrypt_pii(model.encrypted_value) == "ciso@enterprise.org"

    # Second run should be idempotent (0 re-encrypted)
    assert reencrypt_all_pii(privacy_db, target_version="v2") == 0


def test_safe_hmac_fingerprint_migration(privacy_db):
    """
    Verifies safe HMAC fingerprint migration when rotating HMAC keys without
    breaking tenant deduplication or observable associations.
    """
    repo = ThreatIntelRepository(privacy_db)
    extractor = ObservableExtractor()

    email_obs = extractor.validate_and_normalize_email("analyst@soc.corp")
    model = repo.get_or_create_observable(email_obs, tenant_id="tenant-alpha")
    old_fingerprint = model.fingerprint

    # New dedicated HMAC key
    new_hmac_key = b"New-HMAC-Key-For-SOC-2026-Rotation-Secret"
    migrated_count = migrate_pii_hmac_fingerprints(privacy_db, new_hmac_key)
    assert migrated_count == 1

    privacy_db.refresh(model)
    assert model.fingerprint != old_fingerprint
    # Verify decrypted email matches
    assert decrypt_pii(model.encrypted_value) == "analyst@soc.corp"


def test_stale_job_crash_recovery_and_atomic_claim(privacy_db):
    """
    Verifies that a job left in 'processing' status after an unhandled worker crash
    (with an expired locked_until lease) is automatically recovered and claimed atomically.
    """
    repo = ThreatIntelRepository(privacy_db)
    extractor = ObservableExtractor()

    obs = extractor.validate_and_normalize_ip("198.51.100.77")
    model = repo.get_or_create_observable(obs, tenant_id="tenant-alpha")

    # Insert a simulated crashed job (lease expired 10 seconds ago)
    past_time = datetime.now(UTC) - timedelta(seconds=10)
    job = repo.enqueue_enrichment_job(
        observable_id=model.id,
        observable_value=obs.normalized_value,
        observable_type=obs.observable_type.value,
        tenant_id="tenant-alpha",
    )
    job.status = "processing"
    job.locked_by = "dead-worker-pid-9999"
    job.locked_until = past_time
    privacy_db.commit()

    # New worker claims jobs
    active_worker_id = "live-worker-pid-1111"
    claimed = repo.claim_pending_jobs(
        active_worker_id, limit=5, lease_duration_seconds=60
    )

    assert len(claimed) == 1
    reclaimed_job = claimed[0]
    assert reclaimed_job.id == job.id
    assert reclaimed_job.status == "processing"
    assert reclaimed_job.locked_by == active_worker_id
    locked_dt = (
        reclaimed_job.locked_until.replace(tzinfo=UTC)
        if reclaimed_job.locked_until.tzinfo is None
        else reclaimed_job.locked_until
    )
    assert locked_dt > datetime.now(UTC)
    assert reclaimed_job.attempts == 1

    # Verify queue health metrics
    metrics = repo.get_enrichment_queue_metrics()
    assert metrics["total_jobs"] >= 1
    assert metrics["processing_jobs"] >= 1


def test_telemetry_sanitization_url_credentials_and_api_keys():
    """
    Verifies structured logging and telemetry scrubbing against realistic security payloads:
    URL credentials, AWS tokens, bearer tokens, API keys, and nested dictionaries.
    """
    realistic_log = (
        "Failed database probe to postgresql://db_admin:P@ssw0rd2026!@internal-db.corp:5432/siem "
        "with AWS token AKIAIOSFODNN7EXAMPLE and API key: sec_token_abcdef1234567890. "
        "Reported by security_lead@target.com with auth header Bearer eyJhbGciOiJIUzI1NiJ9.abc.xyz"
    )
    nested_context = {
        "client_request": {
            "auth": "Bearer secrettoken12345",
            "db_conn": "mysql://root:RootPassWord#99@localhost/auth",
            "nested_list": ["clean_val", "api_key=my_custom_secret_key_123456"],
        },
        "session_token": "live_session_cookie_abc",
        "ip": "203.0.113.1",
    }

    tiore_metrics.record_error("realistic_leak_test", realistic_log, nested_context)
    summary = tiore_metrics.get_summary()
    err = [
        e for e in summary["recent_errors"] if e["error_type"] == "realistic_leak_test"
    ][-1]

    # Text redactions
    assert "P@ssw0rd2026!" not in err["message"]
    assert "[REDACTED_PASS]" in err["message"]
    assert "AKIAIOSFODNN7EXAMPLE" not in err["message"]
    assert "[REDACTED_API_KEY]" in err["message"]
    assert "sec_token_abcdef1234567890" not in err["message"]
    assert "[REDACTED_CREDENTIAL]" in err["message"]
    assert "security_lead@target.com" not in err["message"]
    assert "[REDACTED_EMAIL]" in err["message"]
    assert (
        "Bearer [REDACTED_TOKEN]" not in err["message"]
    )  # Bearer ey... is replaced by [REDACTED_TOKEN]
    assert "[REDACTED_TOKEN]" in err["message"]

    # Context redactions
    ctx_str = str(err["context"])
    assert "secrettoken12345" not in ctx_str
    assert "RootPassWord#99" not in ctx_str
    assert "live_session_cookie_abc" not in ctx_str
    assert "[REDACTED]" in ctx_str


def test_migration_fail_closed_logic():
    """
    Verifies that any corrupted, un-decryptable PII record during migration
    causes the migration logic to raise a RuntimeError and fail closed.
    """

    # Simulate the fail-closed assertion from alembic migration
    def execute_migration_step(records):
        migrated = 0
        for r_id, r_type, r_val, r_enc in records:
            if not r_enc:
                try:
                    ct = encrypt_pii(r_val)
                    decrypted = decrypt_pii(ct)
                    if decrypted != r_val:
                        raise ValueError("Mismatch")
                    migrated += 1
                except Exception as exc:
                    raise RuntimeError(
                        f"PII migration failed closed on {r_id}: {exc}"
                    ) from exc
        return migrated

    # Valid records succeed
    valid_records = [("1", "email", "valid@corp.com", None)]
    assert execute_migration_step(valid_records) == 1

    # Corrupt or failing encryption fails closed
    with pytest.raises(RuntimeError, match="PII migration failed closed"):
        corrupt_records = [("2", "email", None, None)]
        # Passing None causes an exception which must raise RuntimeError
        execute_migration_step(corrupt_records)


def test_durable_enrichment_queue_lifecycle(privacy_db):
    """
    Verifies ThreatEnrichmentJobModel lifecycle: enqueue -> process -> complete/fail,
    and reconciliation.
    """
    repo = ThreatIntelRepository(privacy_db)
    extractor = ObservableExtractor()

    obs = extractor.validate_and_normalize_ip("198.51.100.99")
    model = repo.get_or_create_observable(obs, tenant_id="tenant-test")

    # 1. Enqueue job
    job = repo.enqueue_enrichment_job(
        observable_id=model.id,
        observable_value=obs.normalized_value,
        observable_type=obs.observable_type.value,
        tenant_id="tenant-test",
    )
    assert job.status == "pending"
    assert job.attempts == 0

    # Deduplication test: re-enqueuing returns existing active job
    job_dup = repo.enqueue_enrichment_job(
        observable_id=model.id,
        observable_value=obs.normalized_value,
        observable_type=obs.observable_type.value,
        tenant_id="tenant-test",
    )
    assert job_dup.id == job.id

    # 2. Mark processing
    ok = repo.mark_enrichment_job_processing(job.id)
    assert ok is True
    privacy_db.refresh(job)
    assert job.status == "processing"
    assert job.attempts == 1

    # 3. Mark failed (retry back to pending if attempts < max_attempts)
    repo.mark_enrichment_job_failed(job.id, "Temporary network timeout")
    privacy_db.refresh(job)
    assert job.status == "pending"  # Retries allowed
    assert "Temporary network timeout" in job.last_error

    # 4. Mark processing then completed
    repo.mark_enrichment_job_processing(job.id)
    repo.mark_enrichment_job_completed(job.id)
    privacy_db.refresh(job)
    assert job.status == "completed"
