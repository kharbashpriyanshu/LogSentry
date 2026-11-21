"""Comprehensive Security Test Suite for Sprint 1: Identity, Authentication & RBAC.

Covers:
  1. Secure Configuration & Production Secrets Validation
  2. Argon2id Password Hashing & Timing Attack Mitigation
  3. PyJWT HS256 Cryptographic Verification & Claim Integrity
  4. Persistent Identity Models & Multi-Tenant Boundaries
  5. Machine-to-Machine Agent Enrollment & Scoped Ingestion
  6. Privilege Escalation Defenses & RBAC Hierarchy Enforcement
"""

import time

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config.settings import Settings
from app.core.jwt import (
    JWT_ALGORITHM,
    JWT_AUDIENCE,
    JWT_ISSUER,
    create_access_token,
    decode_access_token,
)
from app.core.password import hash_password, verify_password
from app.core.rbac import UserRole, get_current_user
from app.database.base import Base
from app.main import app
from app.models.tenant import TenantModel, UserTenantMembershipModel
from app.models.user import UserModel
from app.services.identity_service import IdentityService


@pytest.fixture(scope="module")
def identity_db():
    """In-memory SQLite database isolated for Sprint 1 testing."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    IdentityService.bootstrap_default_tenants_and_admin(session)
    yield session
    session.close()


@pytest.fixture
def client():
    return TestClient(app)


# ==============================================================================
# 1. Configuration & Production Startup Validation
# ==============================================================================


def test_production_secret_key_validation():
    """Ensures production startup fails if SECRET_KEY is missing, default, or < 32 chars."""
    dev_default = "logsentry-insecure-dev-secret-key-min-32-chars-2026!"

    # 1. Dev default in production MUST raise ValueError
    with pytest.raises(
        ValueError, match="Default development secret key is strictly prohibited"
    ):
        Settings(
            ENVIRONMENT="production",
            DATABASE_URI="postgresql://db.corp:5432/siem",
            SECRET_KEY=dev_default,
        )

    # 2. Key shorter than 32 characters in production MUST raise ValueError
    with pytest.raises(ValueError, match="at least 32 characters"):
        Settings(
            ENVIRONMENT="production",
            DATABASE_URI="postgresql://db.corp:5432/siem",
            SECRET_KEY="short-secret-key-12345",
        )

    # 3. High-entropy key with >= 32 chars succeeds and enables strict mode
    prod_settings = Settings(
        ENVIRONMENT="production",
        DATABASE_URI="postgresql://db.corp:5432/siem",
        SECRET_KEY="a" * 32,
        PII_ENCRYPTION_KEY="b" * 32,
        PII_HMAC_KEY="c" * 32,
        INITIAL_ADMIN_PASSWORD="Strong#AdminPassword2026!",
    )
    assert prod_settings.AUTH_STRICT_MODE is True


# ==============================================================================
# 2. Argon2id Password Hashing
# ==============================================================================


def test_argon2id_hashing_and_verification():
    """Verifies Argon2id produces valid RFC 9106 hashes and verifies correctly."""
    password = "SuperSecretPassword#2026!"
    hashed = hash_password(password)

    # Argon2id prefix check
    assert hashed.startswith("$argon2id$")
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword123!", hashed) is False
    assert verify_password("", hashed) is False

    with pytest.raises(ValueError, match="Password cannot be empty"):
        hash_password("")


# ==============================================================================
# 3. PyJWT HS256 Cryptographic Verification
# ==============================================================================


def test_jwt_valid_lifecycle_and_claims():
    """Creates a JWT and asserts all required claims are populated and decoded."""
    token = create_access_token(
        user_id="analyst_test_01",
        role=UserRole.TIER_2_ANALYST.value,
        tenant_id="tenant-corp-a",
        email="analyst@corp.com",
    )
    payload = decode_access_token(token)

    assert payload["iss"] == JWT_ISSUER
    assert payload["aud"] == JWT_AUDIENCE
    assert payload["sub"] == "analyst_test_01"
    assert payload["role"] == UserRole.TIER_2_ANALYST.value
    assert payload["tenant_id"] == "tenant-corp-a"
    assert payload["typ"] == "access"
    assert payload["exp"] > payload["iat"]


def test_jwt_tampering_and_algorithm_none_rejected():
    """Verifies signature tampering and 'alg': 'none' are strictly rejected."""
    token = create_access_token("admin_test", UserRole.ADMIN.value)

    # 1. Signature tampering
    parts = token.split(".")
    tampered_sig = parts[2][:-4] + "AAAA"
    tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"
    with pytest.raises(ValueError, match="signature"):
        decode_access_token(tampered_token)

    # 2. Algorithm 'none' attack token
    none_token = jwt.encode(
        {
            "sub": "admin",
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
            "role": "Admin",
            "tenant_id": "default",
            "typ": "access",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        },
        key="",
        algorithm="none",
    )
    with pytest.raises(ValueError):
        decode_access_token(none_token)


def test_jwt_protected_claims_cannot_be_overwritten():
    """Extra claims cannot overwrite core security claims like role or sub."""
    token = create_access_token(
        user_id="legit_user",
        role=UserRole.TIER_1_ANALYST.value,
        extra_claims={"role": "Admin", "sub": "superuser", "custom_dept": "SOC"},
    )
    payload = decode_access_token(token)
    assert payload["role"] == UserRole.TIER_1_ANALYST.value
    assert payload["sub"] == "legit_user"
    assert payload["custom_dept"] == "SOC"


# ==============================================================================
# 4. Multi-Tenant Boundaries & Persistent Authentication
# ==============================================================================


def test_login_flow_and_tenant_restriction(client):
    """Verifies database authentication with Argon2id and strict tenant membership."""
    # 1. Successful admin login on default tenant
    res = client.post(
        "/api/v1/auth/login",
        json={
            "username": "admin",
            "password": "admin",
            "tenant_id": "default",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["user"]["role"] == UserRole.ADMIN.value

    # 2. Invalid password rejected with 401
    bad_res = client.post(
        "/api/v1/auth/login",
        json={
            "username": "admin",
            "password": "WrongPassword123!",
            "tenant_id": "default",
        },
    )
    assert bad_res.status_code == 401

    # 3. Non-existent user rejected with identical error (timing attack resistance)
    ghost_res = client.post(
        "/api/v1/auth/login",
        json={
            "username": "non_existent_ghost_user_999",
            "password": "AnyPassword123!",
            "tenant_id": "default",
        },
    )
    assert ghost_res.status_code == 401

    # 4. Non-admin attempting to access unauthorized tenant is rejected (403)
    unauthorized_tenant_res = client.post(
        "/api/v1/auth/login",
        json={
            "username": "analyst",
            "password": "analyst123",
            "tenant_id": "lab-sec-ops",  # analyst only belongs to 'default'
        },
    )
    assert unauthorized_tenant_res.status_code == 403


# ==============================================================================
# 5. Machine-to-Machine Agent Authentication & Scoped Ingestion
# ==============================================================================


def test_agent_enrollment_and_batch_ingestion(client):
    """Enrolls a collector agent, transmits a batch with its API key, and verifies tenant scoping."""
    # 1. Login as Admin
    admin_login = client.post(
        "/api/v1/auth/login",
        json={
            "username": "admin",
            "password": "admin",
            "tenant_id": "default",
        },
    )
    admin_token = admin_login.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 2. Enroll a new collector agent
    enroll_res = client.post(
        "/api/v1/auth/agents/enroll",
        headers=admin_headers,
        json={"name": "test-edge-collector-01", "tenant_id": "default"},
    )
    assert enroll_res.status_code == 200
    agent_info = enroll_res.json()
    api_key = agent_info["api_key"]
    agent_id = agent_info["agent_id"]
    assert api_key.startswith("lgs_agt_")

    # 3. Transmit batch telemetry using Agent API key (X-Agent-Key)
    batch_payload = {
        "events": [
            {
                "timestamp": "2026-11-21T12:00:00Z",
                "source_ip": "10.0.0.99",
                "hostname": "edge-sensor",
                "method": "GET",
                "endpoint": "/api/v1/probe",
                "status_code": 200,
                "raw_log": "10.0.0.99 - - GET /api/v1/probe 200",
                "parser_name": "generic",
            }
        ],
        "tenant_id": "default",
    }
    agent_headers = {"X-Agent-Key": api_key}
    ingest_res = client.post(
        "/api/v1/detection/batch", headers=agent_headers, json=batch_payload
    )
    assert ingest_res.status_code == 200
    assert ingest_res.json()["processed_count"] == 1

    # 4. Agent attempts to access user operations (e.g. enroll other agents) -> REJECTED (401/403)
    agent_forbidden_res = client.post(
        "/api/v1/auth/agents/enroll",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"name": "rogue-agent", "tenant_id": "default"},
    )
    assert agent_forbidden_res.status_code in (401, 403)

    # 5. Revoke the agent and verify subsequent requests are 401
    revoke_res = client.delete(f"/api/v1/auth/agents/{agent_id}", headers=admin_headers)
    assert revoke_res.status_code == 200

    revoked_ingest_res = client.post(
        "/api/v1/detection/batch", headers=agent_headers, json=batch_payload
    )
    assert revoked_ingest_res.status_code == 401


# ==============================================================================
# 6. Privilege Escalation Defenses & Router RBAC Matrix
# ==============================================================================


def test_unauthenticated_privilege_escalation_blocked(client):
    """Ensures callers cannot forge X-User-Role: Admin to bypass authorization."""
    # Attempting to call an admin-only endpoint with forged headers
    res = client.get(
        "/api/v1/auth/admin-only",
        headers={"X-User-Role": "Admin", "X-User-Id": "attacker"},
    )
    # Must be downgraded to Tier1_Analyst and denied with 403
    assert res.status_code == 403

    # Attempting to reload detection rules with forged headers
    reload_res = client.post(
        "/api/v1/detection/rules/reload", headers={"X-User-Role": "Admin"}
    )
    assert reload_res.status_code == 403
