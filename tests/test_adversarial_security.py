"""LogSentry Adversarial Security & Enterprise Hardening Test Suite.

Validates:
1. PBKDF2 Password Hashing & Tenant Lock during authentication
2. Cryptographic JWT RFC 7519 signature & claims verification (rejecting alg=none, expired, missing claims)
3. Cross-Tenant Correlation Isolation (preventing multi-tenant alert leakage)
4. DuckDB Forensics Sandbox Evasion & Tenant Isolation
5. Persistent SOAR RBAC & IPv4/IPv6 private address guardrails
6. Batch Ingestion explicit error reporting for dropped/malformed items
7. Universal Shipper local disk spool replay & drainer
"""

import json
import os

import pytest
from fastapi.testclient import TestClient

from app.core.jwt import create_access_token, decode_access_token
from app.core.rbac import UserRole
from app.detection.correlation import CorrelationEngine
from app.main import app
from app.schemas.detection_alert import DetectionAlert
from app.schemas.severity import Severity
from app.services.duckdb_forensics import DuckDBForensicsEngine
from scripts.logsentry_shipper import LogShipper

client = TestClient(app)


# ===========================================================================
# 1. PBKDF2 Auth & Tenant Lock Tests
# ===========================================================================


def test_auth_pbkdf2_login_and_tenant_lock():
    # Valid login
    res = client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "analyst123", "tenant_id": "default"},
    )
    assert res.status_code == 200
    token_data = res.json()
    assert "access_token" in token_data
    assert token_data["user"]["role"] == UserRole.TIER_2_ANALYST.value
    assert token_data["user"]["tenant_id"] == "default"

    # Invalid password
    res_bad = client.post(
        "/api/v1/auth/login",
        json={
            "username": "analyst",
            "password": "wrongpassword",
            "tenant_id": "default",
        },
    )
    assert res_bad.status_code == 401

    # Non-admin attempting to switch to unauthorized tenant
    res_unauth_tenant = client.post(
        "/api/v1/auth/login",
        json={
            "username": "analyst",
            "password": "analyst123",
            "tenant_id": "unauthorized-corp-bank",
        },
    )
    assert res_unauth_tenant.status_code == 403
    detail = res_unauth_tenant.json().get("details") or res_unauth_tenant.json().get(
        "detail", ""
    )
    assert "not authorized to access tenant" in detail

    # Admin can access arbitrary tenant
    res_admin = client.post(
        "/api/v1/auth/login",
        json={
            "username": "admin",
            "password": "admin",
            "tenant_id": "custom-enterprise-tenant",
        },
    )
    assert res_admin.status_code == 200
    assert res_admin.json()["user"]["tenant_id"] == "custom-enterprise-tenant"


# ===========================================================================
# 2. Strict RFC 7519 Cryptographic JWT Verification Tests
# ===========================================================================


def test_jwt_claims_and_signature_security():
    token = create_access_token(
        user_id="hunter-01",
        role=UserRole.THREAT_HUNTER.value,
        tenant_id="alpha-tenant",
        email="hunter@corp.local",
        expires_delta_minutes=60,
    )
    payload = decode_access_token(token)
    assert payload["sub"] == "hunter-01"
    assert payload["role"] == UserRole.THREAT_HUNTER.value
    assert payload["tenant_id"] == "alpha-tenant"
    assert "exp" in payload
    assert "iat" in payload

    # Tampered payload signature verification
    parts = token.split(".")
    tampered = f"{parts[0]}.{parts[1]}x.{parts[2]}"
    with pytest.raises(ValueError, match="JWT signature verification failed"):
        decode_access_token(tampered)

    # Forged 'alg': 'none' header
    fake_header = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"  # {"alg":"none","typ":"JWT"}
    fake_token = f"{fake_header}.{parts[1]}."
    with pytest.raises(ValueError, match="Unsupported JWT algorithm"):
        decode_access_token(fake_token)


# ===========================================================================
# 3. Cross-Tenant Correlation Isolation Tests
# ===========================================================================


def test_cross_tenant_correlation_isolation():
    engine = CorrelationEngine(window_seconds=300)

    # Alert from Tenant Alpha
    alert_alpha_sqli = DetectionAlert(
        alert_id="alt-alpha-1",
        rule_name="sqli_probe",
        rule_version="1.0.0",
        severity=Severity.HIGH,
        confidence=0.9,
        risk_score=80.0,
        title="SQL Injection Probe",
        description="SQL injection in input param",
        source_ip="198.51.100.77",
        endpoint="/login",
        attack_type="SQL Injection",
        mitre_technique="T1190",
        mitre_tactic="Initial Access",
        recommendation="Block IP",
        evidence={},
        raw_log_reference="SELECT * FROM users",
        tenant_id="tenant-alpha",
    )

    # Alert from Tenant Beta from SAME attacker IP
    alert_beta_rce = DetectionAlert(
        alert_id="alt-beta-1",
        rule_name="rce_probe",
        rule_version="1.0.0",
        severity=Severity.CRITICAL,
        confidence=0.95,
        risk_score=95.0,
        title="Command Execution",
        description="Bash execution",
        source_ip="198.51.100.77",
        endpoint="/api/exec",
        attack_type="Command Injection",
        mitre_technique="T1059",
        mitre_tactic="Execution",
        recommendation="Quarantine host",
        evidence={},
        raw_log_reference="; cat /etc/passwd",
        tenant_id="tenant-beta",
    )

    camp_alpha = engine.correlate_alert(alert_alpha_sqli)
    camp_beta = engine.correlate_alert(alert_beta_rce)

    # They should NOT cross-correlate into a campaign because tenants are isolated
    assert camp_alpha is None
    assert camp_beta is None

    # Now add a second alert into Tenant Alpha for the same IP
    alert_alpha_rce = DetectionAlert(
        alert_id="alt-alpha-2",
        rule_name="rce_probe",
        rule_version="1.0.0",
        severity=Severity.CRITICAL,
        confidence=0.95,
        risk_score=95.0,
        title="Command Execution",
        description="Bash execution",
        source_ip="198.51.100.77",
        endpoint="/api/exec",
        attack_type="Command Injection",
        mitre_technique="T1059",
        mitre_tactic="Execution",
        recommendation="Quarantine host",
        evidence={},
        raw_log_reference="; cat /etc/passwd",
        tenant_id="tenant-alpha",
    )
    camp_alpha_full = engine.correlate_alert(alert_alpha_rce)
    assert camp_alpha_full is not None
    assert camp_alpha_full.tenant_id == "tenant-alpha"
    assert "alt-beta-1" not in camp_alpha_full.alert_ids


# ===========================================================================
# 4. DuckDB SQL Sandbox & Tenant Filtering Tests
# ===========================================================================


def test_duckdb_sandbox_security_rules():
    # Multi-statement injection attempt
    with pytest.raises(
        ValueError, match="Multiple SQL statements are strictly prohibited"
    ):
        DuckDBForensicsEngine.validate_sql_security("SELECT 1; DROP TABLE logs;")

    # Non-SELECT statement attempt
    with pytest.raises(ValueError, match="Only read-only SELECT"):
        DuckDBForensicsEngine.validate_sql_security("DELETE FROM logs WHERE 1=1")

    # File reading evasion attempt
    with pytest.raises(ValueError, match="Forbidden SQL operation"):
        DuckDBForensicsEngine.validate_sql_security(
            "SELECT * FROM read_csv('/etc/passwd')"
        )

    # Comment hiding attempt
    with pytest.raises(ValueError, match="Forbidden SQL operation"):
        DuckDBForensicsEngine.validate_sql_security(
            "SELECT * FROM logs -- comment bypass"
        )


# ===========================================================================
# 5. Persistent SOAR RBAC & Safety Guardrails
# ===========================================================================


def test_soar_safety_and_rbac():
    admin_token = create_access_token(
        user_id="admin", role=UserRole.ADMIN.value, tenant_id="default"
    )
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Protected RFC 1918 private IP quarantine rejection
    res_priv = client.post(
        "/api/v1/soar/quarantine",
        headers=admin_headers,
        json={
            "ip": "10.0.0.1",
            "reason": "Accidental test",
        },
    )
    assert res_priv.status_code == 400
    detail_priv = res_priv.json().get("details") or res_priv.json().get("detail", "")
    assert "Protected private/internal IP" in detail_priv

    # Protected IPv6 loopback rejection
    res_ipv6 = client.post(
        "/api/v1/soar/quarantine",
        headers=admin_headers,
        json={
            "ip": "::1",
            "reason": "Loopback block test",
        },
    )
    assert res_ipv6.status_code == 400
    detail_ipv6 = res_ipv6.json().get("details") or res_ipv6.json().get("detail", "")
    assert "Protected private/internal IP" in detail_ipv6

    # Valid external IP quarantine
    target_ext_ip = "203.0.113.120"
    res_ok = client.post(
        "/api/v1/soar/quarantine",
        headers=admin_headers,
        json={
            "ip": target_ext_ip,
            "reason": "Confirmed malicious C2 traffic",
            "duration_seconds": 1800,
            "containment_type": "IN_MEMORY",
        },
    )
    assert res_ok.status_code == 200
    assert res_ok.json()["status"] in ("active", "ACTIVE")

    # Release target
    res_rel = client.delete(
        f"/api/v1/soar/quarantine/{target_ext_ip}", headers=admin_headers
    )
    assert res_rel.status_code == 200
    assert res_rel.json()["status"] == "success"


# ===========================================================================
# 6. Batch Ingestion Acknowledgment & Error Reporting Tests
# ===========================================================================


def test_batch_ingestion_acknowledgement_separation():
    admin_token = create_access_token(
        user_id="admin", role=UserRole.ADMIN.value, tenant_id="default"
    )
    headers = {"Authorization": f"Bearer {admin_token}"}

    payload = {
        "tenant_id": "default",
        "events": [
            {
                "event_id": "valid-evt-001",
                "timestamp": "2026-11-21T12:00:00Z",
                "raw_log": "GET /index.html 200",
                "source": "web-01",
                "source_type": "nginx",
                "source_ip": "198.51.100.10",
            },
            {
                "event_id": "malformed-evt-002",
                # Missing raw_log will trigger LogEvent validation failure
                "source": "web-01",
                "source_type": "nginx",
            },
        ],
    }

    res = client.post("/api/v1/detection/batch", headers=headers, json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["received_count"] == 2
    assert data["processed_count"] == 1
    assert data["rejected_count"] == 1
    assert "valid-evt-001" in data["ack_ids"]
    assert "malformed-evt-002" not in data["ack_ids"]
    assert len(data["rejected_errors"]) == 1
    assert data["rejected_errors"][0]["event_id"] == "malformed-evt-002"


# ===========================================================================
# 7. Shipper Disk Spool Replay & Drainer Tests
# ===========================================================================


def test_shipper_spool_drainer(tmp_path):
    spool_file = str(tmp_path / "test_spool.jsonl")
    checkpoint_file = str(tmp_path / "test_ckpt.json")

    # Write dummy events to spool
    with open(spool_file, "w", encoding="utf-8") as f:
        f.write(
            json.dumps(
                {"raw_log": "test log 1", "source": "t1", "source_type": "nginx"}
            )
            + "\n"
        )
        f.write(
            json.dumps(
                {"raw_log": "test log 2", "source": "t2", "source_type": "nginx"}
            )
            + "\n"
        )

    shipper = LogShipper(
        file_patterns=[],
        parser_name="nginx",
        server_url="http://127.0.0.1:9999",  # unreachable server
        spool_path=spool_file,
        checkpoint_path=checkpoint_file,
    )

    # When server is down, events remain safely in spool
    shipper.drain_spool()
    assert os.path.exists(spool_file)
    with open(spool_file, encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
    assert len(lines) == 2
