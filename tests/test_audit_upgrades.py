"""Comprehensive Unit Tests for LogSentry Enterprise Security & Architecture Upgrades.

Covers:
  1. Cryptographic JWT token generation, expiration, signature verification & forged header rejection.
  2. Multi-tenant isolation & RBAC permission checks.
  3. DuckDB SQL parser security boundary (blocking multi-statement, DDL, file I/O).
  4. Batch ingestion, idempotent event deduplication & multi-stage attack correlation.
  5. Persistent SOAR response, internal IP protection & containment rollback.
  6. Incident attack graph & evidence chain generation.
"""

import time

import pytest
from fastapi.testclient import TestClient

from app.core.jwt import create_access_token, decode_access_token
from app.core.rbac import UserRole, get_current_user
from app.database.session import SessionLocal
from app.detection.correlation import CorrelationEngine
from app.main import app
from app.models.incident import IncidentModel
from app.models.soar_action import SOARActionModel
from app.schemas.detection_alert import DetectionAlert
from app.schemas.severity import Severity
from app.services.dedup_service import EventDeduplicator
from app.services.duckdb_forensics import DuckDBForensicsEngine
from app.services.soar_service import SOARService

client = TestClient(app)


# ── 1. Cryptographic JWT & Identity Security Tests ─────────────────────────────
def test_jwt_token_creation_and_decoding():
    token = create_access_token(
        user_id="sec-analyst",
        role=UserRole.THREAT_HUNTER.value,
        tenant_id="corp-finance",
        expires_delta_minutes=60,
    )
    assert isinstance(token, str)
    assert token.count(".") == 2

    payload = decode_access_token(token)
    assert payload["sub"] == "sec-analyst"
    assert payload["role"] == UserRole.THREAT_HUNTER.value
    assert payload["tenant_id"] == "corp-finance"
    assert "exp" in payload


def test_jwt_token_tampering_rejected():
    token = create_access_token(
        user_id="analyst",
        role=UserRole.TIER_1_ANALYST.value,
        tenant_id="default",
    )
    # Tamper with the token string
    tampered = token[:-4] + "ABCD"
    with pytest.raises(ValueError, match="signature verification failed"):
        decode_access_token(tampered)


def test_jwt_token_expiration():
    # Create token expired 1 second ago
    token = create_access_token(
        user_id="analyst",
        role=UserRole.TIER_1_ANALYST.value,
        expires_delta_minutes=-1,
    )
    with pytest.raises(ValueError, match="expired"):
        decode_access_token(token)


def test_api_auth_login_endpoint():
    # Successful login
    resp = client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "admin"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["user"]["role"] == "Admin"

    # Authenticated call with Bearer token
    admin_token = data["access_token"]
    admin_resp = client.get(
        "/api/v1/auth/admin-only", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert admin_resp.status_code == 200
    assert "Privileged access granted" in admin_resp.json()["message"]


def test_api_forged_header_elevation_rejected():
    # Attacker tries to send X-User-Role: Admin without a signed JWT
    resp = client.get(
        "/api/v1/auth/admin-only",
        headers={"X-User-Role": "Admin", "X-User-ID": "attacker"},
    )
    # System downgrades unverified privileged headers and forbids access
    assert resp.status_code == 403


# ── 2. DuckDB SQL Parser Security Boundary Tests ─────────────────────────────
def test_duckdb_sql_security_valid_select():
    valid = "SELECT source_ip, count(*) FROM logs GROUP BY source_ip"
    clean = DuckDBForensicsEngine.validate_sql_security(valid)
    assert clean == valid


def test_duckdb_sql_security_multi_statement_blocked():
    with pytest.raises(ValueError, match="Multiple SQL statements"):
        DuckDBForensicsEngine.validate_sql_security(
            "SELECT * FROM logs; DROP TABLE logs;"
        )


def test_duckdb_sql_security_ddl_dml_blocked():
    dangerous_queries = [
        "DELETE FROM logs",
        "INSERT INTO logs VALUES ('1', '2')",
        "DROP TABLE logs",
        "ALTER TABLE logs ADD COLUMN x INT",
        "TRUNCATE logs",
    ]
    for q in dangerous_queries:
        with pytest.raises(ValueError):
            DuckDBForensicsEngine.validate_sql_security(q)


def test_duckdb_sql_security_file_io_blocked():
    file_queries = [
        "SELECT * FROM read_csv('secret.csv')",
        "SELECT * FROM read_parquet('data.parquet')",
        "COPY logs TO 'dump.csv'",
        "PRAGMA version",
    ]
    for q in file_queries:
        with pytest.raises(ValueError):
            DuckDBForensicsEngine.validate_sql_security(q)


# ── 3. Batch Ingestion, Deduplication & Attack Correlation Tests ───────────────
def test_event_deduplication():
    dedup = EventDeduplicator(ttl_seconds=60)
    event = {
        "timestamp": "2026-11-21T10:00:00Z",
        "source_ip": "198.51.100.99",
        "raw_log": "POST /login 401 Unauthorized",
    }
    fp = dedup.compute_event_fingerprint(event)
    assert not dedup.is_duplicate(fp)
    # Second submission is flagged as duplicate
    assert dedup.is_duplicate(fp)


def test_api_batch_ingestion_and_correlation():
    batch_payload = {
        "tenant_id": "corp-dev",
        "events": [
            {
                "event_id": "evt-001",
                "timestamp": "2026-11-21T10:00:00Z",
                "source_ip": "203.0.113.88",
                "raw_log": "GET /wp-admin/setup-config.php 404",
                "endpoint": "/wp-admin/setup-config.php",
                "status_code": 404,
                "source_type": "apache",
            },
            {
                "event_id": "evt-002",
                "timestamp": "2026-11-21T10:00:02Z",
                "source_ip": "203.0.113.88",
                "raw_log": "GET /api/v1/users?id=1 UNION SELECT username,password FROM users-- 200",
                "endpoint": "/api/v1/users?id=1 UNION SELECT username,password FROM users--",
                "status_code": 200,
                "source_type": "nginx",
            },
            {
                "event_id": "evt-003",
                "timestamp": "2026-11-21T10:00:05Z",
                "source_ip": "203.0.113.88",
                "raw_log": "POST /diagnostic?cmd=cat+/etc/passwd 200",
                "endpoint": "/diagnostic?cmd=cat+/etc/passwd",
                "status_code": 200,
                "source_type": "apache",
            },
        ],
    }

    resp = client.post("/api/v1/detection/batch", json=batch_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "acknowledged"
    assert data["received_count"] == 3
    assert data["processed_count"] == 3
    assert len(data["ack_ids"]) == 3
    # Verify multi-stage attack correlation
    assert "correlated_campaigns" in data
    assert len(data["correlated_campaigns"]) >= 1
    campaign = data["correlated_campaigns"][0]
    assert "Multi-Stage" in campaign["title"] or "Attack" in campaign["title"]


def test_correlation_engine_killchain():
    corr = CorrelationEngine(window_seconds=300)
    alert1 = DetectionAlert(
        alert_id="a1",
        title="Admin Probe",
        attack_type="Admin Probe",
        severity=Severity.MEDIUM,
        confidence=0.8,
        risk_score=5.0,
        rule_name="probe",
        rule_version="1.0",
        description="Admin panel probe",
        raw_log_reference="GET /wp-admin 404",
        source_ip="198.51.100.77",
    )
    alert2 = DetectionAlert(
        alert_id="a2",
        title="SQL Injection",
        attack_type="SQL Injection",
        severity=Severity.HIGH,
        confidence=0.9,
        risk_score=8.0,
        rule_name="sqli",
        rule_version="1.0",
        description="SQL injection in id param",
        raw_log_reference="GET /users?id=1 UNION SELECT 200",
        source_ip="198.51.100.77",
    )

    res1 = corr.correlate_alert(alert1)
    assert res1 is None  # Single alert not yet a campaign

    res2 = corr.correlate_alert(alert2)
    assert res2 is not None  # Probe + SQLi triggers Multi-Stage Intrusion Campaign
    assert res2.source_ip == "198.51.100.77"
    assert "Multi-Stage" in res2.title


# ── 4. Persistent SOAR & Safe Response Tests ─────────────────────────────────
def test_soar_private_ip_protection():
    with pytest.raises(ValueError, match="Protected private/internal IP"):
        SOARService.quarantine_ip("127.0.0.1", "Accidental local block", force=False)

    with pytest.raises(ValueError, match="Protected private/internal IP"):
        SOARService.quarantine_ip("192.168.1.1", "Accidental LAN block", force=False)


def test_soar_persistence_and_rollback():
    db = SessionLocal()
    target_ip = "198.51.100.188"
    try:
        # Quarantine external attacker IP
        res = SOARService.quarantine_ip(
            ip=target_ip,
            reason="Confirmed Log4Shell exploit",
            duration_seconds=1800,
            containment_type="IPTABLES",
            db=db,
        )
        assert res["ip"] == target_ip
        assert res["status"] == "ACTIVE"

        # Verify record exists in DB
        action_in_db = (
            db.query(SOARActionModel)
            .filter(
                SOARActionModel.target == target_ip, SOARActionModel.status == "ACTIVE"
            )
            .first()
        )
        assert action_in_db is not None
        assert action_in_db.action_type == "QUARANTINE_IP"

        # Perform Rollback
        rolled_back = SOARService.rollback_action(target_ip, db=db)
        assert rolled_back is True

        # Check DB status is updated to RELEASED
        db.refresh(action_in_db)
        assert action_in_db.status == "RELEASED"
    finally:
        db.close()


# ── 5. Incident Attack Graph Tests ───────────────────────────────────────────
def test_incident_attack_graph_endpoint():
    # Create incident via API in test session
    create_resp = client.post(
        "/api/v1/incidents",
        json={
            "title": "Coordinated RCE Incident",
            "description": "Multi-alert investigation",
            "severity": "CRITICAL",
            "priority": "P1",
            "category": "Intrusion",
        },
    )
    assert create_resp.status_code == 201
    inc_id = create_resp.json()["id"]

    resp = client.get(f"/api/v1/incidents/{inc_id}/graph")
    assert resp.status_code == 200
    graph = resp.json()
    assert graph["incident_id"] == inc_id
    assert "nodes" in graph
    assert "edges" in graph
    assert graph["node_count"] >= 1
