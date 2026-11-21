"""Unit tests for Threat Hunting Copilot, DuckDB forensics, and Server Integrations."""

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app.database.session import SessionLocal
from app.main import app
from app.models.log_event import LogEventModel
from app.services.duckdb_forensics import DuckDBForensicsEngine
from app.services.hunting_copilot import HuntingCopilot

client = TestClient(app)


def test_copilot_parser_offline():
    lucene, reasoning, mitre = HuntingCopilot.translate_to_lucene(
        "Show me failed SSH logins with more than 5 attempts"
    )
    assert lucene != ""
    assert mitre == "T1110 (Brute Force)"
    assert reasoning != ""


def test_copilot_sql_injection():
    lucene, reasoning, mitre = HuntingCopilot.translate_to_lucene(
        "Find SQL injection attempts in apache access logs"
    )
    assert "UNION" in lucene or "SELECT" in lucene or "endpoint" in lucene
    assert mitre == "T1190 (Exploit Public-Facing Application)"


def test_copilot_fallback():
    lucene, reasoning, mitre = HuntingCopilot.translate_to_lucene(
        "random unknown search string 12345"
    )
    assert "endpoint" in lucene or "status_code" in lucene


def test_duckdb_execution():
    db = SessionLocal()
    try:
        sample_log = LogEventModel(
            timestamp=datetime.now(UTC),
            raw_log="Sample attack log",
            source_ip="198.51.100.77",
            destination_ip="10.0.0.1",
            source_type="syslog",
            source="firewall",
            status_code="403",
            path="/login",
            http_method="POST",
        )
        db.add(sample_log)
        db.commit()

        # Execute query via duckdb
        res = DuckDBForensicsEngine.execute_query(
            db, "SELECT source_ip, count(*) as cnt FROM logs GROUP BY source_ip"
        )
        assert res.total_rows >= 1
        assert res.execution_time_ms >= 0
        assert any(r[0] == "198.51.100.77" for r in res.rows)
    finally:
        db.close()


def test_api_hunting_copilot_endpoint():
    response = client.post(
        "/api/v1/hunting/copilot",
        json={"natural_query": "Detect brute force attacks on admin port"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "translated_lucene" in data
    assert "search_result" in data
    assert "ai_tactical_summary" in data


def test_api_hunting_analytics_endpoint():
    response = client.post(
        "/api/v1/hunting/analytics",
        json={"sql_query": "SELECT count(*) as total_events FROM logs"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "columns" in data
    assert "rows" in data
    assert "execution_time_ms" in data


def test_api_hunting_analytics_invalid_sql():
    response = client.post(
        "/api/v1/hunting/analytics",
        json={"sql_query": "DELETE FROM logs"},
    )
    assert response.status_code == 400


def test_api_integrations_endpoints():
    # Test GET /servers
    resp = client.get("/api/v1/integrations/servers")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

    # Test POST /test-ping
    ping_resp = client.post(
        "/api/v1/integrations/test-ping",
        json={
            "server_name": "srv-prod-linux-01",
            "server_ip": "10.0.1.50",
            "platform": "linux",
            "parser": "nginx",
        },
    )
    assert ping_resp.status_code == 200
    assert ping_resp.json()["status"] == "connected"

    # Test GET /ingestion-info
    info_resp = client.get("/api/v1/integrations/ingestion-info")
    assert info_resp.status_code == 200
    data = info_resp.json()
    assert "syslog_udp" in data
    assert "api_endpoint" in data
