import pytest
from unittest.mock import Mock, patch
from fastapi.testclient import TestClient
from datetime import datetime
from app.main import app
from app.api.dependencies import get_enrichment_service
from app.enrichment.models import ThreatEnrichment
from app.enrichment.cache import InMemoryCache
from app.services.enrichment_service import EnrichmentService
from app.enrichment.providers.base_provider import BaseThreatProvider
from app.enrichment.exceptions import ProviderTimeoutError, ProviderUnavailableError

class MockHealthyProvider(BaseThreatProvider):
    @property
    def provider_name(self) -> str:
        return "mock_healthy"
        
    def health(self) -> bool:
        return True
        
    def enrich(self, alert) -> ThreatEnrichment:
        return ThreatEnrichment(
            provider="mock_healthy",
            reputation="suspicious",
            confidence=0.8,
            ioc_tags=["mock_tag"]
        )

class MockFailingProvider(BaseThreatProvider):
    @property
    def provider_name(self) -> str:
        return "mock_failing"
        
    def health(self) -> bool:
        return True
        
    def enrich(self, alert) -> ThreatEnrichment:
        raise ProviderTimeoutError("Mock timeout")

def get_mock_enrichment_service():
    cache = InMemoryCache(ttl_seconds=60)
    return EnrichmentService([MockHealthyProvider(), MockFailingProvider()], cache)

app.dependency_overrides[get_enrichment_service] = get_mock_enrichment_service

client = TestClient(app)

def create_mock_alert():
    return {
        "alert_id": "12345678-1234-5678-1234-567812345678",
        "timestamp": datetime.now().isoformat(),
        "rule_name": "sqli",
        "rule_version": "1.0",
        "severity": "HIGH",
        "confidence": 0.9,
        "risk_score": 85.0,
        "title": "SQL Injection",
        "description": "Test alert",
        "source_ip": "1.1.1.1",
        "endpoint": "/login",
        "attack_type": "SQL Injection",
        "mitre_technique": "T1190",
        "mitre_tactic": "Initial Access",
        "recommendation": "Block",
        "evidence": {},
        "raw_log_reference": "raw"
    }

def test_health():
    res = client.get("/api/v1/enrichment/health")
    assert res.status_code == 200
    assert res.json()["healthy"] is True
    assert "mock_healthy" in res.json()["details"]

def test_providers():
    res = client.get("/api/v1/enrichment/providers")
    assert res.status_code == 200
    assert res.json()["providers"]["mock_healthy"] is True

def test_analyze():
    res = client.post("/api/v1/enrichment/analyze", json=create_mock_alert())
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 1  # Only the healthy provider should return data
    assert data[0]["provider"] == "mock_healthy"
    assert data[0]["reputation"] == "suspicious"

def test_cache_logic():
    cache = InMemoryCache(ttl_seconds=1)
    cache.set("test_key", {"val": 123})
    assert cache.get("test_key") == {"val": 123}
    import time
    time.sleep(1.1)
    assert cache.get("test_key") is None
