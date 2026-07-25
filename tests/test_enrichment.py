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
        return self.enrich_ioc("1.1.1.1")

    def enrich_ioc(self, observable: str):
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
        return self.enrich_ioc("1.1.1.1")

    def enrich_ioc(self, observable: str):
        raise ProviderTimeoutError("Mock timeout")

def get_mock_enrichment_service():
    cache = InMemoryCache(ttl_seconds=60)
    return EnrichmentService([MockHealthyProvider(), MockFailingProvider()], cache)

def get_mock_enrichment_repo():
    from unittest.mock import MagicMock
    from app.repositories.enrichment_repository import EnrichmentRepository
    repo = MagicMock(spec=EnrichmentRepository)
    repo.save_enrichment.return_value = None
    repo.get_recent_enrichments.return_value = []
    return repo

from app.api.dependencies import get_enrichment_service, get_enrichment_repository

@pytest.fixture(autouse=True)
def override_dependencies():
    app.dependency_overrides[get_enrichment_service] = get_mock_enrichment_service
    app.dependency_overrides[get_enrichment_repository] = get_mock_enrichment_repo
    yield
    app.dependency_overrides.pop(get_enrichment_service, None)
    app.dependency_overrides.pop(get_enrichment_repository, None)

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

def test_providers():
    res = client.get("/api/v1/enrichment/providers")
    assert res.status_code == 200
    assert "mock_healthy" in res.json()["providers"]

def test_analyze():
    res = client.post("/api/v1/enrichment/analyze", json=create_mock_alert())
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 1  # the healthy provider should return data
    
def test_cache_logic():
    cache = InMemoryCache(ttl_seconds=1)
    cache.set("test_key", {"val": 123})
    assert cache.get("test_key") == {"val": 123}
    import time
    time.sleep(1.1)
    assert cache.get("test_key") is None

def test_lookup_ioc():
    res = client.get("/api/v1/enrichment/ioc/1.1.1.1")
    assert res.status_code == 200
    data = res.json()
    assert data["observable"] == "1.1.1.1"
    assert data["observable_type"] == "ip"
    # It will be 0 because we didn't mock abuseipdb specifically
    assert data["risk"]["score"] == 0
    
def test_history():
    res = client.get("/api/v1/enrichment/history")
    assert res.status_code == 200
    assert isinstance(res.json(), list)
