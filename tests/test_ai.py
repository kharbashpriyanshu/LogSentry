import pytest
from unittest.mock import Mock, patch
from fastapi.testclient import TestClient
from app.main import app
from app.api.dependencies import get_ai_service
from app.ai.providers.base_provider import BaseAIProvider
from app.ai.models import AIAnalysisResponse
from app.schemas.detection_alert import DetectionAlert
from app.services.ai_service import AIService
from app.ai.exceptions import AIProviderUnavailableError, AITimeoutError
from datetime import datetime

class MockAIProvider(BaseAIProvider):
    @property
    def provider_name(self) -> str:
        return "mock_provider"
        
    def health(self) -> bool:
        return True
        
    def analyze_alert(self, alert: DetectionAlert) -> AIAnalysisResponse:
        return AIAnalysisResponse(
            executive_summary="Mock summary",
            technical_explanation="Mock tech",
            severity_justification="Mock sev",
            likely_attack_goal="Mock goal",
            potential_impact="Mock impact",
            recommended_actions="Mock actions",
            containment_strategy=[{"priority": "High", "action": "Block", "reason": "Stop attack"}],
            attack_chain=[{"stage": "Initial Access", "evidence": "SQLi", "confidence": 0.95}],
            cve_references=["CVE-2023-1234"],
            mitre_technique="T1234",
            confidence_score=0.99,
            false_positive_likelihood="Low",
            analyst_notes="Mock notes"
        )

from app.api.dependencies import get_alert_repository, get_ai_repository
from app.repositories.alert_repository import AlertRepository
from app.repositories.ai_repository import AIRepository
from app.models.alert import AlertModel
from app.models.ai_analysis import AIAnalysisModel
from unittest.mock import MagicMock

def get_mock_ai_service():
    return AIService(MockAIProvider())

def get_mock_alert_repo():
    repo = MagicMock(spec=AlertRepository)
    # mock get_alert_by_id
    mock_model = MagicMock(spec=AlertModel)
    repo.get_alert_by_id.return_value = mock_model
    mock_schema = MagicMock()
    repo._to_schema.return_value = mock_schema
    return repo

def get_mock_ai_repo():
    repo = MagicMock(spec=AIRepository)
    repo.save_analysis.return_value = None
    repo.get_analyses_for_alert.return_value = []
    return repo

@pytest.fixture(autouse=True)
def override_dependencies():
    app.dependency_overrides[get_ai_service] = get_mock_ai_service
    app.dependency_overrides[get_alert_repository] = get_mock_alert_repo
    app.dependency_overrides[get_ai_repository] = get_mock_ai_repo
    yield
    app.dependency_overrides.pop(get_ai_service, None)
    app.dependency_overrides.pop(get_alert_repository, None)
    app.dependency_overrides.pop(get_ai_repository, None)

client = TestClient(app)

def create_mock_request():
    return {
        "alert_id": "12345678-1234-5678-1234-567812345678"
    }

def test_ai_health():
    res = client.get("/api/v1/ai/health")
    assert res.status_code == 200
    assert res.json()["provider"] == "mock_provider"
    assert res.json()["healthy"] is True

def test_ai_providers():
    res = client.get("/api/v1/ai/providers")
    assert res.status_code == 200
    assert "mock_provider" in res.json()["active_provider"]

def test_ai_analyze_success():
    res = client.post("/api/v1/ai/analyze", json=create_mock_request())
    assert res.status_code == 200
    assert res.json()["executive_summary"] == "Mock summary"

def test_ai_analyze_unavailable():
    class FailingProvider(MockAIProvider):
        def analyze_alert(self, alert):
            raise AIProviderUnavailableError("Down")
            
    def get_failing_service():
        return AIService(FailingProvider())
        
    app.dependency_overrides[get_ai_service] = get_failing_service
    res = client.post("/api/v1/ai/analyze", json=create_mock_request())
    assert res.status_code == 502
    
    app.dependency_overrides[get_ai_service] = get_mock_ai_service

def test_ai_analyze_timeout():
    class TimeoutProvider(MockAIProvider):
        def analyze_alert(self, alert):
            raise AITimeoutError("Timeout")
            
    def get_timeout_service():
        return AIService(TimeoutProvider())
        
    app.dependency_overrides[get_ai_service] = get_timeout_service
    res = client.post("/api/v1/ai/analyze", json=create_mock_request())
    assert res.status_code == 502
    
    app.dependency_overrides[get_ai_service] = get_mock_ai_service
