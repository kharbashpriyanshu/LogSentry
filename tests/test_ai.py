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
            mitre_technique="T1234",
            confidence_score=0.99,
            false_positive_likelihood="Low",
            analyst_notes="Mock notes"
        )

def get_mock_ai_service():
    return AIService(MockAIProvider())

# Dependency override
app.dependency_overrides[get_ai_service] = get_mock_ai_service

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
    res = client.post("/api/v1/ai/analyze", json=create_mock_alert())
    assert res.status_code == 200
    assert res.json()["executive_summary"] == "Mock summary"

def test_ai_analyze_unavailable():
    class FailingProvider(MockAIProvider):
        def analyze_alert(self, alert):
            raise AIProviderUnavailableError("Down")
            
    def get_failing_service():
        return AIService(FailingProvider())
        
    app.dependency_overrides[get_ai_service] = get_failing_service
    res = client.post("/api/v1/ai/analyze", json=create_mock_alert())
    assert res.status_code == 503
    
    app.dependency_overrides[get_ai_service] = get_mock_ai_service

def test_ai_analyze_timeout():
    class TimeoutProvider(MockAIProvider):
        def analyze_alert(self, alert):
            raise AITimeoutError("Timeout")
            
    def get_timeout_service():
        return AIService(TimeoutProvider())
        
    app.dependency_overrides[get_ai_service] = get_timeout_service
    res = client.post("/api/v1/ai/analyze", json=create_mock_alert())
    assert res.status_code == 504
    
    app.dependency_overrides[get_ai_service] = get_mock_ai_service
