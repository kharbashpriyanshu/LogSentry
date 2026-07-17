from fastapi import APIRouter, Depends, HTTPException, Response
from typing import List, Dict, Any
from app.schemas.detection_alert import DetectionAlert
from app.ai.models import AIAnalysisResponse
from app.services.ai_service import AIService
from app.api.dependencies import get_ai_service
from app.ai.exceptions import AIError

router = APIRouter()

@router.post("/analyze", response_model=AIAnalysisResponse)
def analyze_alert(
    alert: DetectionAlert,
    ai_service: AIService = Depends(get_ai_service)
):
    try:
        return ai_service.analyze(alert)
    except AIError:
        # Handled by global exception handlers
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/providers")
def get_providers(ai_service: AIService = Depends(get_ai_service)) -> Dict[str, Any]:
    return {
        "active_provider": ai_service.get_provider_name(),
        "available_providers": ["openai", "gemini", "ollama"]
    }

@router.get("/health")
def health_check(response: Response, ai_service: AIService = Depends(get_ai_service)) -> Dict[str, Any]:
    is_healthy = ai_service.check_health()
    if not is_healthy:
        response.status_code = 503
        
    return {
        "provider": ai_service.get_provider_name(),
        "healthy": is_healthy
    }
