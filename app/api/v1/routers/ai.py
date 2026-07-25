from fastapi import APIRouter, Depends, HTTPException, Response
from typing import List, Dict, Any
from pydantic import BaseModel
from app.schemas.detection_alert import DetectionAlert
from app.ai.models import AIAnalysisResponse
from app.services.ai_service import AIService
from app.api.dependencies import get_ai_service, get_alert_repository, get_ai_repository
from app.repositories.alert_repository import AlertRepository
from app.repositories.ai_repository import AIRepository
from app.models.ai_analysis import AIAnalysisModel
from app.ai.exceptions import AIError
import json

router = APIRouter()

class AnalyzeRequest(BaseModel):
    alert_id: str

@router.post("/analyze", response_model=AIAnalysisResponse)
def analyze_alert(
    request: AnalyzeRequest,
    ai_service: AIService = Depends(get_ai_service),
    alert_repo: AlertRepository = Depends(get_alert_repository),
    ai_repo: AIRepository = Depends(get_ai_repository)
):
    try:
        # Fetch actual persisted alert
        alert_model = alert_repo.get_alert_by_id(request.alert_id)
        if not alert_model:
            raise HTTPException(status_code=404, detail="Alert not found")
            
        alert_schema = alert_repo._to_schema(alert_model) # type: DetectionAlert
        
        # Call AI provider
        ai_response = ai_service.analyze(alert_schema)
        
        # Persist response
        ai_model = AIAnalysisModel(
            alert_id=request.alert_id,
            provider=ai_service.get_provider_name(),
            summary=ai_response.executive_summary,
            severity_assessment=ai_response.severity_justification,
            confidence_score=ai_response.confidence_score,
            raw_response=ai_response.model_dump()
        )
        ai_repo.save_analysis(ai_model)
        
        return ai_response
    except AIError as e:
        raise HTTPException(status_code=502, detail=f"AI Provider Error: {str(e)}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/alerts/{alert_id}/ai-analyses")
def get_alert_analyses(
    alert_id: str,
    ai_repo: AIRepository = Depends(get_ai_repository)
):
    analyses = ai_repo.get_analyses_for_alert(alert_id)
    return [{
        "id": a.id,
        "provider": a.provider,
        "created_at": a.created_at,
        "summary": a.summary,
        "confidence_score": a.confidence_score,
        "raw_response": a.raw_response
    } for a in analyses]

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
