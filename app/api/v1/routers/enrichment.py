from fastapi import APIRouter, Depends, HTTPException, Response
from typing import List, Dict, Any
from app.schemas.detection_alert import DetectionAlert
from app.enrichment.models import ThreatEnrichment
from app.services.enrichment_service import EnrichmentService
from app.api.dependencies import get_enrichment_service

router = APIRouter()

@router.post("/analyze", response_model=List[ThreatEnrichment])
def analyze_alert(
    alert: DetectionAlert,
    enrichment_service: EnrichmentService = Depends(get_enrichment_service)
):
    try:
        return enrichment_service.enrich_alert(alert)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/providers")
def get_providers(enrichment_service: EnrichmentService = Depends(get_enrichment_service)) -> Dict[str, Any]:
    return enrichment_service.get_providers_health()

@router.get("/health")
def health_check(response: Response, enrichment_service: EnrichmentService = Depends(get_enrichment_service)) -> Dict[str, Any]:
    health_data = enrichment_service.get_providers_health()
    if not health_data["overall"]:
        response.status_code = 503
        
    return {
        "healthy": health_data["overall"],
        "details": health_data["providers"]
    }
