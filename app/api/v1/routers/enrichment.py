from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response

from app.api.dependencies import get_enrichment_repository, get_enrichment_service
from app.core.rbac import UserContext, get_current_user
from app.enrichment.models import NormalizedThreatIntel, ThreatEnrichment
from app.models.enrichment import EnrichmentModel
from app.repositories.enrichment_repository import EnrichmentRepository
from app.schemas.detection_alert import DetectionAlert
from app.services.enrichment_service import EnrichmentService

router = APIRouter()


@router.post("/analyze", response_model=list[ThreatEnrichment])
@router.post("/enrich", response_model=list[ThreatEnrichment])
def analyze_alert(
    alert: DetectionAlert,
    user: UserContext = Depends(get_current_user),
    enrichment_service: EnrichmentService = Depends(get_enrichment_service),
):
    try:
        return enrichment_service.enrich_alert(alert)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ioc/{observable}", response_model=NormalizedThreatIntel)
def lookup_ioc(
    observable: str,
    force_refresh: bool = False,
    user: UserContext = Depends(get_current_user),
    enrichment_service: EnrichmentService = Depends(get_enrichment_service),
    enrichment_repo: EnrichmentRepository = Depends(get_enrichment_repository),
):
    try:
        # Check cache if not force refreshing
        cache_key = f"ioc:{observable}"
        if not force_refresh:
            cached_data = enrichment_service.cache.get(cache_key)
            if cached_data:
                cached_data.cached = True
                return cached_data

        # Perform enrichment
        result = enrichment_service.enrich_ioc(observable)

        # Save to DB history
        model = EnrichmentModel(
            observable_value=result.observable,
            provider="aggregated",
            reputation=(
                "malicious" if result.risk.level in ["critical", "high"] else "clean"
            ),
            confidence=float(result.risk.score) / 100.0,
            result=result.model_dump(mode="json"),
        )
        enrichment_repo.save_enrichment(model)

        # Cache the result
        enrichment_service.cache.set(cache_key, result)

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history")
def get_enrichment_history(
    limit: int = 10,
    user: UserContext = Depends(get_current_user),
    enrichment_repo: EnrichmentRepository = Depends(get_enrichment_repository),
):
    history = enrichment_repo.get_recent_enrichments(limit=limit)
    return [h.result for h in history if h.result]


@router.get("/providers")
def get_providers(
    enrichment_service: EnrichmentService = Depends(get_enrichment_service),
) -> dict[str, Any]:
    return enrichment_service.get_providers_health()


@router.get("/health")
def health_check(
    response: Response,
    enrichment_service: EnrichmentService = Depends(get_enrichment_service),
) -> dict[str, Any]:
    health_data = enrichment_service.get_providers_health()
    if not health_data["overall"]:
        response.status_code = 503

    return {"healthy": health_data["overall"], "details": health_data["providers"]}
