import time
from fastapi import APIRouter
from app.schemas.api import HealthResponse
from app.parsers.factory import ParserFactory
from app.detection.registry import RuleRegistry

router = APIRouter()

START_TIME = time.time()

@router.get("/health", response_model=HealthResponse)
def health_check():
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        uptime_seconds=round(time.time() - START_TIME, 2),
        parsers_available=len(ParserFactory.get_all_parsers()),
        detection_rules_available=len(RuleRegistry.get_all_rules())
    )
