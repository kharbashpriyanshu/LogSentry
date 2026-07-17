"""
Hardened health check router with liveness, readiness, and version probes.

Changes from Sprint 7:
  - /health now returns additional subsystem status detail
  - /health/live — raw liveness probe (always 200 if process is alive)
  - /health/ready — readiness probe (checks parsers + detection rules)
  - Response model extended with environment and version fields
"""

import time
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Dict

from app.config.settings import settings
from app.parsers.factory import ParserFactory
from app.detection.registry import RuleRegistry

router = APIRouter()

START_TIME = time.time()


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    uptime_seconds: float
    parsers_available: int
    detection_rules_available: int
    subsystems: Dict[str, bool]


@router.get("/health", response_model=HealthResponse, summary="Application health check")
def health_check() -> HealthResponse:
    """
    Returns application health status including subsystem availability.
    Used by load balancers, monitoring systems, and dashboards.
    """
    parsers = ParserFactory.get_all_parsers()
    rules = RuleRegistry.get_all_rules()

    return HealthResponse(
        status="healthy",
        version=settings.VERSION,
        environment=settings.ENVIRONMENT,
        uptime_seconds=round(time.time() - START_TIME, 2),
        parsers_available=len(parsers),
        detection_rules_available=len(rules),
        subsystems={
            "parsers": len(parsers) > 0,
            "detection_rules": len(rules) > 0,
        },
    )


@router.get("/health/live", include_in_schema=False)
def liveness() -> dict:
    """Kubernetes liveness probe."""
    return {"status": "alive"}


@router.get("/health/ready", include_in_schema=False)
def readiness() -> dict:
    """Kubernetes readiness probe."""
    checks = {
        "parsers": len(ParserFactory.get_all_parsers()) > 0,
        "detection_rules": len(RuleRegistry.get_all_rules()) > 0,
    }
    ready = all(checks.values())
    return {"status": "ready" if ready else "not_ready", "checks": checks}
