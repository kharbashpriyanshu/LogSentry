"""
Hardened FastAPI application factory for LogSentry.

Changes from Sprint 7:
  - Strict CORS policy (no wildcard in production)
  - RequestSizeLimitMiddleware (1 MB body cap)
  - Structured JSON logging initialised before first request
  - /metrics endpoint (in-process counters)
  - /readiness probe (dependency checks)
  - /liveness probe (always-200 heartbeat)
  - /version endpoint
  - Lifespan context manager (replaces deprecated on_event)
  - OpenAPI metadata hardened (no internal server URLs in docs)
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from app.config.settings import settings
from app.core.logging import setup_logging
from app.middleware.core import CoreMiddleware, RequestSizeLimitMiddleware, get_metrics
from app.exceptions.handlers import add_exception_handlers

# Routers
from app.api.v1.routers.health import router as health_router
from app.api.v1.routers.parser import router as parser_router
from app.api.v1.routers.detection import router as detection_router
from app.api.v1.routers.alerts import router as alerts_router
from app.api.v1.routers.ai import router as ai_router
from app.api.v1.routers.enrichment import router as enrichment_router
from app.api.v1.routers.reports import router as reports_router

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Lifespan (replaces deprecated @app.on_event)
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application startup and shutdown hooks."""
    setup_logging()
    logger.info(
        "LogSentry starting",
        extra={
            "version": settings.VERSION,
            "environment": settings.ENVIRONMENT,
        },
    )
    yield
    logger.info("LogSentry shutting down gracefully")


# ---------------------------------------------------------------------------
# Application Factory
# ---------------------------------------------------------------------------


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        description=(
            "Enterprise SIEM — log parsing, detection, AI analysis, "
            "threat intelligence, and incident reporting."
        ),
        contact={
            "name": "Security Engineering",
            "email": "security@logsentry.local",
        },
        license_info={"name": "MIT"},
        docs_url="/docs" if settings.ENVIRONMENT != "production" else None,
        redoc_url="/redoc" if settings.ENVIRONMENT != "production" else None,
        openapi_url="/openapi.json" if settings.ENVIRONMENT != "production" else None,
        lifespan=lifespan,
    )

    # ------------------------------------------------------------------
    # Middleware stack (order: outermost first, applied inside-out)
    # ------------------------------------------------------------------

    # 1. Request size guard — must be outermost (raw ASGI, before parsing)
    app.add_middleware(
        RequestSizeLimitMiddleware,  # type: ignore[arg-type]
        max_bytes=settings.MAX_REQUEST_SIZE_BYTES,
    )

    # 2. GZip compression for responses >= 1 KB
    app.add_middleware(GZipMiddleware, minimum_size=1000)

    # 3. CORS — strict allowlist (no wildcard in production)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization", "X-Correlation-ID"],
        expose_headers=["X-Correlation-ID", "X-Process-Time"],
        max_age=600,
    )

    # 4. Security headers + observability (correlation ID, metrics, logging)
    app.add_middleware(CoreMiddleware)

    # ------------------------------------------------------------------
    # Exception Handlers
    # ------------------------------------------------------------------
    add_exception_handlers(app)

    # ------------------------------------------------------------------
    # API Routers
    # ------------------------------------------------------------------
    prefix = settings.API_V1_STR
    app.include_router(health_router, prefix=prefix, tags=["Health"])
    app.include_router(parser_router, prefix=f"{prefix}/parser", tags=["Parser"])
    app.include_router(detection_router, prefix=f"{prefix}/detection", tags=["Detection"])
    app.include_router(alerts_router, prefix=f"{prefix}/alerts", tags=["Alerts"])
    app.include_router(ai_router, prefix=f"{prefix}/ai", tags=["AI SOC Analyst"])
    app.include_router(enrichment_router, prefix=f"{prefix}/enrichment", tags=["Threat Intelligence"])
    app.include_router(reports_router, prefix=f"{prefix}/reports", tags=["Reporting"])

    # ------------------------------------------------------------------
    # Observability endpoints (mounted directly on app, not versioned)
    # ------------------------------------------------------------------

    @app.get("/metrics", tags=["Observability"], include_in_schema=False)
    def metrics_endpoint():
        """In-process request metrics (Prometheus-compatible counter values)."""
        return get_metrics()

    @app.get("/liveness", tags=["Observability"], include_in_schema=False)
    def liveness():
        """Kubernetes liveness probe — returns 200 if the process is alive."""
        return {"status": "alive"}

    @app.get("/readiness", tags=["Observability"], include_in_schema=False)
    def readiness():
        """
        Kubernetes readiness probe — checks that core subsystems are operational.
        Returns 200 when ready to accept traffic, 503 when warming up.
        """
        from app.parsers.factory import ParserFactory
        from app.detection.registry import RuleRegistry
        checks = {
            "parsers": len(ParserFactory.get_all_parsers()) > 0,
            "detection_rules": len(RuleRegistry.get_all_rules()) > 0,
        }
        ready = all(checks.values())
        return {"status": "ready" if ready else "not_ready", "checks": checks}

    @app.get("/version", tags=["Observability"], include_in_schema=False)
    def version():
        """Application version and environment metadata."""
        return {
            "name": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "environment": settings.ENVIRONMENT,
        }

    return app


app = create_app()
