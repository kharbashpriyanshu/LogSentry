from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from app.config.settings import settings
from app.middleware.core import CoreMiddleware
from app.exceptions.handlers import add_exception_handlers

# Routers
from app.api.v1.routers.health import router as health_router
from app.api.v1.routers.parser import router as parser_router
from app.api.v1.routers.detection import router as detection_router
from app.api.v1.routers.alerts import router as alerts_router

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version="1.0.0",
        description="Enterprise SIEM parsing and detection backend API.",
        contact={
            "name": "Security Engineering",
            "email": "security@logsentry.local",
        }
    )

    # Middleware Registration (Order matters: Core outer, GZip inner)
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(CoreMiddleware)

    # Exception Handlers
    add_exception_handlers(app)

    # API Routers
    app.include_router(health_router, prefix=f"{settings.API_V1_STR}", tags=["Health"])
    app.include_router(parser_router, prefix=f"{settings.API_V1_STR}/parser", tags=["Parser"])
    app.include_router(detection_router, prefix=f"{settings.API_V1_STR}/detection", tags=["Detection"])
    app.include_router(alerts_router, prefix=f"{settings.API_V1_STR}/alerts", tags=["Alerts"])

    return app

app = create_app()
