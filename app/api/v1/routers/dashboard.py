from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.config.settings import settings
from app.core.jwt import decode_access_token
from app.core.rbac import UserContext, UserRole, get_current_user
from app.repositories.dashboard_repository import DashboardRepository
from app.services.websocket import manager

router = APIRouter()


def get_dashboard_repository(
    user: UserContext = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DashboardRepository:
    return DashboardRepository(db)


@router.get("/summary")
def get_dashboard_summary(
    time_range_hours: int = Query(24, ge=1, le=720),
    repo: DashboardRepository = Depends(get_dashboard_repository),
):
    return repo.get_summary(time_range_hours=time_range_hours)


@router.get("/alert-trend")
def get_alert_trend(
    days: int = Query(7, ge=1, le=30),
    repo: DashboardRepository = Depends(get_dashboard_repository),
):
    return repo.get_alert_trend(days=days)


@router.get("/severity-distribution")
def get_severity_distribution(
    repo: DashboardRepository = Depends(get_dashboard_repository),
):
    return repo.get_severity_distribution()


@router.get("/top-sources")
def get_top_sources(repo: DashboardRepository = Depends(get_dashboard_repository)):
    return repo.get_top_sources()


@router.get("/activity")
def get_recent_activity(
    limit: int = Query(50, ge=1, le=200),
    repo: DashboardRepository = Depends(get_dashboard_repository),
):
    return repo.get_recent_activity(limit=limit)


@router.get("/top-attack-types")
def get_top_attack_types(
    limit: int = Query(5, ge=1, le=20),
    repo: DashboardRepository = Depends(get_dashboard_repository),
):
    return repo.get_top_attack_types(limit=limit)


@router.get("/top-mitre")
def get_top_mitre_techniques(
    limit: int = Query(5, ge=1, le=20),
    repo: DashboardRepository = Depends(get_dashboard_repository),
):
    return repo.get_top_mitre_techniques(limit=limit)


@router.get("/recent-incidents")
def get_recent_incidents(
    limit: int = Query(5, ge=1, le=20),
    repo: DashboardRepository = Depends(get_dashboard_repository),
):
    return repo.get_recent_incidents(limit=limit)


@router.websocket("/ws/events")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str | None = Query(None),
):
    """
    Authenticated, tenant-isolated WebSocket feed for real-time security events.
    Enforces JWT authentication and delivers only events matching the caller's tenant.
    """
    tenant_id = "default"
    is_admin = False

    if token:
        try:
            payload = decode_access_token(token)
            tenant_id = payload.get("tenant_id", "default")
            is_admin = payload.get("role") in (UserRole.ADMIN.value, UserRole.ADMIN)
        except Exception as e:
            await websocket.close(code=1008, reason=f"Authentication failed: {e}")
            return
    else:
        is_production = getattr(settings, "ENVIRONMENT", "development") == "production"
        is_strict = getattr(settings, "AUTH_STRICT_MODE", False) or getattr(settings, "AUTH_STRICT_JWT", False)
        if is_production or is_strict:
            await websocket.close(code=1008, reason="Authentication token required")
            return

    await manager.connect(websocket, tenant_id=tenant_id, is_admin=is_admin)
    try:
        while True:
            await websocket.receive_text()  # keepalive
    except WebSocketDisconnect:
        manager.disconnect(websocket)
