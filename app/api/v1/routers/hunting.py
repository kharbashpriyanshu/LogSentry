from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.rbac import UserContext, UserRole, get_current_user, require_role
from app.database.session import get_db
from app.models.log_event import LogEventModel
from app.services.duckdb_forensics import (
    ColumnarQueryRequest,
    ColumnarQueryResult,
    DuckDBForensicsEngine,
)
from app.services.hunting_copilot import (
    CopilotQueryRequest,
    CopilotResponse,
    HuntingCopilot,
)
from app.services.hunting_service import (
    HuntingQueryRequest,
    HuntingSearchResult,
    ThreatHuntingEngine,
)

router = APIRouter(prefix="/hunting", tags=["Threat Hunting"])


@router.post("/copilot", response_model=CopilotResponse)
def copilot_threat_hunt(
    request: CopilotQueryRequest,
    user: UserContext = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    AI Threat Hunting Copilot: Translates plain English security hypotheses
    into precision Lucene syntax, executes search, and generates threat attribution.
    Example questions:
      - "Find all failed logins targeting root user"
      - "Show me all PowerShell download cradles"
      - "Search for SQL injection attacks on public endpoints"
    """
    return HuntingCopilot.execute_copilot(db=db, req=request)


@router.post("/analytics", response_model=ColumnarQueryResult)
def run_duckdb_analytics(
    request: ColumnarQueryRequest,
    db: Session = Depends(get_db),
    user: UserContext = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SOC_MANAGER,
            UserRole.THREAT_HUNTER,
            UserRole.TIER_2_ANALYST,
        )
    ),
):
    """
    Sub-second Columnar Forensics Query (DuckDB Engine).
    Executes vectorized analytical SQL queries across log records in milliseconds.
    Strictly isolated and scoped to the authenticated analyst's tenant.
    """

    # Lock tenant_id to user identity (admin may query across/specify tenants)
    effective_tenant = (
        request.tenant_id
        if user.role == UserRole.ADMIN and request.tenant_id
        else user.tenant_id
    )

    try:
        return DuckDBForensicsEngine.execute_query(
            db=db,
            sql_query=request.sql_query,
            tenant_id=effective_tenant,
            time_range_hours=request.time_range_hours,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/search", response_model=HuntingSearchResult)
def execute_threat_hunt(
    request: HuntingQueryRequest,
    user: UserContext = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Execute an interactive threat hunting search with Lucene/OpenSearch syntax.
    Example queries:
      - source_ip:192.168.1.* AND status_code:>=400
      - endpoint:*/wp-admin* OR action:SSH_FAILED_LOGIN
    """
    effective_tenant = (
        request.tenant_id
        if user.role == UserRole.ADMIN and request.tenant_id
        else user.tenant_id
    )

    # Fetch recent telemetry from DB scoped to tenant
    query = db.query(LogEventModel)
    if effective_tenant:
        query = query.filter(
            (LogEventModel.tenant_id == effective_tenant)
            | (LogEventModel.tenant_id == "default")
            | (LogEventModel.tenant_id.is_(None))
        )

    records = query.order_by(LogEventModel.created_at.desc()).limit(2000).all()

    # Convert to dict representation for the hunting engine
    events = [
        {
            "id": r.id,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "source_ip": r.source_ip,
            "destination_ip": r.destination_ip,
            "method": r.http_method,
            "endpoint": r.path,
            "status_code": r.status_code,
            "user": getattr(r, "user", None),
            "event_id": getattr(r, "event_id", None),
            "action": getattr(r, "action", None),
            "raw_log": r.raw_log,
            "tenant_id": getattr(r, "tenant_id", "default"),
        }
        for r in records
    ]

    return ThreatHuntingEngine.search(
        query_str=request.query,
        events=events,
        limit=request.limit,
    )
