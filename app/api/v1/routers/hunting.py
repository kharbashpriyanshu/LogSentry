from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.log_event import LogEventModel
from app.services.hunting_service import (
    HuntingQueryRequest,
    HuntingSearchResult,
    ThreatHuntingEngine,
)

router = APIRouter(prefix="/hunting", tags=["Threat Hunting"])


@router.post("/search", response_model=HuntingSearchResult)
def execute_threat_hunt(
    request: HuntingQueryRequest,
    db: Session = Depends(get_db),
):
    """
    Execute an interactive threat hunting search with Lucene/OpenSearch syntax.
    Example queries:
      - source_ip:192.168.1.* AND status_code:>=400
      - endpoint:*/wp-admin* OR action:SSH_FAILED_LOGIN
    """
    # Fetch recent telemetry from DB
    query = db.query(LogEventModel)
    if request.tenant_id:
        query = query.filter(
            (LogEventModel.tenant_id == request.tenant_id)
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
