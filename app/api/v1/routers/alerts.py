from fastapi import APIRouter, Query, Depends, HTTPException
from typing import List, Optional
from app.schemas.detection_alert import DetectionAlert
from app.schemas.alert_update import AlertUpdate
from app.schemas.timeline import TimelineEventResponse
from app.api.dependencies import get_alert_repository, get_timeline_repository
from app.repositories.alert_repository import AlertRepository
from app.repositories.timeline_repository import TimelineRepository
from datetime import datetime, timezone

router = APIRouter()

@router.get("", response_model=List[DetectionAlert])
def get_alerts(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    severity: Optional[str] = None,
    repo: AlertRepository = Depends(get_alert_repository)
):
    """Get all alerts with pagination and filtering."""
    return repo.get_alerts(page=page, limit=limit, severity=severity)

@router.patch("/{alert_id}", response_model=DetectionAlert)
def update_alert(
    alert_id: str,
    updates: AlertUpdate,
    repo: AlertRepository = Depends(get_alert_repository),
    timeline: TimelineRepository = Depends(get_timeline_repository)
):
    # Retrieve current state
    alert = repo.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    old_status = alert.status
    old_assignee = alert.assigned_analyst
    
    update_dict = updates.model_dump(exclude_unset=True)
    
    # Handle resolution lifecycle updates
    if updates.status in ["RESOLVED", "FALSE_POSITIVE", "resolved", "false_positive"]:
        update_dict["resolved_at"] = datetime.now(timezone.utc)
    
    if updates.assignee is not None:
        update_dict["assigned_analyst"] = updates.assignee
        del update_dict["assignee"]
        
    # Prevent invalid transitions
    if updates.status and old_status.upper() == "FALSE_POSITIVE" and updates.status.upper() == "INVESTIGATING":
        raise HTTPException(status_code=409, detail="Cannot silently transition from FALSE_POSITIVE to INVESTIGATING")

    updated_model = repo.update_alert(alert_id, update_dict)
    
    # Audit trail
    if updates.status and updates.status != old_status:
        timeline.add_event("alert", alert_id, "status_changed", old_value=old_status, new_value=updates.status, metadata_json={"note": updates.resolution_note})
    if updates.assignee and updates.assignee != old_assignee:
        timeline.add_event("alert", alert_id, "assigned", old_value=old_assignee, new_value=updates.assignee)
        
    return repo._to_schema(updated_model)

@router.get("/{alert_id}/timeline", response_model=List[TimelineEventResponse])
def get_alert_timeline(
    alert_id: str,
    timeline: TimelineRepository = Depends(get_timeline_repository)
):
    return timeline.get_events("alert", alert_id)

@router.get("/example", response_model=List[DetectionAlert])
def get_example_alerts(repo: AlertRepository = Depends(get_alert_repository)):
    """Temporary endpoint returning example alerts."""
    return repo.get_alerts(page=1, limit=1)
