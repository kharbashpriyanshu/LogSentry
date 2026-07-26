from fastapi import APIRouter, Query, Depends, HTTPException
from typing import List, Optional
from app.schemas.detection_alert import DetectionAlert
from app.schemas.alert_update import AlertUpdate
from app.schemas.timeline import TimelineEventResponse
from app.api.dependencies import get_alert_repository, get_timeline_repository
from app.repositories.alert_repository import AlertRepository
from app.repositories.timeline_repository import TimelineRepository
from datetime import datetime, timezone
from app.schemas.alert_workflow import AlertFalsePositive, AlertResolve, AlertAssign, AlertInvestigate, AlertComment
from app.schemas.incident import IncidentCreate, IncidentResponse
from app.api.dependencies import get_incident_repository
from app.repositories.incident_repository import IncidentRepository

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

@router.post("/{alert_id}/false-positive", response_model=DetectionAlert)
def mark_false_positive(
    alert_id: str,
    payload: AlertFalsePositive,
    repo: AlertRepository = Depends(get_alert_repository),
    timeline: TimelineRepository = Depends(get_timeline_repository)
):
    alert = repo.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    old_status = alert.status
    update_dict = {
        "status": "FALSE_POSITIVE",
        "resolved_at": datetime.now(timezone.utc),
        "false_positive_reason": payload.reason,
        "resolution_note": payload.notes
    }
    updated_model = repo.update_alert(alert_id, update_dict)
    
    timeline.add_event("alert", alert_id, "marked_false_positive", old_value=old_status, new_value="FALSE_POSITIVE", 
                       metadata_json={"reason": payload.reason, "notes": payload.notes, "user": payload.marked_by})
    return repo._to_schema(updated_model)

@router.post("/{alert_id}/resolve", response_model=DetectionAlert)
def resolve_alert(
    alert_id: str,
    payload: AlertResolve,
    repo: AlertRepository = Depends(get_alert_repository),
    timeline: TimelineRepository = Depends(get_timeline_repository)
):
    alert = repo.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    old_status = alert.status
    update_dict = {
        "status": "RESOLVED",
        "resolved_at": datetime.now(timezone.utc),
        "resolution_type": payload.resolution_type,
        "resolution_note": payload.notes
    }
    updated_model = repo.update_alert(alert_id, update_dict)
    
    timeline.add_event("alert", alert_id, "resolved", old_value=old_status, new_value="RESOLVED", 
                       metadata_json={"type": payload.resolution_type, "notes": payload.notes, "user": payload.resolved_by})
    return repo._to_schema(updated_model)

@router.post("/{alert_id}/assign", response_model=DetectionAlert)
def assign_alert(
    alert_id: str,
    payload: AlertAssign,
    repo: AlertRepository = Depends(get_alert_repository),
    timeline: TimelineRepository = Depends(get_timeline_repository)
):
    alert = repo.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    old_assignee = alert.assigned_analyst
    update_dict = {
        "assigned_analyst": payload.assignee,
        "assignment_notes": payload.notes
    }
    updated_model = repo.update_alert(alert_id, update_dict)
    
    timeline.add_event("alert", alert_id, "assigned", old_value=old_assignee, new_value=payload.assignee, 
                       metadata_json={"priority": payload.priority, "notes": payload.notes, "user": payload.assigned_by})
    return repo._to_schema(updated_model)

@router.post("/{alert_id}/comments")
def add_comment(
    alert_id: str,
    payload: AlertComment,
    repo: AlertRepository = Depends(get_alert_repository),
    timeline: TimelineRepository = Depends(get_timeline_repository)
):
    alert = repo.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    timeline.add_event("alert", alert_id, "commented", new_value=payload.content, metadata_json={"user": payload.author})
    return {"status": "success"}

@router.post("/{alert_id}/investigate", response_model=IncidentResponse)
def investigate_alert(
    alert_id: str,
    payload: AlertInvestigate,
    repo: AlertRepository = Depends(get_alert_repository),
    timeline: TimelineRepository = Depends(get_timeline_repository),
    incident_repo: IncidentRepository = Depends(get_incident_repository)
):
    alert = repo.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    # Create incident
    incident_in = IncidentCreate(
        title=payload.title,
        description=payload.description,
        severity=alert.severity,
        priority=payload.priority,
        category=payload.category,
        tags=payload.tags,
        alert_ids=[alert_id]
    )
    incident = incident_repo.create_incident(incident_in)
    
    # Update alert
    old_status = alert.status
    repo.update_alert(alert_id, {"status": "INVESTIGATING"})
    
    # Audit trail
    timeline.add_event("alert", alert_id, "investigation_started", old_value=old_status, new_value="INVESTIGATING", 
                       metadata_json={"incident_id": incident.id, "user": payload.investigator})
    timeline.add_event("incident", incident.id, "created", new_value=payload.title, metadata_json={"user": payload.investigator, "alert_id": alert_id})
    
    return incident

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
