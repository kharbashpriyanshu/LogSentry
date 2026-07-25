from fastapi import APIRouter, Depends, Query, HTTPException
from typing import List, Optional
from app.schemas.incident import IncidentCreate, IncidentUpdate, IncidentResponse
from app.schemas.timeline import TimelineEventResponse
from app.repositories.incident_repository import IncidentRepository
from app.repositories.timeline_repository import TimelineRepository
from app.api.dependencies import get_incident_repository, get_timeline_repository

router = APIRouter()

@router.post("", response_model=IncidentResponse, status_code=201)
def create_incident(
    data: IncidentCreate,
    repo: IncidentRepository = Depends(get_incident_repository),
    timeline: TimelineRepository = Depends(get_timeline_repository)
):
    incident = repo.create_incident(data)
    timeline.add_event("incident", incident.id, "created", metadata_json={"title": data.title})
    if data.alert_ids:
        for aid in data.alert_ids:
            timeline.add_event("alert", aid, "escalated", metadata_json={"incident_id": incident.id})
    return incident

@router.get("", response_model=List[IncidentResponse])
def list_incidents(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    status: Optional[str] = None,
    repo: IncidentRepository = Depends(get_incident_repository)
):
    return repo.get_incidents(page=page, limit=limit, status=status)

@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(
    incident_id: str,
    repo: IncidentRepository = Depends(get_incident_repository)
):
    incident = repo.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident

@router.patch("/{incident_id}", response_model=IncidentResponse)
def update_incident(
    incident_id: str,
    updates: IncidentUpdate,
    repo: IncidentRepository = Depends(get_incident_repository),
    timeline: TimelineRepository = Depends(get_timeline_repository)
):
    incident = repo.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    old_status = incident.status
    old_assignee = incident.assignee
    
    updated = repo.update_incident(incident_id, updates)
    
    if updates.status and updates.status != old_status:
        timeline.add_event("incident", incident_id, "status_changed", old_value=old_status, new_value=updates.status)
    if updates.assignee and updates.assignee != old_assignee:
        timeline.add_event("incident", incident_id, "assigned", old_value=old_assignee, new_value=updates.assignee)
    if updates.add_alert_ids:
        for aid in updates.add_alert_ids:
            timeline.add_event("alert", aid, "escalated", metadata_json={"incident_id": incident_id})
            
    return updated

@router.get("/{incident_id}/timeline", response_model=List[TimelineEventResponse])
def get_incident_timeline(
    incident_id: str,
    timeline: TimelineRepository = Depends(get_timeline_repository)
):
    return timeline.get_events("incident", incident_id)
