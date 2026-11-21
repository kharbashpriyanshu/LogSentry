from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.dependencies import get_incident_repository, get_timeline_repository
from app.repositories.incident_repository import IncidentRepository
from app.repositories.timeline_repository import TimelineRepository
from app.schemas.incident import IncidentCreate, IncidentResponse, IncidentUpdate
from app.schemas.timeline import TimelineEventResponse

router = APIRouter()


@router.post("", response_model=IncidentResponse, status_code=201)
def create_incident(
    data: IncidentCreate,
    repo: IncidentRepository = Depends(get_incident_repository),
    timeline: TimelineRepository = Depends(get_timeline_repository),
):
    incident = repo.create_incident(data)
    timeline.add_event(
        "incident", incident.id, "created", metadata_json={"title": data.title}
    )
    if data.alert_ids:
        for aid in data.alert_ids:
            timeline.add_event(
                "alert", aid, "escalated", metadata_json={"incident_id": incident.id}
            )
    return incident


@router.get("", response_model=list[IncidentResponse])
def list_incidents(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    status: str | None = None,
    repo: IncidentRepository = Depends(get_incident_repository),
):
    return repo.get_incidents(page=page, limit=limit, status=status)


@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(
    incident_id: str, repo: IncidentRepository = Depends(get_incident_repository)
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
    timeline: TimelineRepository = Depends(get_timeline_repository),
):
    incident = repo.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    old_status = incident.status
    old_assignee = incident.assignee

    updated = repo.update_incident(incident_id, updates)

    if updates.status and updates.status != old_status:
        timeline.add_event(
            "incident",
            incident_id,
            "status_changed",
            old_value=old_status,
            new_value=updates.status,
        )
    if updates.assignee and updates.assignee != old_assignee:
        timeline.add_event(
            "incident",
            incident_id,
            "assigned",
            old_value=old_assignee,
            new_value=updates.assignee,
        )
    if updates.add_alert_ids:
        for aid in updates.add_alert_ids:
            timeline.add_event(
                "alert", aid, "escalated", metadata_json={"incident_id": incident_id}
            )

    return updated


@router.get("/{incident_id}/timeline", response_model=list[TimelineEventResponse])
def get_incident_timeline(
    incident_id: str, timeline: TimelineRepository = Depends(get_timeline_repository)
):
    return timeline.get_events("incident", incident_id)


from app.schemas.alert_workflow import AlertComment


@router.post("/{incident_id}/comments")
def add_incident_comment(
    incident_id: str,
    payload: AlertComment,
    repo: IncidentRepository = Depends(get_incident_repository),
    timeline: TimelineRepository = Depends(get_timeline_repository),
):
    incident = repo.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    timeline.add_event(
        "incident",
        incident_id,
        "commented",
        new_value=payload.content,
        metadata_json={"user": payload.author},
    )
    return {"status": "success"}


@router.get("/{incident_id}/graph")
def get_incident_attack_graph(
    incident_id: str,
    repo: IncidentRepository = Depends(get_incident_repository),
):
    """
    Returns an entity-relationship attack graph connecting attacker IPs, target hosts,
    associated alerts, MITRE techniques, and containment actions for this incident.
    """
    incident = repo.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    nodes = [
        {
            "id": f"inc-{incident.id}",
            "label": f"Incident: {incident.title}",
            "type": "incident",
            "severity": incident.priority,
        }
    ]
    edges = []

    # Parse and link alerts
    alerts = getattr(incident, "alerts", [])
    seen_ips = set()
    seen_mitre = set()

    for idx, alert in enumerate(alerts):
        alert_node_id = f"alt-{alert.id}"
        nodes.append(
            {
                "id": alert_node_id,
                "label": alert.title,
                "type": "alert",
                "severity": alert.severity,
                "rule": alert.rule_name,
            }
        )
        edges.append(
            {
                "from": alert_node_id,
                "to": f"inc-{incident.id}",
                "relation": "escalated_into",
            }
        )

        # Source IP Node
        src_ip = getattr(alert, "source_ip", None)
        if src_ip and src_ip not in seen_ips:
            seen_ips.add(src_ip)
            ip_node_id = f"ip-{src_ip}"
            nodes.append(
                {
                    "id": ip_node_id,
                    "label": f"Attacker IP: {src_ip}",
                    "type": "threat_actor",
                }
            )
            edges.append(
                {
                    "from": ip_node_id,
                    "to": alert_node_id,
                    "relation": "origin_of",
                }
            )

        # MITRE Technique Node
        mitre = getattr(alert, "mitre_technique", None)
        if mitre and mitre not in seen_mitre:
            seen_mitre.add(mitre)
            mitre_node_id = f"mitre-{mitre}"
            nodes.append(
                {
                    "id": mitre_node_id,
                    "label": f"ATT&CK {mitre}",
                    "type": "mitre_technique",
                }
            )
            edges.append(
                {
                    "from": alert_node_id,
                    "to": mitre_node_id,
                    "relation": "exhibits_behavior",
                }
            )

    return {
        "incident_id": incident.id,
        "title": incident.title,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
    }
