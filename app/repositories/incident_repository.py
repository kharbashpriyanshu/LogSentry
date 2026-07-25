from sqlalchemy.orm import Session
from app.models.incident import IncidentModel
from app.models.alert import AlertModel
from app.schemas.incident import IncidentCreate, IncidentUpdate, IncidentResponse
from app.core.events import event_bus
from typing import List, Optional
from datetime import datetime, timezone

class IncidentRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_incident(self, incident_id: str) -> Optional[IncidentResponse]:
        model = self.db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
        if not model:
            return None
        return self._to_schema(model)

    def get_incidents(self, page: int = 1, limit: int = 50, status: Optional[str] = None) -> List[IncidentResponse]:
        query = self.db.query(IncidentModel)
        if status:
            query = query.filter(IncidentModel.status == status)
        models = query.order_by(IncidentModel.created_at.desc()).offset((page - 1) * limit).limit(limit).all()
        return [self._to_schema(m) for m in models]

    def create_incident(self, data: IncidentCreate) -> IncidentResponse:
        model = IncidentModel(
            title=data.title,
            description=data.description,
            severity=data.severity,
            priority=data.priority,
            status="open"
        )
        
        # Attach alerts if valid
        if data.alert_ids:
            alerts = self.db.query(AlertModel).filter(AlertModel.id.in_(data.alert_ids)).all()
            for alert in alerts:
                model.alerts.append(alert)
        
        self.db.add(model)
        self.db.commit()
        self.db.refresh(model)
        
        schema = self._to_schema(model)
        event_bus.publish("incident.created", {"id": schema.id, "title": schema.title, "status": schema.status})
        
        return schema

    def update_incident(self, incident_id: str, updates: IncidentUpdate) -> Optional[IncidentResponse]:
        model = self.db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
        if not model:
            return None

        update_dict = updates.model_dump(exclude_unset=True)
        alert_ids_to_add = update_dict.pop('add_alert_ids', None)

        for key, value in update_dict.items():
            setattr(model, key, value)
            
        if updates.status == "resolved" and not model.resolved_at:
            model.resolved_at = datetime.now(timezone.utc)

        if alert_ids_to_add:
            alerts = self.db.query(AlertModel).filter(AlertModel.id.in_(alert_ids_to_add)).all()
            for alert in alerts:
                if alert not in model.alerts:
                    model.alerts.append(alert)

        self.db.commit()
        self.db.refresh(model)
        
        schema = self._to_schema(model)
        event_bus.publish("incident.updated", {"id": schema.id, "status": schema.status, "assignee": schema.assignee})
        
        return schema

    def _to_schema(self, model: IncidentModel) -> IncidentResponse:
        alert_ids = [a.id for a in model.alerts]
        return IncidentResponse(
            id=model.id,
            title=model.title,
            description=model.description,
            severity=model.severity,
            priority=model.priority,
            status=model.status,
            assignee=model.assignee,
            created_at=model.created_at,
            updated_at=model.updated_at,
            resolved_at=model.resolved_at,
            alert_ids=alert_ids
        )
