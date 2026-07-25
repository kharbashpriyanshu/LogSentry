from sqlalchemy.orm import Session
from app.models.alert import AlertModel
from app.schemas.detection_alert import DetectionAlert
from app.schemas.severity import Severity
from app.core.events import event_bus
from typing import List, Optional

class AlertRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_alerts(self, page: int = 1, limit: int = 50, severity: Optional[str] = None) -> List[DetectionAlert]:
        query = self.db.query(AlertModel)
        if severity:
            query = query.filter(AlertModel.severity == severity)
        
        models = query.order_by(AlertModel.created_at.desc()).offset((page - 1) * limit).limit(limit).all()
        return [self._to_schema(m) for m in models]

    def create_alert(self, alert: DetectionAlert) -> DetectionAlert:
        model = AlertModel(
            id=alert.alert_id,
            title=alert.title,
            description=alert.description,
            severity=alert.severity.value if isinstance(alert.severity, Severity) else alert.severity,
            rule_name=alert.rule_name,
            attack_type=alert.attack_type,
            source_ip=alert.source_ip,
            destination_ip=alert.destination_ip,
            confidence=alert.confidence,
            risk_score=alert.risk_score,
            mitre_technique=alert.mitre_technique,
            mitre_tactic=alert.mitre_tactic,
            recommendation=alert.recommendation,
            evidence=alert.evidence,
            raw_log_reference=alert.raw_log_reference,
            endpoint=alert.endpoint,
            hostname=alert.endpoint, # using endpoint for hostname fallback if needed
            rule_version=alert.rule_version,
            created_at=alert.timestamp
        )
        self.db.add(model)
        self.db.commit()
        self.db.refresh(model)
        
        schema = self._to_schema(model)
        event_bus.publish("alert.created", {"id": schema.alert_id, "title": schema.title, "severity": schema.severity.value})
        
        return schema
        
    def get_alert_by_id(self, alert_id: str) -> Optional[AlertModel]:
        return self.db.query(AlertModel).filter(AlertModel.id == alert_id).first()

    def update_alert(self, alert_id: str, updates: dict) -> Optional[AlertModel]:
        model = self.get_alert_by_id(alert_id)
        if not model:
            return None
        
        for key, value in updates.items():
            if hasattr(model, key):
                setattr(model, key, value)
        
        self.db.commit()
        self.db.refresh(model)
        
        event_bus.publish("alert.updated", {"id": model.id, "status": model.status, "assignee": model.assigned_analyst})
        return model

    def _to_schema(self, model: AlertModel) -> DetectionAlert:
        return DetectionAlert(
            alert_id=model.id,
            timestamp=model.created_at,
            rule_name=model.rule_name,
            rule_version=model.rule_version or "1.0.0",
            severity=Severity(model.severity),
            confidence=model.confidence or 0.0,
            risk_score=model.risk_score or 0.0,
            title=model.title,
            description=model.description or "",
            source_ip=model.source_ip,
            destination_ip=model.destination_ip,
            endpoint=model.endpoint,
            attack_type=model.attack_type,
            mitre_technique=model.mitre_technique,
            mitre_tactic=model.mitre_tactic,
            recommendation=model.recommendation,
            evidence=model.evidence or {},
            raw_log_reference=model.raw_log_reference or "",
            status=model.status,
            assignee=model.assigned_analyst,
            resolved_at=model.resolved_at,
            resolution_note=model.resolution_note
        )
