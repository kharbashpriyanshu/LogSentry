from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models.alert import AlertModel
from app.models.incident import IncidentModel
from app.models.log_event import LogEventModel
from datetime import datetime, timedelta, timezone
from app.models.timeline import TimelineEventModel
from typing import Optional

class DashboardRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_summary(self, time_range_hours: int = 24):
        cutoff = datetime.now(timezone.utc) - timedelta(hours=time_range_hours)
        
        # Alerts
        total_alerts = self.db.query(AlertModel).count()
        alerts_last_24h = self.db.query(AlertModel).filter(AlertModel.created_at >= cutoff).count()
        open_alerts = self.db.query(AlertModel).filter(func.upper(AlertModel.status) == "OPEN").count()
        investigating_alerts = self.db.query(AlertModel).filter(func.upper(AlertModel.status) == "INVESTIGATING").count()
        resolved_alerts = self.db.query(AlertModel).filter(func.upper(AlertModel.status) == "RESOLVED").count()
        fp_alerts = self.db.query(AlertModel).filter(func.upper(AlertModel.status) == "FALSE_POSITIVE").count()
        critical_alerts = self.db.query(AlertModel).filter(func.upper(AlertModel.severity) == "CRITICAL").count()
        high_alerts = self.db.query(AlertModel).filter(func.upper(AlertModel.severity) == "HIGH").count()
        
        # Incidents
        total_incidents = self.db.query(IncidentModel).count()
        open_incidents = self.db.query(IncidentModel).filter(func.upper(IncidentModel.status) == "OPEN").count()
        
        # Events
        events_processed = self.db.query(LogEventModel).count()
        
        return {
            "total_alerts": total_alerts,
            "open_alerts": open_alerts,
            "investigating_alerts": investigating_alerts,
            "resolved_alerts": resolved_alerts,
            "false_positive_alerts": fp_alerts,
            "critical_alerts": critical_alerts,
            "high_alerts": high_alerts,
            "total_incidents": total_incidents,
            "open_incidents": open_incidents,
            "events_processed": events_processed,
            "alerts_in_range": alerts_last_24h
        }

    def get_alert_trend(self, days: int = 7):
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        # Using SQLite/PostgreSQL safe basic date extraction (for demo, grouping in Python is safer cross-db)
        alerts = self.db.query(AlertModel.created_at).filter(AlertModel.created_at >= cutoff).all()
        
        trend = {}
        for (created_at,) in alerts:
            date_str = created_at.strftime('%Y-%m-%d')
            trend[date_str] = trend.get(date_str, 0) + 1
            
        return [{"date": k, "count": v} for k, v in trend.items()]

    def get_severity_distribution(self):
        result = self.db.query(AlertModel.severity, func.count(AlertModel.id)).group_by(AlertModel.severity).all()
        return [{"severity": k, "count": v} for k, v in result]

    def get_top_sources(self):
        result = self.db.query(AlertModel.source_ip, func.count(AlertModel.id)).filter(AlertModel.source_ip != None).group_by(AlertModel.source_ip).order_by(func.count(AlertModel.id).desc()).limit(5).all()
        return [{"source_ip": k, "count": v} for k, v in result]

    def get_top_attack_types(self, limit: int = 5):
        result = self.db.query(AlertModel.attack_type, func.count(AlertModel.id)).filter(AlertModel.attack_type != None).group_by(AlertModel.attack_type).order_by(func.count(AlertModel.id).desc()).limit(limit).all()
        return [{"attack_type": k, "count": v} for k, v in result]

    def get_top_mitre_techniques(self, limit: int = 5):
        result = self.db.query(AlertModel.mitre_technique, func.count(AlertModel.id)).filter(AlertModel.mitre_technique != None).group_by(AlertModel.mitre_technique).order_by(func.count(AlertModel.id).desc()).limit(limit).all()
        return [{"technique": k, "count": v} for k, v in result]

    def get_recent_incidents(self, limit: int = 5):
        incidents = self.db.query(IncidentModel).order_by(IncidentModel.created_at.desc()).limit(limit).all()
        return [
            {
                "id": inc.id,
                "title": inc.title,
                "severity": inc.severity,
                "status": inc.status,
                "priority": inc.priority,
                "assignee": inc.assignee,
                "created_at": inc.created_at,
            }
            for inc in incidents
        ]

    def get_recent_activity(self, limit: int = 50):
        events = self.db.query(TimelineEventModel).order_by(TimelineEventModel.created_at.desc()).limit(limit).all()
        results = []
        for ev in events:
            actor = None
            if ev.metadata_json:
                actor = ev.metadata_json.get("user") or ev.metadata_json.get("actor")
            if not actor and ev.actor:
                actor = ev.actor

            # Build a short, human-readable entity label (e.g. "ALT-0001" or "INC-0001")
            short_id = ev.entity_id[:8] if ev.entity_id else "?"

            results.append({
                "id": ev.id,
                "entity_type": ev.entity_type,
                "entity_id": ev.entity_id,
                "short_id": short_id,
                "action": ev.action,
                "actor": actor or "System",
                "metadata": ev.metadata_json,
                "created_at": ev.created_at,
                "old_value": ev.old_value,
                "new_value": ev.new_value
            })
        return results
