from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models.alert import AlertModel
from app.models.incident import IncidentModel
from app.models.log_event import LogEventModel
from datetime import datetime, timedelta, timezone

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
