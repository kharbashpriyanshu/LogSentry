from app.models.log_event import LogEventModel
from app.models.alert import AlertModel
from app.models.incident import IncidentModel
from app.models.enrichment import EnrichmentModel
from app.models.ai_analysis import AIAnalysisModel
from app.models.report import ReportModel
from datetime import datetime, timezone
import uuid

def test_log_event_persistence(db_session):
    event = LogEventModel(
        timestamp=datetime.now(timezone.utc),
        source="test_src",
        raw_log="test log"
    )
    db_session.add(event)
    db_session.commit()
    
    saved = db_session.query(LogEventModel).first()
    assert saved.source == "test_src"

def test_alert_persistence(db_session):
    alert = AlertModel(
        id=str(uuid.uuid4()),
        title="Test Alert",
        severity="high",
        rule_name="test_rule",
        attack_type="Test Attack"
    )
    db_session.add(alert)
    db_session.commit()
    
    saved = db_session.query(AlertModel).first()
    assert saved.title == "Test Alert"

def test_incident_and_alert_relationship(db_session):
    alert1 = AlertModel(
        id=str(uuid.uuid4()),
        title="Alert 1",
        severity="low",
        rule_name="rule1",
        attack_type="attack1"
    )
    alert2 = AlertModel(
        id=str(uuid.uuid4()),
        title="Alert 2",
        severity="low",
        rule_name="rule2",
        attack_type="attack2"
    )
    incident = IncidentModel(
        title="Major Incident",
        severity="critical"
    )
    incident.alerts.append(alert1)
    incident.alerts.append(alert2)
    
    db_session.add(incident)
    db_session.commit()
    
    saved_incident = db_session.query(IncidentModel).first()
    assert len(saved_incident.alerts) == 2
