from datetime import UTC, datetime

from sqlalchemy import JSON, Column, DateTime, Float, ForeignKey, String, Table
from sqlalchemy.orm import relationship

from app.database.base import Base

incident_alert_association = Table(
    "incident_alert",
    Base.metadata,
    Column("incident_id", String, ForeignKey("incidents.id"), primary_key=True),
    Column("alert_id", String, ForeignKey("alerts.id"), primary_key=True),
)


class AlertModel(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True)  # Map to alert_id in Pydantic schema
    title = Column(String, nullable=False)
    description = Column(String, nullable=True)
    severity = Column(String, nullable=False)
    rule_name = Column(String, nullable=False)
    attack_type = Column(String, nullable=False)
    source_ip = Column(String, index=True, nullable=True)
    destination_ip = Column(String, nullable=True)
    log_event_id = Column(String, ForeignKey("log_events.id"), nullable=True)
    status = Column(String, nullable=False, default="open", index=True)
    confidence = Column(Float, nullable=True)
    risk_score = Column(Float, nullable=True)
    mitre_technique = Column(String, nullable=True)
    mitre_tactic = Column(String, nullable=True)
    recommendation = Column(String, nullable=True)
    evidence = Column(JSON, nullable=True)
    raw_log_reference = Column(String, nullable=True)
    endpoint = Column(String, nullable=True)
    hostname = Column(String, nullable=True)
    rule_version = Column(String, nullable=True)
    assigned_analyst = Column(String, nullable=True)
    assignment_notes = Column(String, nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolution_type = Column(String, nullable=True)
    resolution_note = Column(String, nullable=True)
    false_positive_reason = Column(String, nullable=True)
    created_at = Column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    log_event = relationship("LogEventModel", back_populates="alerts")
    incidents = relationship(
        "IncidentModel", secondary=incident_alert_association, back_populates="alerts"
    )
