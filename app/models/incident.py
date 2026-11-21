import uuid
from datetime import UTC, datetime

from sqlalchemy import Column, DateTime, String
from sqlalchemy.orm import relationship

from app.database.base import Base
from app.models.alert import incident_alert_association


class IncidentModel(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String, nullable=False)
    description = Column(String, nullable=True)
    severity = Column(String, nullable=False)
    status = Column(String, nullable=False, default="open", index=True)
    assignee = Column(String, nullable=True, index=True)
    priority = Column(String, nullable=True)
    category = Column(String, nullable=True)
    tags = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    alerts = relationship(
        "AlertModel", secondary=incident_alert_association, back_populates="incidents"
    )
