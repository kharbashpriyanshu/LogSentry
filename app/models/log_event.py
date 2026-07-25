from sqlalchemy import Column, String, DateTime, JSON, Text
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
import uuid
from app.database.base import Base

class LogEventModel(Base):
    __tablename__ = "log_events"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime(timezone=True), nullable=False)
    source = Column(String, nullable=True)
    source_type = Column(String, nullable=True)
    raw_log = Column(Text, nullable=False)
    parsed_data = Column(JSON, nullable=True)
    source_ip = Column(String, nullable=True)
    destination_ip = Column(String, nullable=True)
    http_method = Column(String, nullable=True)
    path = Column(String, nullable=True)
    status_code = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    alerts = relationship("AlertModel", back_populates="log_event")
