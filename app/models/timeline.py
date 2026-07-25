from sqlalchemy import Column, String, DateTime, JSON
from datetime import datetime, timezone
import uuid
from app.database.base import Base

class TimelineEventModel(Base):
    __tablename__ = "timeline_events"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    entity_type = Column(String, index=True, nullable=False) # "alert" or "incident"
    entity_id = Column(String, index=True, nullable=False)
    action = Column(String, nullable=False)
    actor = Column(String, nullable=True)
    old_value = Column(String, nullable=True)
    new_value = Column(String, nullable=True)
    metadata_json = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
