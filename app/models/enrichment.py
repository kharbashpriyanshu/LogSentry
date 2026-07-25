from sqlalchemy import Column, String, DateTime, JSON, Float
from datetime import datetime, timezone
import uuid
from app.database.base import Base

class EnrichmentModel(Base):
    __tablename__ = "enrichments"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    alert_id = Column(String, index=True, nullable=True)
    observable_value = Column(String, index=True, nullable=False)
    provider = Column(String, nullable=False)
    reputation = Column(String, nullable=True)
    confidence = Column(Float, nullable=True)
    result = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
