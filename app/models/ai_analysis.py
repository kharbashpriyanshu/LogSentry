from sqlalchemy import Column, String, Float, DateTime, JSON
from datetime import datetime, timezone
import uuid
from app.database.base import Base

class AIAnalysisModel(Base):
    __tablename__ = "ai_analyses"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    alert_id = Column(String, index=True, nullable=False)
    provider = Column(String, nullable=False)
    model_name = Column(String, nullable=True)
    summary = Column(String, nullable=True)
    severity_assessment = Column(String, nullable=True)
    recommendations = Column(String, nullable=True)
    confidence_score = Column(Float, nullable=True)
    raw_response = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
