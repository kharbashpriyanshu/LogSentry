from sqlalchemy import Column, String, DateTime
from datetime import datetime, timezone
import uuid
from app.database.base import Base

class ReportModel(Base):
    __tablename__ = "reports"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    report_type = Column(String, nullable=False)
    format = Column(String, nullable=False)
    filename = Column(String, nullable=True)
    storage_path = Column(String, nullable=True)
    status = Column(String, nullable=False, default="generated")
    alert_id = Column(String, index=True, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
