import uuid
from datetime import UTC, datetime

from sqlalchemy import Column, DateTime, String

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
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
