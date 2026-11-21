import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String
from sqlalchemy.orm import relationship

from app.database.base import Base


class AgentCredentialModel(Base):
    __tablename__ = "agent_credentials"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(128), nullable=False)
    api_key_hash = Column(
        String(64), unique=True, index=True, nullable=False
    )  # SHA-256
    api_key_prefix = Column(String(16), nullable=False)  # e.g. "lgs_agt_7a8b..."
    tenant_id = Column(
        String(64),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    is_active = Column(Boolean, default=True, nullable=False)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    tenant = relationship("TenantModel")
