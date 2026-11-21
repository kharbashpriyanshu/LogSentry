import uuid
from datetime import UTC, datetime

from sqlalchemy import Column, DateTime, Integer, String, Text

from app.database.base import Base


class SOARActionModel(Base):
    """Persistent audit model for all active containment and automation actions."""

    __tablename__ = "soar_actions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String, default="default", index=True)
    action_type = Column(
        String, nullable=False
    )  # QUARANTINE_IP, IPTABLES_DROP, CLOUDFLARE_BLOCK, JIRA_TICKET
    target = Column(String, nullable=False)  # IP address, hostname, or ticket key
    status = Column(
        String, default="ACTIVE"
    )  # ACTIVE, RELEASED, EXPIRED, PENDING_APPROVAL, ROLLED_BACK
    reason = Column(Text, nullable=False)
    requested_by = Column(String, nullable=False)  # analyst id or SYSTEM_AUTOMATION
    approved_by = Column(String, nullable=True)  # privileged authorizer
    duration_seconds = Column(Integer, default=3600)
    provider_reference = Column(String, nullable=True)  # e.g. Cloudflare rule ID
    rollback_command = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    executed_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    expires_at = Column(DateTime(timezone=True), nullable=True)
