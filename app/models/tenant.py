import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import relationship

from app.database.base import Base


class TenantModel(Base):
    __tablename__ = "tenants"

    id = Column(String(64), primary_key=True)  # e.g. "default", "corp-sec-ops"
    name = Column(String(128), nullable=False)
    description = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    memberships = relationship(
        "UserTenantMembershipModel",
        back_populates="tenant",
        cascade="all, delete-orphan",
    )


class UserTenantMembershipModel(Base):
    __tablename__ = "user_tenant_memberships"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tenant_id = Column(
        String(64),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role = Column(String(32), nullable=True)  # Optional role override per tenant
    created_at = Column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("user_id", "tenant_id", name="uq_user_tenant_membership"),
    )

    user = relationship("UserModel", back_populates="memberships")
    tenant = relationship("TenantModel", back_populates="memberships")
