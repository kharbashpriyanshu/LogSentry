from enum import StrEnum
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from pydantic import BaseModel


class UserRole(StrEnum):
    TIER_1_ANALYST = "Tier1_Analyst"  # View dashboard, triage alerts
    TIER_2_ANALYST = "Tier2_Analyst"  # Create incidents, containment
    THREAT_HUNTER = "Threat_Hunter"  # Custom queries & author rules
    SOC_MANAGER = "SOC_Manager"  # Audit logs, configuration
    ADMIN = "Admin"  # Full superuser access


ROLE_HIERARCHY: dict[UserRole, int] = {
    UserRole.TIER_1_ANALYST: 1,
    UserRole.TIER_2_ANALYST: 2,
    UserRole.THREAT_HUNTER: 2,
    UserRole.SOC_MANAGER: 3,
    UserRole.ADMIN: 4,
}


class UserContext(BaseModel):
    user_id: str
    email: str
    role: UserRole
    tenant_id: str = "default"


def get_current_user(
    x_user_id: Annotated[str | None, Header()] = "analyst-001",
    x_user_role: Annotated[str | None, Header()] = "Tier2_Analyst",
    x_tenant_id: Annotated[str | None, Header()] = "default",
) -> UserContext:
    """Extract authenticated user identity and role from headers (or SSO bearer token)."""
    try:
        role = UserRole(x_user_role)
    except ValueError:
        role = UserRole.TIER_1_ANALYST

    return UserContext(
        user_id=x_user_id or "analyst-001",
        email=f"{x_user_id or 'analyst'}@logsentry.corp",
        role=role,
        tenant_id=x_tenant_id or "default",
    )


def require_role(*allowed_roles: UserRole):
    """Dependency that enforces RBAC authorization for endpoints."""

    def role_checker(user: UserContext = Depends(get_current_user)) -> UserContext:
        if user.role == UserRole.ADMIN:
            return user

        if user.role not in allowed_roles:
            role_values = [r.value for r in allowed_roles]
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. User role '{user.role.value}' is insufficient. Required: {role_values}",
            )
        return user

    return role_checker
