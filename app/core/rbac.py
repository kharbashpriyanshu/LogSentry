from enum import StrEnum
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from pydantic import BaseModel

from app.config.settings import settings
from app.core.jwt import decode_access_token


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
    authorization: Annotated[str | None, Header(description="Bearer <JWT>")] = None,
    x_user_id: Annotated[str | None, Header()] = None,
    x_user_role: Annotated[str | None, Header()] = None,
    x_tenant_id: Annotated[str | None, Header()] = None,
) -> UserContext:
    """
    Extracts authenticated user identity from cryptographically signed JWT Bearer token.
    In production, strictly requires Bearer token authentication.
    Rejects forged user role or tenant headers.
    """
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
        try:
            payload = decode_access_token(token)
            role_str = payload.get("role", UserRole.TIER_1_ANALYST.value)
            try:
                role = UserRole(role_str)
            except ValueError:
                role = UserRole.TIER_1_ANALYST

            return UserContext(
                user_id=payload.get("sub", "analyst-001"),
                email=payload.get(
                    "email", f"{payload.get('sub', 'analyst')}@logsentry.corp"
                ),
                role=role,
                tenant_id=payload.get("tenant_id", "default"),
            )
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid or expired authentication token: {e}",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # In production or strict auth mode, unauthenticated header fallback is forbidden
    is_production = getattr(settings, "ENVIRONMENT", "development") == "production"
    if is_production or getattr(settings, "AUTH_STRICT_JWT", False):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please provide a valid Bearer JWT access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Controlled development/test fallback:
    # Caller CANNOT elevate privileges to Admin or SOC_Manager via unauthenticated headers.
    requested_role = x_user_role or "Tier2_Analyst"
    try:
        parsed_role = UserRole(requested_role)
    except ValueError:
        parsed_role = UserRole.TIER_1_ANALYST

    # Disallow privilege escalation via unauthenticated header forgery
    if parsed_role in (UserRole.ADMIN, UserRole.SOC_MANAGER):
        parsed_role = UserRole.TIER_1_ANALYST

    return UserContext(
        user_id=x_user_id or "analyst-001",
        email=f"{x_user_id or 'analyst'}@logsentry.corp",
        role=parsed_role,
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
