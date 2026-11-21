"""LogSentry Role-Based Access Control (RBAC) & Tenant Security Enforcement.

Enforces:
  - Cryptographically signed JWT verification for SOC analysts
  - Agent API key verification (X-Agent-Key) for machine collectors
  - Role hierarchy & explicit permission mapping
  - Strict tenant boundary isolation
"""

from enum import StrEnum
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config.settings import settings
from app.core.jwt import decode_access_token
from app.database.session import get_db


class UserRole(StrEnum):
    TIER_1_ANALYST = "Tier1_Analyst"  # View dashboard, triage alerts
    TIER_2_ANALYST = "Tier2_Analyst"  # Create incidents, containment
    THREAT_HUNTER = "Threat_Hunter"  # Custom queries & author rules
    SOC_MANAGER = "SOC_Manager"  # Audit logs, configuration, agent enrollment
    ADMIN = "Admin"  # Full superuser access


ROLE_HIERARCHY: dict[UserRole, int] = {
    UserRole.TIER_1_ANALYST: 1,
    UserRole.TIER_2_ANALYST: 2,
    UserRole.THREAT_HUNTER: 2,
    UserRole.SOC_MANAGER: 3,
    UserRole.ADMIN: 4,
}

# Explicit permission mappings per role
ROLE_PERMISSIONS: dict[UserRole, set[str]] = {
    UserRole.TIER_1_ANALYST: {
        "read:dashboard",
        "read:alerts",
        "read:incidents",
        "read:reports",
        "read:telemetry",
    },
    UserRole.TIER_2_ANALYST: {
        "read:dashboard",
        "read:alerts",
        "write:alerts",
        "read:incidents",
        "write:incidents",
        "write:soar",
        "read:reports",
        "write:reports",
        "read:telemetry",
    },
    UserRole.THREAT_HUNTER: {
        "read:dashboard",
        "read:alerts",
        "write:alerts",
        "read:incidents",
        "write:incidents",
        "hunt:duckdb",
        "write:rules",
        "read:intel",
        "read:reports",
        "read:telemetry",
    },
    UserRole.SOC_MANAGER: {
        "read:all",
        "read:dashboard",
        "read:alerts",
        "write:alerts",
        "read:incidents",
        "write:incidents",
        "write:soar",
        "write:rules",
        "manage:agents",
        "read:reports",
        "write:reports",
        "read:audit",
        "read:telemetry",
    },
    UserRole.ADMIN: {
        "*",  # All permissions
    },
}


class UserContext(BaseModel):
    user_id: str
    email: str
    role: UserRole
    tenant_id: str = "default"
    is_agent: bool = False

    def has_permission(self, permission: str) -> bool:
        if self.role == UserRole.ADMIN:
            return True
        perms = ROLE_PERMISSIONS.get(self.role, set())
        return "*" in perms or permission in perms or "read:all" in perms and permission.startswith("read:")


def get_current_user(
    authorization: Annotated[str | None, Header(description="Bearer <JWT>")] = None,
    x_user_id: Annotated[str | None, Header()] = None,
    x_user_role: Annotated[str | None, Header()] = None,
    x_tenant_id: Annotated[str | None, Header()] = None,
) -> UserContext:
    """
    Extracts authenticated user identity from cryptographically signed JWT Bearer token.
    In production or strict auth mode, strictly requires Bearer token authentication.
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
                is_agent=False,
            )
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid or expired authentication token: {e}",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # In production or strict auth mode, unauthenticated header fallback is forbidden
    is_production = getattr(settings, "ENVIRONMENT", "development") == "production"
    is_strict = getattr(settings, "AUTH_STRICT_MODE", False) or getattr(settings, "AUTH_STRICT_JWT", False)
    if is_production or is_strict:
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
        is_agent=False,
    )


def get_authenticated_agent_or_user(
    authorization: Annotated[str | None, Header()] = None,
    x_agent_key: Annotated[str | None, Header()] = None,
    x_user_id: Annotated[str | None, Header()] = None,
    x_user_role: Annotated[str | None, Header()] = None,
    x_tenant_id: Annotated[str | None, Header()] = None,
    db: Session = Depends(get_db),
) -> UserContext:
    """
    Authenticates either a machine collector agent (via X-Agent-Key or Bearer lgs_agt_...)
    or a human analyst (via JWT Bearer token).
    Agent principals are strictly scoped to their enrolled tenant and ingestion capabilities.
    """
    raw_key: str | None = None
    if x_agent_key and x_agent_key.startswith("lgs_agt_"):
        raw_key = x_agent_key.strip()
    elif authorization and authorization.lower().startswith("bearer lgs_agt_"):
        raw_key = authorization[7:].strip()

    if raw_key:
        from app.services.identity_service import IdentityService

        agent = IdentityService.verify_agent_api_key(db, raw_key)
        if not agent:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or revoked agent API key",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return UserContext(
            user_id=str(agent.id),
            email=f"{agent.name}@agents.logsentry.internal",
            role=UserRole.TIER_1_ANALYST,
            tenant_id=str(agent.tenant_id),
            is_agent=True,
        )

    # If not an agent key, process via standard user authentication
    return get_current_user(
        authorization=authorization,
        x_user_id=x_user_id,
        x_user_role=x_user_role,
        x_tenant_id=x_tenant_id,
    )


def require_role(*allowed_roles: UserRole):
    """Dependency that enforces RBAC authorization for endpoints."""

    def role_checker(user: UserContext = Depends(get_current_user)) -> UserContext:
        if user.is_agent:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Agent identities are restricted to ingestion and cannot access user operations.",
            )

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


def require_permission(permission: str):
    """Dependency that enforces fine-grained permission authorization."""

    def permission_checker(user: UserContext = Depends(get_current_user)) -> UserContext:
        if not user.has_permission(permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Missing required permission '{permission}'.",
            )
        return user

    return permission_checker
