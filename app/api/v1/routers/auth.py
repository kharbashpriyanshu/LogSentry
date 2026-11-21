import hashlib
import hmac
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.core.jwt import create_access_token
from app.core.rbac import UserContext, UserRole, get_current_user, require_role

router = APIRouter(prefix="/auth", tags=["Identity & RBAC"])


def _hash_password(password: str, salt: str = "logsentry_soc_salt_2026") -> str:
    """Cryptographic PBKDF2-HMAC-SHA256 password hash."""
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000
    ).hex()


class LoginRequest(BaseModel):
    username: str = Field(
        ..., description="Corporate SOC analyst username e.g. 'admin' or 'analyst'"
    )
    password: str = Field(..., description="User password")
    tenant_id: str = Field("default", description="Target workspace tenant")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S106
    expires_in_minutes: int = 120
    user: UserContext


# Built-in salted PBKDF2 user directory with assigned tenant boundaries
_DEMO_SALT = "logsentry_soc_salt_2026"
SOC_DIRECTORY: dict[str, dict[str, Any]] = {
    "admin": {
        "password_hash": _hash_password("admin", _DEMO_SALT),
        "role": UserRole.ADMIN,
        "email": "admin@logsentry.corp",
        "allowed_tenants": ["*"],  # Admin can access any tenant
        "default_tenant": "default",
    },
    "soc_manager": {
        "password_hash": _hash_password("manager123", _DEMO_SALT),
        "role": UserRole.SOC_MANAGER,
        "email": "manager@logsentry.corp",
        "allowed_tenants": ["default", "corp-sec-ops"],
        "default_tenant": "default",
    },
    "threat_hunter": {
        "password_hash": _hash_password("hunter123", _DEMO_SALT),
        "role": UserRole.THREAT_HUNTER,
        "email": "hunter@logsentry.corp",
        "allowed_tenants": ["default", "threat-hunting-lab"],
        "default_tenant": "default",
    },
    "analyst": {
        "password_hash": _hash_password("analyst123", _DEMO_SALT),
        "role": UserRole.TIER_2_ANALYST,
        "email": "analyst@logsentry.corp",
        "allowed_tenants": ["default"],
        "default_tenant": "default",
    },
    "junior_analyst": {
        "password_hash": _hash_password("junior123", _DEMO_SALT),
        "role": UserRole.TIER_1_ANALYST,
        "email": "junior@logsentry.corp",
        "allowed_tenants": ["default"],
        "default_tenant": "default",
    },
}


@router.post("/login", response_model=TokenResponse)
@router.post("/token", response_model=TokenResponse)
def login_for_access_token(form_data: LoginRequest):
    """
    Authenticates SOC user credentials with PBKDF2-HMAC-SHA256 and issues a cryptographically
    signed HS256 JWT access token. Enforces strict role hierarchy and tenant boundaries.
    """
    account = SOC_DIRECTORY.get(form_data.username.lower())
    if not account:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    computed_hash = _hash_password(form_data.password, _DEMO_SALT)
    if not hmac.compare_digest(account["password_hash"], computed_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Validate tenant membership: non-admins cannot log in to unassigned tenants
    allowed = account.get("allowed_tenants", ["default"])
    target_tenant = form_data.tenant_id or account.get("default_tenant", "default")
    if "*" not in allowed and target_tenant not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"User '{form_data.username}' is not authorized to access tenant '{target_tenant}'.",
        )

    role = account["role"]
    token = create_access_token(
        user_id=form_data.username,
        role=role.value,
        tenant_id=target_tenant,
        email=account["email"],
        expires_delta_minutes=120,
    )

    user_ctx = UserContext(
        user_id=form_data.username,
        email=account["email"],
        role=role,
        tenant_id=target_tenant,
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",  # noqa: S106
        expires_in_minutes=120,
        user=user_ctx,
    )


@router.get("/me", response_model=UserContext)
def get_my_identity(user: UserContext = Depends(get_current_user)):
    """Retrieve current authenticated analyst identity, role, and tenant."""
    return user


@router.get("/admin-only")
def admin_only_check(
    user: UserContext = Depends(require_role(UserRole.ADMIN, UserRole.SOC_MANAGER)),
):
    """Admin and SOC Manager protected endpoint."""
    return {
        "status": "authorized",
        "message": f"Welcome, {user.email}. Privileged access granted.",
    }
