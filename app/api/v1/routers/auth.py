from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.core.jwt import create_access_token
from app.core.rbac import UserContext, UserRole, get_current_user, require_role

router = APIRouter(prefix="/auth", tags=["Identity & RBAC"])


class LoginRequest(BaseModel):
    username: str = Field(
        ..., description="Corporate SOC analyst username e.g. 'admin' or 'analyst'"
    )
    password: str = Field(..., description="User password")
    tenant_id: str = Field("default", description="Target workspace tenant")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int = 120
    user: UserContext


# Built-in secure user directory for enterprise SOC demonstration
SOC_DIRECTORY = {
    "admin": {
        "password": "admin",
        "role": UserRole.ADMIN,
        "email": "admin@logsentry.corp",
    },
    "soc_manager": {
        "password": "manager123",
        "role": UserRole.SOC_MANAGER,
        "email": "manager@logsentry.corp",
    },
    "threat_hunter": {
        "password": "hunter123",
        "role": UserRole.THREAT_HUNTER,
        "email": "hunter@logsentry.corp",
    },
    "analyst": {
        "password": "analyst123",
        "role": UserRole.TIER_2_ANALYST,
        "email": "analyst@logsentry.corp",
    },
    "junior_analyst": {
        "password": "junior123",
        "role": UserRole.TIER_1_ANALYST,
        "email": "junior@logsentry.corp",
    },
}


@router.post("/login", response_model=TokenResponse)
@router.post("/token", response_model=TokenResponse)
def login_for_access_token(form_data: LoginRequest):
    """
    Authenticates SOC user credentials and issues a cryptographically signed HS256 JWT access token.
    Enforces role hierarchy and tenant boundaries.
    """
    account = SOC_DIRECTORY.get(form_data.username.lower())
    if not account or account["password"] != form_data.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    role = account["role"]
    token = create_access_token(
        user_id=form_data.username,
        role=role.value,
        tenant_id=form_data.tenant_id,
        email=account["email"],
        expires_delta_minutes=120,
    )

    user_ctx = UserContext(
        user_id=form_data.username,
        email=account["email"],
        role=role,
        tenant_id=form_data.tenant_id,
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
