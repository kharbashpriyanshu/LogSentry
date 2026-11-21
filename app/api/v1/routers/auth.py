from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config.settings import settings
from app.core.jwt import create_access_token
from app.core.rbac import UserContext, UserRole, get_current_user, require_role
from app.database.session import get_db
from app.models.agent_credential import AgentCredentialModel
from app.models.tenant import TenantModel, UserTenantMembershipModel
from app.models.user import UserModel
from app.services.identity_service import IdentityService

router = APIRouter(prefix="/auth", tags=["Identity & RBAC"])


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


class AgentEnrollRequest(BaseModel):
    name: str = Field(..., description="Collector or shipper agent name e.g. 'bastion-shipper-01'")
    tenant_id: str = Field("default", description="Tenant to bind this collector agent to")


class AgentEnrollResponse(BaseModel):
    agent_id: str
    name: str
    tenant_id: str
    api_key: str
    api_key_prefix: str
    created_at: str


class AgentSummaryResponse(BaseModel):
    id: str
    name: str
    tenant_id: str
    api_key_prefix: str
    is_active: bool
    last_used_at: datetime | None = None
    created_at: datetime


class CreateTenantRequest(BaseModel):
    id: str = Field(..., description="Unique alphanumeric tenant slug/ID e.g. 'corp-sec-ops'")
    name: str = Field(..., description="Enterprise workspace or client name")
    description: str | None = Field(None, description="Optional tenant description")


class TenantResponse(BaseModel):
    id: str
    name: str
    description: str | None = None
    is_active: bool


@router.post("/login", response_model=TokenResponse)
@router.post("/token", response_model=TokenResponse)
def login_for_access_token(
    form_data: LoginRequest,
    db: Session = Depends(get_db),
):
    """
    Authenticates SOC user credentials against database with Argon2id password verification
    and issues a cryptographically signed HS256 JWT access token. Enforces strict role
    hierarchy and tenant boundaries.
    """
    # Ensure bootstrap default accounts exist
    IdentityService.bootstrap_default_tenants_and_admin(db)

    try:
        user_record, bound_tenant_id = IdentityService.authenticate_user(
            db=db,
            username=form_data.username,
            password=form_data.password,
            requested_tenant_id=form_data.tenant_id or "default",
        )
    except PermissionError as pe:
        # Account disabled or tenant membership violation
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(pe),
        )
    except ValueError as ve:
        # Invalid credentials or missing tenant
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(ve),
            headers={"WWW-Authenticate": "Bearer"},
        )

    role_str = user_record.role
    try:
        user_role = UserRole(role_str)
    except ValueError:
        user_role = UserRole.TIER_1_ANALYST

    token_lifetime_minutes = getattr(settings, "AUTH_TOKEN_EXPIRE_MINUTES", 120)

    token = create_access_token(
        user_id=str(user_record.id),
        role=user_role.value,
        tenant_id=bound_tenant_id,
        email=user_record.email,
        expires_delta_minutes=token_lifetime_minutes,
        extra_claims={"username": user_record.username},
    )

    user_ctx = UserContext(
        user_id=str(user_record.id),
        username=user_record.username,
        email=user_record.email,
        role=user_role,
        tenant_id=bound_tenant_id,
        is_agent=False,
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",  # noqa: S106
        expires_in_minutes=token_lifetime_minutes,
        user=user_ctx,
    )


@router.get("/me", response_model=UserContext)
def get_my_identity(user: UserContext = Depends(get_current_user)):
    """Retrieve current authenticated analyst identity, role, and tenant."""
    return user


@router.get("/tenants", response_model=List[TenantResponse])
def get_user_tenants(
    user: UserContext = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List tenants accessible by the authenticated user."""
    if user.role == UserRole.ADMIN:
        tenants = db.query(TenantModel).filter(TenantModel.is_active == True).all()  # noqa: E712
    else:
        # Check by user ID UUID or joined username to ensure exact match
        memberships = (
            db.query(UserTenantMembershipModel)
            .join(TenantModel, TenantModel.id == UserTenantMembershipModel.tenant_id)
            .join(UserModel, UserModel.id == UserTenantMembershipModel.user_id)
            .filter(
                (UserTenantMembershipModel.user_id == user.user_id)
                | (UserModel.username == user.username),
                TenantModel.is_active == True,  # noqa: E712
            )
            .all()
        )
        tenant_ids = [m.tenant_id for m in memberships]
        if not tenant_ids and user.tenant_id:
            tenant_ids = [user.tenant_id]
        tenants = db.query(TenantModel).filter(TenantModel.id.in_(tenant_ids)).all()

    return [
        TenantResponse(
            id=t.id,
            name=t.name,
            description=t.description,
            is_active=t.is_active,
        )
        for t in tenants
    ]


@router.post("/tenants", response_model=TenantResponse, status_code=201)
def create_tenant(
    payload: CreateTenantRequest,
    user: UserContext = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
):
    """Explicitly provision a new enterprise tenant. Restricted to Admin role."""
    clean_id = payload.id.strip()
    existing = db.query(TenantModel).filter(TenantModel.id == clean_id).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Tenant '{clean_id}' already exists.",
        )
    tenant = TenantModel(
        id=clean_id,
        name=payload.name.strip(),
        description=payload.description,
        is_active=True,
    )
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return TenantResponse(
        id=tenant.id,
        name=tenant.name,
        description=tenant.description,
        is_active=tenant.is_active,
    )


@router.post("/agents/enroll", response_model=AgentEnrollResponse)
def enroll_collector_agent(
    payload: AgentEnrollRequest,
    user: UserContext = Depends(require_role(UserRole.ADMIN, UserRole.SOC_MANAGER)),
    db: Session = Depends(get_db),
):
    """
    Enroll a new machine collector agent (shipper, endpoint sensor) and generate
    a scoped agent API key. Enforces manager-to-tenant boundary.
    """
    # Cross-tenant enrollment prevention: SOC Managers cannot enroll agents for other tenants
    target_tenant = user.tenant_id
    if user.role == UserRole.ADMIN:
        target_tenant = payload.tenant_id or user.tenant_id
    elif payload.tenant_id and payload.tenant_id != user.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"SOC Managers can only enroll agents for their own tenant '{user.tenant_id}'. Cross-tenant enrollment is forbidden.",
        )

    try:
        agent_data = IdentityService.enroll_agent(
            db=db,
            name=payload.name,
            tenant_id=target_tenant,
        )
        return AgentEnrollResponse(**agent_data)
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )


@router.get("/agents", response_model=List[AgentSummaryResponse])
def list_enrolled_agents(
    user: UserContext = Depends(require_role(UserRole.ADMIN, UserRole.SOC_MANAGER)),
    db: Session = Depends(get_db),
):
    """List enrolled collector agents for the caller's tenant."""
    query = db.query(AgentCredentialModel)
    if user.role != UserRole.ADMIN:
        query = query.filter(AgentCredentialModel.tenant_id == user.tenant_id)
    agents = query.order_by(AgentCredentialModel.created_at.desc()).all()

    return [
        AgentSummaryResponse(
            id=str(a.id),
            name=a.name,
            tenant_id=a.tenant_id,
            api_key_prefix=a.api_key_prefix,
            is_active=a.is_active,
            last_used_at=a.last_used_at,
            created_at=a.created_at,
        )
        for a in agents
    ]


@router.delete("/agents/{agent_id}")
def revoke_agent(
    agent_id: str,
    user: UserContext = Depends(require_role(UserRole.ADMIN, UserRole.SOC_MANAGER)),
    db: Session = Depends(get_db),
):
    """Revoke an agent's credentials immediately."""
    agent = db.query(AgentCredentialModel).filter(AgentCredentialModel.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

    if user.role != UserRole.ADMIN and agent.tenant_id != user.tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot revoke agent belonging to another tenant")

    agent.is_active = False
    db.commit()
    return {"status": "success", "message": f"Agent '{agent.name}' revoked successfully."}


@router.get("/admin-only")
def admin_only_check(
    user: UserContext = Depends(require_role(UserRole.ADMIN, UserRole.SOC_MANAGER)),
):
    """Admin and SOC Manager protected endpoint."""
    return {
        "status": "authorized",
        "message": f"Welcome, {user.email}. Privileged access granted.",
    }
