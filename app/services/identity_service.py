"""LogSentry Identity, Tenant & Agent Credential Management Service.

Handles:
  - Initial system administrator bootstrapping
  - Argon2id password hashing and constant-time verification
  - User-to-tenant membership validation (strict multi-tenancy)
  - Machine-to-machine Agent credential enrollment and SHA-256 API key hashing
  - Timing-attack enumeration mitigation
"""

import hashlib
import logging
import secrets
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.config.settings import settings
from app.core.password import hash_password, verify_password
from app.core.rbac import UserRole
from app.models.agent_credential import AgentCredentialModel
from app.models.tenant import TenantModel, UserTenantMembershipModel
from app.models.user import UserModel

logger = logging.getLogger(__name__)

# Precomputed dummy Argon2id hash for constant-time dummy verification when user is not found
_DUMMY_ARGON2_HASH = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXJhbmRvbXNhbHQx$6tB2p9+sOaR7v8o7J4I7gH+q6fT1d4y9s7E6w5Z0aBc"


class IdentityService:
    """Service encapsulating user, tenant, and agent identity lifecycle."""

    @staticmethod
    def bootstrap_default_tenants_and_admin(db: Session) -> None:
        """
        Idempotently provisions the default tenant and initial administrator account.
        In development mode, also ensures demonstration analysts are provisioned.
        """
        # 1. Ensure default tenant exists
        default_tenant = (
            db.query(TenantModel).filter(TenantModel.id == "default").first()
        )
        if not default_tenant:
            default_tenant = TenantModel(
                id="default",
                name="Default SOC Operations",
                description="Primary Enterprise SOC Security Domain",
                is_active=True,
            )
            db.add(default_tenant)
            db.commit()
            db.refresh(default_tenant)
            logger.info("Initialized default enterprise tenant: 'default'")

        # Secondary tenant for multi-tenant isolation testing
        lab_tenant = (
            db.query(TenantModel).filter(TenantModel.id == "lab-sec-ops").first()
        )
        if not lab_tenant:
            lab_tenant = TenantModel(
                id="lab-sec-ops",
                name="Lab Security Operations",
                description="Secondary Isolated Testing Tenant",
                is_active=True,
            )
            db.add(lab_tenant)
            db.commit()

        # Development tenant for test suites
        if settings.ENVIRONMENT != "production":
            custom_tenant = (
                db.query(TenantModel)
                .filter(TenantModel.id == "custom-enterprise-tenant")
                .first()
            )
            if not custom_tenant:
                custom_tenant = TenantModel(
                    id="custom-enterprise-tenant",
                    name="Custom Enterprise Tenant",
                    description="Test Tenant",
                    is_active=True,
                )
                db.add(custom_tenant)
                db.commit()

            unauth_tenant = (
                db.query(TenantModel)
                .filter(TenantModel.id == "unauthorized-corp-bank")
                .first()
            )
            if not unauth_tenant:
                unauth_tenant = TenantModel(
                    id="unauthorized-corp-bank",
                    name="Unauthorized Corp Bank",
                    description="Test Tenant for Access Control",
                    is_active=True,
                )
                db.add(unauth_tenant)
                db.commit()

        # 2. Check if admin exists
        admin_username = settings.INITIAL_ADMIN_USERNAME.lower()
        admin_user = (
            db.query(UserModel).filter(UserModel.username == admin_username).first()
        )
        if not admin_user:
            admin_user = UserModel(
                username=admin_username,
                email="admin@logsentry.corp",
                hashed_password=hash_password(settings.INITIAL_ADMIN_PASSWORD),
                role=UserRole.ADMIN.value,
                is_active=True,
            )
            db.add(admin_user)
            db.commit()
            db.refresh(admin_user)

            # Assign membership to default and lab tenants
            db.add(
                UserTenantMembershipModel(
                    user_id=admin_user.id,
                    tenant_id="default",
                    role=UserRole.ADMIN.value,
                )
            )
            db.add(
                UserTenantMembershipModel(
                    user_id=admin_user.id,
                    tenant_id="lab-sec-ops",
                    role=UserRole.ADMIN.value,
                )
            )
            db.commit()
            logger.info(
                f"Bootstrapped initial enterprise admin user '{admin_username}' with tenant memberships."
            )
        elif settings.ENVIRONMENT != "production":
            # In development, synchronize admin password with configured INITIAL_ADMIN_PASSWORD
            admin_user.hashed_password = hash_password(settings.INITIAL_ADMIN_PASSWORD)
            db.commit()

        # In development/test mode, seed standard role accounts if missing
        if settings.ENVIRONMENT != "production":
            dev_accounts = [
                (
                    "soc_manager",
                    "manager123",
                    "manager@logsentry.corp",
                    UserRole.SOC_MANAGER.value,
                    ["default", "lab-sec-ops"],
                ),
                (
                    "threat_hunter",
                    "hunter123",
                    "hunter@logsentry.corp",
                    UserRole.THREAT_HUNTER.value,
                    ["default"],
                ),
                (
                    "analyst",
                    "analyst123",
                    "analyst@logsentry.corp",
                    UserRole.TIER_2_ANALYST.value,
                    ["default"],
                ),
                (
                    "junior_analyst",
                    "junior123",
                    "junior@logsentry.corp",
                    UserRole.TIER_1_ANALYST.value,
                    ["default"],
                ),
            ]
            for uname, pwd, email, role, tenants in dev_accounts:
                existing = (
                    db.query(UserModel).filter(UserModel.username == uname).first()
                )
                if not existing:
                    user_obj = UserModel(
                        username=uname,
                        email=email,
                        hashed_password=hash_password(pwd),
                        role=role,
                        is_active=True,
                    )
                    db.add(user_obj)
                    db.commit()
                    db.refresh(user_obj)
                    for t_id in tenants:
                        db.add(
                            UserTenantMembershipModel(
                                user_id=user_obj.id, tenant_id=t_id, role=role
                            )
                        )
                    db.commit()

    @staticmethod
    def authenticate_user(
        db: Session,
        username: str,
        password: str,
        requested_tenant_id: str = "default",
    ) -> tuple[UserModel, str]:
        """
        Authenticates user with Argon2id password verification and strict tenant checking.

        Defenses:
          - Timing attack mitigation: executes dummy verify if user does not exist.
          - Multi-tenant boundary check: non-admins cannot authenticate into unassigned tenants.
          - Account status check: rejects inactive accounts.
        """
        user = (
            db.query(UserModel)
            .filter(UserModel.username == username.strip().lower())
            .first()
        )
        if not user:
            # Perform dummy verification to neutralize user enumeration timing side-channels
            verify_password(password, _DUMMY_ARGON2_HASH)
            raise ValueError("Incorrect username or password")

        if not verify_password(password, user.hashed_password):
            raise ValueError("Incorrect username or password")

        if not user.is_active:
            raise PermissionError("User account is inactive or disabled")

        # Tenant authorization — target tenant must exist and be active
        tenant = (
            db.query(TenantModel).filter(TenantModel.id == requested_tenant_id).first()
        )
        if not tenant:
            if requested_tenant_id == "default":
                tenant = TenantModel(
                    id="default", name="Default SOC Operations", is_active=True
                )
                db.add(tenant)
                db.commit()
            else:
                raise ValueError(
                    f"Requested tenant '{requested_tenant_id}' does not exist"
                )

        if not tenant.is_active:
            raise PermissionError(
                f"Tenant '{requested_tenant_id}' is disabled or deactivated"
            )

        is_admin = user.role in (UserRole.ADMIN.value, UserRole.ADMIN)
        if is_admin:
            # Admins have universal authority over all existing tenants
            return user, requested_tenant_id

        # Non-admins must have explicit membership in the requested tenant
        membership = (
            db.query(UserTenantMembershipModel)
            .filter(
                UserTenantMembershipModel.user_id == user.id,
                UserTenantMembershipModel.tenant_id == requested_tenant_id,
            )
            .first()
        )
        if not membership:
            raise PermissionError(
                f"User '{user.username}' is not authorized to access tenant '{requested_tenant_id}'"
            )

        return user, requested_tenant_id

    @staticmethod
    def enroll_agent(
        db: Session,
        name: str,
        tenant_id: str = "default",
    ) -> dict[str, str]:
        """
        Enrolls a new collector/shipper agent for Machine-to-Machine authentication.
        Generates a high-entropy API key prefixed with 'lgs_agt_'.
        Stores the SHA-256 hash in the database and returns the raw key once.
        """
        # Ensure tenant exists
        tenant = db.query(TenantModel).filter(TenantModel.id == tenant_id).first()
        if not tenant:
            raise ValueError(f"Tenant '{tenant_id}' does not exist")

        raw_secret = secrets.token_urlsafe(32)
        raw_api_key = f"lgs_agt_{raw_secret}"
        api_key_hash = hashlib.sha256(raw_api_key.encode("utf-8")).hexdigest()
        api_key_prefix = raw_api_key[:16]

        agent = AgentCredentialModel(
            name=name.strip(),
            api_key_hash=api_key_hash,
            api_key_prefix=api_key_prefix,
            tenant_id=tenant_id,
            is_active=True,
        )
        db.add(agent)
        db.commit()
        db.refresh(agent)

        logger.info(
            f"Enrolled collector agent '{name}' for tenant '{tenant_id}' with prefix '{api_key_prefix}'"
        )
        return {
            "agent_id": str(agent.id),
            "name": agent.name,
            "tenant_id": agent.tenant_id,
            "api_key": raw_api_key,
            "api_key_prefix": agent.api_key_prefix,
            "created_at": agent.created_at.isoformat(),
        }

    @staticmethod
    def verify_agent_api_key(
        db: Session,
        raw_api_key: str,
    ) -> AgentCredentialModel | None:
        """
        Verifies an agent API key against database hashes.
        Updates last_used_at on successful verification.
        """
        if not raw_api_key or not raw_api_key.startswith("lgs_agt_"):
            return None

        key_hash = hashlib.sha256(raw_api_key.encode("utf-8")).hexdigest()
        agent = (
            db.query(AgentCredentialModel)
            .filter(
                AgentCredentialModel.api_key_hash == key_hash,
                AgentCredentialModel.is_active == True,  # noqa: E712
            )
            .first()
        )
        if agent:
            try:
                agent.last_used_at = datetime.now(UTC)
                db.commit()
            except Exception:
                db.rollback()
            return agent
        return None
