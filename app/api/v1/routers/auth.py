from fastapi import APIRouter, Depends

from app.core.rbac import UserContext, UserRole, get_current_user, require_role

router = APIRouter(prefix="/auth", tags=["Identity & RBAC"])


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
