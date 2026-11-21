from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.rbac import UserContext, UserRole, get_current_user
from app.database.session import get_db
from app.models.alert import AlertModel
from app.services.compliance_service import ComplianceAuditService, ComplianceReport
from app.services.soar_service import SOARService

router = APIRouter(prefix="/compliance", tags=["Compliance & Audits"])


@router.get("/pci-dss", response_model=ComplianceReport)
def get_pci_dss_audit(
    tenant_id: str | None = None,
    user: UserContext = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generate on-demand PCI-DSS v4.0 Requirement 10 audit report."""
    effective_tenant = (
        tenant_id if user.role == UserRole.ADMIN and tenant_id else user.tenant_id
    )
    alerts_count = (
        db.query(AlertModel)
        .filter(
            (AlertModel.tenant_id == effective_tenant)
            | (AlertModel.tenant_id == "default")
        )
        .count()
    )
    quarantined = len(SOARService.get_quarantined_ips())
    return ComplianceAuditService.evaluate_pci_dss(
        alerts_count=alerts_count,
        quarantined_count=quarantined,
        tenant_id=effective_tenant,
    )


@router.get("/hipaa", response_model=ComplianceReport)
def get_hipaa_audit(
    tenant_id: str | None = None,
    user: UserContext = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generate on-demand HIPAA Security Rule § 164.312(b) audit report."""
    effective_tenant = (
        tenant_id if user.role == UserRole.ADMIN and tenant_id else user.tenant_id
    )
    alerts_count = (
        db.query(AlertModel)
        .filter(
            (AlertModel.tenant_id == effective_tenant)
            | (AlertModel.tenant_id == "default")
        )
        .count()
    )
    return ComplianceAuditService.evaluate_hipaa(
        alerts_count=alerts_count, tenant_id=effective_tenant
    )


@router.get("/soc2", response_model=ComplianceReport)
def get_soc2_audit(
    tenant_id: str | None = None,
    user: UserContext = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generate on-demand SOC 2 Type II Security & Incident Response report."""
    effective_tenant = (
        tenant_id if user.role == UserRole.ADMIN and tenant_id else user.tenant_id
    )
    alerts_count = (
        db.query(AlertModel)
        .filter(
            (AlertModel.tenant_id == effective_tenant)
            | (AlertModel.tenant_id == "default")
        )
        .count()
    )
    return ComplianceAuditService.evaluate_soc2(
        alerts_count=alerts_count, tenant_id=effective_tenant
    )
