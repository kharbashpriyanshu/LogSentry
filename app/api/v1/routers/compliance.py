from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.alert import AlertModel
from app.services.compliance_service import ComplianceAuditService, ComplianceReport
from app.services.soar_service import SOARService

router = APIRouter(prefix="/compliance", tags=["Compliance & Audits"])


@router.get("/pci-dss", response_model=ComplianceReport)
def get_pci_dss_audit(tenant_id: str = "default", db: Session = Depends(get_db)):
    """Generate on-demand PCI-DSS v4.0 Requirement 10 audit report."""
    alerts_count = db.query(AlertModel).count()
    quarantined = len(SOARService.get_quarantined_ips())
    return ComplianceAuditService.evaluate_pci_dss(
        alerts_count=alerts_count, quarantined_count=quarantined, tenant_id=tenant_id
    )


@router.get("/hipaa", response_model=ComplianceReport)
def get_hipaa_audit(tenant_id: str = "default", db: Session = Depends(get_db)):
    """Generate on-demand HIPAA Security Rule § 164.312(b) audit report."""
    alerts_count = db.query(AlertModel).count()
    return ComplianceAuditService.evaluate_hipaa(
        alerts_count=alerts_count, tenant_id=tenant_id
    )


@router.get("/soc2", response_model=ComplianceReport)
def get_soc2_audit(tenant_id: str = "default", db: Session = Depends(get_db)):
    """Generate on-demand SOC 2 Type II Security & Incident Response report."""
    alerts_count = db.query(AlertModel).count()
    return ComplianceAuditService.evaluate_soc2(
        alerts_count=alerts_count, tenant_id=tenant_id
    )
