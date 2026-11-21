from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.core.rbac import UserContext, UserRole, require_role
from app.schemas.detection_alert import DetectionAlert
from app.schemas.severity import Severity
from app.services.soar_service import SOARService

router = APIRouter()


class QuarantineRequest(BaseModel):
    ip: str = Field(..., description="Target IPv4/IPv6 address to block")
    reason: str = Field(
        "Manual SOC Analyst Quarantine", description="Justification for containment"
    )
    duration_seconds: int = Field(3600, description="Duration of block in seconds")
    severity: str = Field("HIGH", description="Associated threat severity")
    analyst: str = Field("analyst@logsentry.local", description="Analyst identity")
    containment_type: str = Field("IN_MEMORY", description="Containment backend")


class ReleaseRequest(BaseModel):
    analyst: str = Field(
        "analyst@logsentry.local", description="Analyst who authorized release"
    )
    reason: str = Field(
        "Containment completed or False Positive", description="Release justification"
    )


class WebhookTestRequest(BaseModel):
    webhook_url: str = Field(
        ..., description="Target webhook URL (Slack, Teams, or HTTP endpoint)"
    )


class CloudflareBlockRequest(BaseModel):
    ip: str
    zone_id: str | None = None
    api_token: str | None = None


class IPTablesBlockRequest(BaseModel):
    ip: str
    dry_run: bool = True


@router.get("/quarantine", response_model=list[dict[str, Any]])
def list_quarantined_hosts(
    user: UserContext = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SOC_MANAGER,
            UserRole.TIER_2_ANALYST,
            UserRole.TIER_1_ANALYST,
        )
    ),
):
    """List all currently active quarantined / blocked host IPs scoped to tenant."""
    effective_tenant = None if user.role == UserRole.ADMIN else user.tenant_id
    return SOARService.get_quarantined_ips(tenant_id=effective_tenant)


@router.post("/quarantine", response_model=dict[str, Any])
def quarantine_host(
    req: QuarantineRequest,
    user: UserContext = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SOC_MANAGER,
            UserRole.TIER_2_ANALYST,
        )
    ),
):
    """Manually quarantine an IP address across active defense controls."""
    # Derive analyst identity directly from authenticated user identity
    effective_analyst = user.email or user.user_id

    try:
        return SOARService.quarantine_ip(
            ip=req.ip,
            reason=req.reason,
            duration_seconds=req.duration_seconds,
            severity=req.severity,
            analyst=effective_analyst,
            containment_type=req.containment_type,
            tenant_id=user.tenant_id,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/quarantine/{ip}")
def release_host(
    ip: str,
    req: ReleaseRequest | None = None,
    user: UserContext = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SOC_MANAGER,
            UserRole.TIER_2_ANALYST,
        )
    ),
):
    """Release an IP address from active quarantine within the caller's tenant boundary."""
    effective_analyst = user.email or user.user_id
    success = SOARService.release_ip(
        ip=ip, analyst=effective_analyst, tenant_id=user.tenant_id
    )
    if not success:
        raise HTTPException(
            status_code=404, detail=f"IP '{ip}' is not actively quarantined for tenant '{user.tenant_id}'."
        )
    return {
        "status": "success",
        "message": f"IP {ip} released from quarantine.",
        "ip": ip,
        "tenant_id": user.tenant_id,
    }


@router.get("/history", response_model=list[dict[str, Any]])
def get_containment_history(
    limit: int = Query(50, ge=1, le=500),
    user: UserContext = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SOC_MANAGER,
            UserRole.TIER_2_ANALYST,
            UserRole.TIER_1_ANALYST,
        )
    ),
):
    """Retrieve audit history of all SOAR containment and response actions scoped to tenant."""
    effective_tenant = None if user.role == UserRole.ADMIN else user.tenant_id
    return SOARService.get_action_history(limit=limit, tenant_id=effective_tenant)


@router.post("/firewall/cloudflare")
async def block_ip_cloudflare(
    req: CloudflareBlockRequest,
    user: UserContext = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SOC_MANAGER,
        )
    ),
):
    """Trigger Cloudflare WAF IP Access Rule block."""
    return await SOARService.execute_cloudflare_waf_block(
        ip=req.ip, zone_id=req.zone_id, api_token=req.api_token
    )


@router.post("/firewall/iptables")
def block_ip_iptables(
    req: IPTablesBlockRequest,
    user: UserContext = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SOC_MANAGER,
        )
    ),
):
    """Trigger Linux iptables containment rule generation/execution."""
    return SOARService.execute_linux_iptables_block(ip=req.ip, dry_run=req.dry_run)


@router.post("/webhook/test")
async def test_webhook(
    req: WebhookTestRequest,
    user: UserContext = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SOC_MANAGER,
        )
    ),
):
    """Test webhook delivery by dispatching a sample rich interactive SIEM incident card."""
    sample_alert = DetectionAlert(
        rule_name="soar_test",
        rule_version="1.0.0",
        severity=Severity.HIGH,
        confidence=0.95,
        risk_score=85.0,
        title="[TEST] LogSentry Active Defense Webhook Verification",
        description="Verification event from LogSentry SIEM SOAR engine.",
        source_ip="203.0.113.199",
        endpoint="/api/v1/auth/login",
        attack_type="Active Defense Verification",
        mitre_technique="T1078",
        mitre_tactic="Initial Access",
        recommendation="Verify webhook connectivity and permissions.",
        evidence={"test": True},
        raw_log_reference="Test log event",
    )
    try:
        success = await SOARService.dispatch_webhook_alert(
            sample_alert, webhook_url=req.webhook_url
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=400,
            detail=f"Webhook URL validation failed (SSRF Protection): {ve}",
        )
    if not success:
        raise HTTPException(
            status_code=502,
            detail="Failed to deliver webhook. Check destination URL and network.",
        )
    return {"status": "success", "message": "Test webhook dispatched successfully."}
