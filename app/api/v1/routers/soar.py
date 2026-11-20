from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from app.services.soar_service import SOARService
from app.schemas.detection_alert import DetectionAlert
from app.schemas.severity import Severity

router = APIRouter()

class QuarantineRequest(BaseModel):
    ip: str = Field(..., description="Target IPv4/IPv6 address to block")
    reason: str = Field("Manual SOC Analyst Quarantine", description="Justification for containment")
    duration_seconds: int = Field(3600, description="Duration of block in seconds")
    severity: str = Field("HIGH", description="Associated threat severity")
    analyst: str = Field("analyst@logsentry.local", description="Analyst identity")

class ReleaseRequest(BaseModel):
    analyst: str = Field("analyst@logsentry.local", description="Analyst who authorized release")
    reason: str = Field("Containment completed or False Positive", description="Release justification")

class WebhookTestRequest(BaseModel):
    webhook_url: str = Field(..., description="Target webhook URL (Slack, Teams, or HTTP endpoint)")

@router.get("/quarantine", response_model=List[Dict[str, Any]])
def list_quarantined_hosts():
    """List all currently active quarantined / blocked host IPs."""
    return SOARService.get_active_quarantines()

@router.post("/quarantine", response_model=Dict[str, Any])
def quarantine_host(req: QuarantineRequest):
    """Manually quarantine an IP address across active defense controls."""
    try:
        return SOARService.quarantine_ip(
            ip=req.ip,
            reason=req.reason,
            duration_seconds=req.duration_seconds,
            severity=req.severity,
            analyst=req.analyst
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.delete("/quarantine/{ip}")
def release_host(ip: str, req: Optional[ReleaseRequest] = None):
    """Release an IP address from active quarantine."""
    analyst = req.analyst if req else "admin"
    reason = req.reason if req else "Manual SOC Release"
    success = SOARService.release_ip(ip=ip, analyst=analyst, reason=reason)
    if not success:
        raise HTTPException(status_code=404, detail=f"IP '{ip}' is not actively quarantined.")
    return {"status": "success", "message": f"IP {ip} released from quarantine.", "ip": ip}

@router.get("/history", response_model=List[Dict[str, Any]])
def get_containment_history(limit: int = Query(50, ge=1, le=500)):
    """Retrieve audit history of all SOAR containment and response actions."""
    return SOARService.get_action_history(limit=limit)

@router.post("/webhook/test")
async def test_webhook(req: WebhookTestRequest):
    """Test webhook delivery by dispatching a sample SIEM incident card."""
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
        raw_log_reference="Test log event"
    )
    success = await SOARService.dispatch_webhook_alert(sample_alert, webhook_url=req.webhook_url)
    if not success:
        raise HTTPException(status_code=502, detail="Failed to deliver webhook. Check destination URL and network.")
    return {"status": "success", "message": "Test webhook dispatched successfully."}
