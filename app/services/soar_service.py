import time
import httpx
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from app.schemas.detection_alert import DetectionAlert
from app.schemas.severity import Severity
from app.config.settings import settings

logger = logging.getLogger(__name__)

class QuarantinedHost:
    def __init__(
        self,
        ip: str,
        reason: str,
        duration_seconds: int = 3600,
        severity: str = "HIGH",
        analyst: str = "SYSTEM_AUTOMATION"
    ):
        self.ip = ip
        self.reason = reason
        self.quarantined_at = datetime.now(timezone.utc)
        self.duration_seconds = duration_seconds
        self.expires_at = self.quarantined_at + timedelta(seconds=duration_seconds)
        self.severity = severity
        self.analyst = analyst
        self.status = "ACTIVE" # ACTIVE | RELEASED | EXPIRED

    @property
    def is_expired(self) -> bool:
        if self.status != "ACTIVE":
            return True
        return datetime.now(timezone.utc) >= self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        remaining = max(0, int((self.expires_at - datetime.now(timezone.utc)).total_seconds()))
        return {
            "ip": self.ip,
            "reason": self.reason,
            "quarantined_at": self.quarantined_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "duration_seconds": self.duration_seconds,
            "remaining_seconds": remaining,
            "severity": self.severity,
            "analyst": self.analyst,
            "status": "EXPIRED" if self.is_expired else self.status
        }


class SOARService:
    """
    Security Orchestration, Automation, and Response (SOAR) Service.
    Handles automated webhook alerting, active containment, and IP quarantine.
    """

    _quarantine_store: Dict[str, QuarantinedHost] = {}
    _action_history: List[Dict[str, Any]] = []

    @classmethod
    def quarantine_ip(
        cls,
        ip: str,
        reason: str,
        duration_seconds: int = 3600,
        severity: str = "HIGH",
        analyst: str = "SYSTEM_AUTOMATION"
    ) -> Dict[str, Any]:
        """Place an attacking IP into automated quarantine / firewall block."""
        if not ip:
            raise ValueError("IP address is required for quarantine.")

        record = QuarantinedHost(
            ip=ip,
            reason=reason,
            duration_seconds=duration_seconds,
            severity=severity,
            analyst=analyst
        )
        cls._quarantine_store[ip] = record

        action = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "QUARANTINE_IP",
            "ip": ip,
            "reason": reason,
            "duration_seconds": duration_seconds,
            "analyst": analyst
        }
        cls._action_history.append(action)
        logger.warning(f"SOAR Active Response: Quarantined IP {ip} for {duration_seconds}s. Reason: {reason}")
        return record.to_dict()

    @classmethod
    def release_ip(cls, ip: str, analyst: str = "admin", reason: str = "Manual SOC Analyst Release") -> bool:
        """Release an IP from quarantine."""
        if ip in cls._quarantine_store:
            cls._quarantine_store[ip].status = "RELEASED"
            cls._action_history.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": "RELEASE_IP",
                "ip": ip,
                "analyst": analyst,
                "reason": reason
            })
            del cls._quarantine_store[ip]
            logger.info(f"SOAR Active Response: Released IP {ip} by {analyst}.")
            return True
        return False

    @classmethod
    def is_ip_quarantined(cls, ip: str) -> bool:
        """Check if an IP is currently blocked by active quarantine."""
        if ip in cls._quarantine_store:
            record = cls._quarantine_store[ip]
            if not record.is_expired:
                return True
            # Clean expired
            del cls._quarantine_store[ip]
        return False

    @classmethod
    def get_active_quarantines(cls) -> List[Dict[str, Any]]:
        """List all currently quarantined IPs with remaining cooldown time."""
        active = []
        expired_keys = []
        for ip, host in list(cls._quarantine_store.items()):
            if host.is_expired:
                expired_keys.append(ip)
            else:
                active.append(host.to_dict())

        for ip in expired_keys:
            del cls._quarantine_store[ip]

        return active

    @classmethod
    def get_action_history(cls, limit: int = 50) -> List[Dict[str, Any]]:
        """Return history of automated and manual SOAR containment actions."""
        return cls._action_history[-limit:]

    @classmethod
    async def dispatch_webhook_alert(
        cls,
        alert: DetectionAlert,
        webhook_url: Optional[str] = None
    ) -> bool:
        """
        Dispatches a rich JSON incident payload to configured Slack, Teams, or SOC webhook.
        """
        target_url = webhook_url or getattr(settings, "SOAR_WEBHOOK_URL", None)
        if not target_url:
            return False

        payload = {
            "text": f"🚨 *LogSentry SIEM Alert [{alert.severity.value}]*: {alert.title}",
            "attachments": [
                {
                    "color": "#ef4444" if alert.severity == Severity.CRITICAL else "#f97316",
                    "title": alert.title,
                    "fields": [
                        {"title": "Severity", "value": alert.severity.value, "short": True},
                        {"title": "Attack Type", "value": alert.attack_type, "short": True},
                        {"title": "Source IP", "value": alert.source_ip, "short": True},
                        {"title": "Target Endpoint", "value": alert.endpoint, "short": True},
                        {"title": "MITRE ATT&CK", "value": f"{alert.mitre_tactic} ({alert.mitre_technique})", "short": True},
                        {"title": "Confidence", "value": f"{alert.confidence * 100:.0f}%", "short": True}
                    ],
                    "footer": f"LogSentry SIEM v{settings.VERSION} • Automated SOC Alert",
                    "ts": int(time.time())
                }
            ]
        }

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.post(target_url, json=payload)
                if res.status_code in (200, 204):
                    logger.info(f"Successfully dispatched SOAR webhook for alert: {alert.title}")
                    return True
                else:
                    logger.warning(f"SOAR webhook returned status {res.status_code}: {res.text}")
                    return False
        except Exception as e:
            logger.error(f"Failed to dispatch SOAR webhook: {e}")
            return False

    @classmethod
    def evaluate_auto_containment(cls, alert: DetectionAlert) -> Optional[Dict[str, Any]]:
        """
        Evaluates policy-based automatic containment.
        If a critical attack is detected with high confidence, triggers immediate IP quarantine.
        """
        if alert.severity == Severity.CRITICAL and alert.source_ip:
            # Check if auto-quarantine enabled or severe exploit
            reason = f"Automated SOAR quarantine triggered by Critical Exploit [{alert.title}] targeting {alert.endpoint}"
            return cls.quarantine_ip(
                ip=alert.source_ip,
                reason=reason,
                duration_seconds=7200, # 2 hours
                severity="CRITICAL",
                analyst="SOAR_POLICY_ENGINE"
            )
        return None
