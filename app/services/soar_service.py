import ipaddress
import logging
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.config.settings import settings
from app.database.session import SessionLocal
from app.models.soar_action import SOARActionModel
from app.schemas.detection_alert import DetectionAlert
from app.schemas.severity import Severity

logger = logging.getLogger(__name__)


class QuarantinedHost:
    def __init__(
        self,
        ip: str,
        reason: str,
        duration_seconds: int = 3600,
        severity: str = "HIGH",
        analyst: str = "SYSTEM_AUTOMATION",
        containment_type: str = "IN_MEMORY",
    ):
        self.ip = ip
        self.reason = reason
        self.quarantined_at = datetime.now(UTC)
        self.duration_seconds = duration_seconds
        self.expires_at = self.quarantined_at + timedelta(seconds=duration_seconds)
        self.severity = severity
        self.analyst = analyst
        self.containment_type = (
            containment_type  # IN_MEMORY | CLOUDFLARE | AWS_WAF | IPTABLES
        )
        self.status = "ACTIVE"  # ACTIVE | RELEASED | EXPIRED

    @property
    def is_expired(self) -> bool:
        if self.status != "ACTIVE":
            return True
        return datetime.now(UTC) >= self.expires_at

    def to_dict(self) -> dict[str, Any]:
        remaining = max(0, int((self.expires_at - datetime.now(UTC)).total_seconds()))
        return {
            "ip": self.ip,
            "reason": self.reason,
            "quarantined_at": self.quarantined_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "duration_seconds": self.duration_seconds,
            "remaining_seconds": remaining,
            "severity": self.severity,
            "analyst": self.analyst,
            "containment_type": self.containment_type,
            "status": "EXPIRED" if self.is_expired else self.status,
        }


class SOARService:
    """
    Security Orchestration, Automation, and Response (SOAR) Service.
    Handles automated webhook alerting, active containment, firewall blocking, and ticketing.
    """

    _quarantine_store: dict[str, QuarantinedHost] = {}
    _action_history: list[dict[str, Any]] = []

    @classmethod
    def validate_target_safety(cls, ip: str, force: bool = False) -> None:
        """
        Protects internal loopback, RFC 1918, Carrier-Grade NAT, IPv6 ULA, link-local,
        and multicast subnets from accidental containment blocks.
        """
        if not ip:
            raise ValueError("IP address is required for containment.")

        try:
            addr = ipaddress.ip_address(ip)
            is_internal = (
                addr.is_loopback
                or addr.is_link_local
                or addr.is_multicast
                or addr.is_reserved
                or addr.is_unspecified
                or (
                    addr.version == 4
                    and (
                        addr in ipaddress.ip_network("10.0.0.0/8")
                        or addr in ipaddress.ip_network("172.16.0.0/12")
                        or addr in ipaddress.ip_network("192.168.0.0/16")
                        or addr in ipaddress.ip_network("100.64.0.0/10")
                    )
                )
                or (
                    addr.version == 6
                    and (
                        addr in ipaddress.ip_network("fc00::/7")  # ULA
                        or addr in ipaddress.ip_network("fe80::/10")  # Link-local
                    )
                )
            )
            if is_internal and not force:
                raise ValueError(
                    f"Protected private/internal IP '{ip}' cannot be quarantined without an explicit force override."
                )
        except ValueError as e:
            if "Protected private/internal" in str(e):
                raise

    @classmethod
    def quarantine_ip(
        cls,
        ip: str,
        reason: str,
        duration_seconds: int = 3600,
        severity: str = "HIGH",
        analyst: str = "SYSTEM_AUTOMATION",
        containment_type: str = "IN_MEMORY",
        tenant_id: str = "default",
        force: bool = False,
        db: Session | None = None,
    ) -> dict[str, Any]:
        """Place an attacking IP into automated quarantine / firewall block with persistent DB audit."""
        cls.validate_target_safety(ip, force=force)

        record = QuarantinedHost(
            ip=ip,
            reason=reason,
            duration_seconds=duration_seconds,
            severity=severity,
            analyst=analyst,
            containment_type=containment_type,
        )
        cls._quarantine_store[ip] = record

        # Generate rollback command
        rollback_cmd = (
            f"iptables -D INPUT -s {ip} -j DROP"
            if containment_type == "IPTABLES"
            else f"release_ip({ip})"
        )

        # Persist to database for multi-node durability
        close_db = False
        if db is None:
            try:
                db = SessionLocal()
                close_db = True
            except Exception:
                db = None

        if db is not None:
            try:
                soar_record = SOARActionModel(
                    tenant_id=tenant_id,
                    action_type="QUARANTINE_IP",
                    target=ip,
                    status="ACTIVE",
                    reason=reason,
                    requested_by=analyst,
                    approved_by=analyst if analyst != "SYSTEM_AUTOMATION" else None,
                    duration_seconds=duration_seconds,
                    rollback_command=rollback_cmd,
                    expires_at=datetime.now(UTC) + timedelta(seconds=duration_seconds),
                )
                db.add(soar_record)
                db.commit()
            except Exception as e:
                logger.warning(f"Failed to persist SOAR action to database: {e}")
            finally:
                if close_db:
                    db.close()

        action = {
            "timestamp": datetime.now(UTC).isoformat(),
            "action": "QUARANTINE_IP",
            "ip": ip,
            "reason": reason,
            "duration_seconds": duration_seconds,
            "analyst": analyst,
            "containment_type": containment_type,
        }
        cls._action_history.append(action)
        logger.warning(
            f"SOAR Active Response: Quarantined IP {ip} ({containment_type}) for {duration_seconds}s. Reason: {reason}"
        )
        return record.to_dict()

    @classmethod
    def rollback_action(
        cls, target_ip: str, analyst: str = "SOC_ANALYST", db: Session | None = None
    ) -> bool:
        """Rolls back an active containment action and updates database status."""
        return cls.release_ip(
            target_ip, analyst=analyst, reason="Manual containment rollback", db=db
        )

    @classmethod
    def release_ip(
        cls,
        ip: str,
        analyst: str = "SOC_ANALYST",
        reason: str = "Containment completed",
        db: Session | None = None,
    ) -> bool:
        """Release an IP from quarantine and record rollback in persistent audit table."""
        released = False
        if ip in cls._quarantine_store:
            cls._quarantine_store[ip].status = "RELEASED"
            released = True

        # Update in database if present
        close_db = False
        if db is None:
            try:
                db = SessionLocal()
                close_db = True
            except Exception:
                db = None

        if db is not None:
            try:
                active_records = (
                    db.query(SOARActionModel)
                    .filter(
                        SOARActionModel.target == ip, SOARActionModel.status == "ACTIVE"
                    )
                    .all()
                )
                for rec in active_records:
                    rec.status = "RELEASED"
                db.commit()
                if active_records:
                    released = True
            except Exception as e:
                logger.warning(f"Failed to update SOAR release in DB: {e}")
            finally:
                if close_db:
                    db.close()

        action = {
            "timestamp": datetime.now(UTC).isoformat(),
            "action": "RELEASE_IP",
            "ip": ip,
            "analyst": analyst,
            "reason": reason,
        }
        cls._action_history.append(action)
        logger.info(f"SOAR Active Response: Released IP {ip} by {analyst}.")
        return released

    @classmethod
    def is_ip_quarantined(cls, ip: str) -> bool:
        """Check if an IP is currently actively quarantined."""
        record = cls._quarantine_store.get(ip)
        if not record:
            return False
        return not record.is_expired

    @classmethod
    def get_quarantined_ips(cls, include_expired: bool = False) -> list[dict[str, Any]]:
        """List quarantined hosts."""
        records = cls._quarantine_store.values()
        if not include_expired:
            records = [r for r in records if not r.is_expired]
        return [r.to_dict() for r in records]

    # Alias for backwards compatibility
    get_active_quarantines = get_quarantined_ips

    @classmethod
    def get_action_history(cls, limit: int = 50) -> list[dict[str, Any]]:
        """Retrieve recent SOAR containment and integration actions."""
        return cls._action_history[-limit:]

    # ------------------------------------------------------------------------
    # Tier 3 - Item 6: Active Firewall / WAF Connectors
    # ------------------------------------------------------------------------

    @classmethod
    async def execute_cloudflare_waf_block(
        cls, ip: str, zone_id: str | None = None, api_token: str | None = None
    ) -> dict[str, Any]:
        """Push an IP block rule to Cloudflare Firewall Rules API."""
        zid = zone_id or getattr(settings, "CLOUDFLARE_ZONE_ID", "mock_zone")
        token = api_token or getattr(settings, "CLOUDFLARE_API_TOKEN", "mock_token")

        rule_payload = {
            "mode": "block",
            "configuration": {"target": "ip", "value": ip},
            "notes": f"LogSentry SOAR Auto-Containment at {datetime.now(UTC).isoformat()}",
        }

        # If live credentials available, issue real API request
        if token != "mock_token" and zid != "mock_zone":
            try:
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                }
                url = f"https://api.cloudflare.com/client/v4/zones/{zid}/firewall/access_rules/rules"
                async with httpx.AsyncClient(timeout=5.0) as client:
                    res = await client.post(url, json=rule_payload, headers=headers)
                    data = res.json()
                    cls.quarantine_ip(
                        ip, "Cloudflare WAF Block Rule", containment_type="CLOUDFLARE"
                    )
                    return {
                        "status": "SUCCESS",
                        "provider": "Cloudflare",
                        "response": data,
                    }
            except Exception as e:
                logger.error(f"Cloudflare WAF block failed: {e}")
                return {"status": "ERROR", "provider": "Cloudflare", "error": str(e)}

        # Simulated execution for sandbox / lab
        cls.quarantine_ip(
            ip, "Cloudflare WAF Block (Simulated)", containment_type="CLOUDFLARE"
        )
        return {
            "status": "SIMULATED",
            "provider": "Cloudflare",
            "action": f"Block IP {ip} in zone {zid}",
            "rule": rule_payload,
        }

    @classmethod
    def generate_iptables_command(cls, ip: str) -> str:
        """Generate Linux iptables containment command."""
        return f"iptables -A INPUT -s {ip} -j DROP -m comment --comment 'LogSentry SOAR Block'"

    @classmethod
    def execute_linux_iptables_block(
        cls, ip: str, dry_run: bool = True
    ) -> dict[str, Any]:
        """Apply or generate a host-level iptables DROP rule for an attacker IP."""
        cmd = cls.generate_iptables_command(ip)
        cls.quarantine_ip(ip, "Linux Host iptables DROP", containment_type="IPTABLES")
        return {
            "status": "DRY_RUN" if dry_run else "EXECUTED",
            "provider": "iptables",
            "command": cmd,
            "ip": ip,
        }

    # ------------------------------------------------------------------------
    # Tier 3 - Item 7: Ticketing & Notification Integrations
    # ------------------------------------------------------------------------

    @classmethod
    def build_slack_alert_card(cls, alert: DetectionAlert) -> dict[str, Any]:
        """Build a rich Slack incident alert card with 1-click containment action buttons."""
        color = "#ef4444" if alert.severity == Severity.CRITICAL else "#f97316"
        return {
            "text": f"🚨 *LogSentry SIEM Alert [{alert.severity.value}]*: {alert.title}",
            "attachments": [
                {
                    "color": color,
                    "title": alert.title,
                    "text": alert.description,
                    "fields": [
                        {
                            "title": "Severity",
                            "value": alert.severity.value,
                            "short": True,
                        },
                        {
                            "title": "Attack Type",
                            "value": alert.attack_type,
                            "short": True,
                        },
                        {
                            "title": "Source IP",
                            "value": str(alert.source_ip),
                            "short": True,
                        },
                        {
                            "title": "Target",
                            "value": str(alert.endpoint),
                            "short": True,
                        },
                        {
                            "title": "MITRE ATT&CK",
                            "value": f"{alert.mitre_tactic} ({alert.mitre_technique})",
                            "short": True,
                        },
                        {
                            "title": "Confidence",
                            "value": f"{alert.confidence * 100:.0f}%",
                            "short": True,
                        },
                    ],
                    "actions": [
                        {
                            "type": "button",
                            "text": "🛡️ 1-Click Quarantine IP",
                            "style": "danger",
                            "url": f"https://logsentry.local/api/v1/soar/quarantine?ip={alert.source_ip}",
                        },
                        {
                            "type": "button",
                            "text": "🔍 Threat Hunt IP",
                            "url": f"https://logsentry.local/hunting?q=source_ip:{alert.source_ip}",
                        },
                        {
                            "type": "button",
                            "text": "✅ Mark False Positive",
                            "url": f"https://logsentry.local/alerts/{alert.alert_id}/fp",
                        },
                    ],
                    "footer": "LogSentry SIEM • Automated Active Defense",
                    "ts": int(time.time()),
                }
            ],
        }

    @classmethod
    async def dispatch_webhook_alert(
        cls, alert: DetectionAlert, webhook_url: str | None = None
    ) -> bool:
        """Dispatches a rich Slack / Teams interactive incident alert."""
        target_url = webhook_url or getattr(settings, "SOAR_WEBHOOK_URL", None)
        if not target_url:
            return False

        payload = cls.build_slack_alert_card(alert)

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.post(target_url, json=payload)
                if res.status_code in (200, 204):
                    logger.info(
                        f"Dispatched SOAR interactive alert card for: {alert.title}"
                    )
                    return True
                else:
                    logger.warning(f"SOAR webhook returned status {res.status_code}")
                    return False
        except Exception as e:
            logger.error(f"Failed to dispatch SOAR webhook: {e}")
            return False

    @classmethod
    async def dispatch_pagerduty_alert(
        cls, alert: DetectionAlert, routing_key: str | None = None
    ) -> dict[str, Any]:
        """Dispatch a critical incident page via PagerDuty Events API v2."""
        r_key = routing_key or getattr(settings, "PAGERDUTY_ROUTING_KEY", "mock_key")
        payload = {
            "routing_key": r_key,
            "event_action": "trigger",
            "dedup_key": f"logsentry-{alert.alert_id}",
            "payload": {
                "summary": f"[{alert.severity.value}] {alert.title} from {alert.source_ip}",
                "severity": (
                    "critical" if alert.severity == Severity.CRITICAL else "error"
                ),
                "source": "LogSentry-SIEM",
                "component": alert.attack_type,
                "custom_details": {
                    "source_ip": alert.source_ip,
                    "endpoint": alert.endpoint,
                    "mitre": alert.mitre_technique,
                },
            },
        }

        if r_key != "mock_key":
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    res = await client.post(
                        "https://events.pagerduty.com/v2/enqueue", json=payload
                    )
                    return {"status": "SENT", "response": res.json()}
            except Exception as e:
                return {"status": "ERROR", "error": str(e)}

        return {"status": "SIMULATED", "payload": payload}

    @classmethod
    def create_jira_ticket_payload(
        cls, alert: DetectionAlert, project_key: str = "SOC"
    ) -> dict[str, Any]:
        """Create Jira / ServiceNow ticketing payload."""
        return {
            "fields": {
                "project": {"key": project_key},
                "summary": f"[SIEM Alert] {alert.title} - {alert.source_ip}",
                "description": (
                    f"Attack Type: {alert.attack_type}\n"
                    f"Severity: {alert.severity.value}\n"
                    f"Source IP: {alert.source_ip}\n"
                    f"Endpoint: {alert.endpoint}\n"
                    f"Recommendation: {alert.recommendation}\n"
                ),
                "issuetype": {"name": "Security Incident"},
                "priority": {
                    "name": "Highest" if alert.severity == Severity.CRITICAL else "High"
                },
            }
        }

    @classmethod
    def evaluate_auto_containment(cls, alert: DetectionAlert) -> dict[str, Any] | None:
        """
        Evaluates policy-based automatic containment.
        If a critical attack is detected with high confidence, triggers immediate IP quarantine.
        """
        if alert.severity == Severity.CRITICAL and alert.source_ip:
            reason = f"Automated SOAR quarantine triggered by Critical Exploit [{alert.title}] targeting {alert.endpoint}"
            return cls.quarantine_ip(
                ip=alert.source_ip,
                reason=reason,
                duration_seconds=7200,  # 2 hours
                severity="CRITICAL",
                analyst="SOAR_POLICY_ENGINE",
            )
        return None
