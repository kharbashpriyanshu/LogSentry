"""LogSentry Multi-Stage Event Correlation Intelligence Engine.

Correlates individual low-level security alerts across sliding time windows
into unified, high-confidence attack campaigns (e.g. Port Scan -> Web Exploit -> Command Execution).
Guarantees strict multi-tenant isolation and deterministic campaign IDs.
"""

import hashlib
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.schemas.detection_alert import DetectionAlert

logger = logging.getLogger(__name__)


@dataclass
class CorrelatedCampaign:
    campaign_id: str
    tenant_id: str
    source_ip: str
    title: str
    severity: str
    confidence: float
    tactics: list[str]
    alert_ids: list[str] = field(default_factory=list)
    attack_types: list[str] = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    summary: str = ""


class CorrelationEngine:
    """Stateful multi-event attack chain correlation engine with strict tenant isolation."""

    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        # Mapping: tenant_id:entity_key -> list of recent alerts
        self._ip_alerts: dict[str, list[dict[str, Any]]] = defaultdict(list)
        # Active campaigns: campaign_id -> CorrelatedCampaign
        self._active_campaigns: dict[str, CorrelatedCampaign] = {}

    def _generate_campaign_id(self, tenant_id: str, entity_key: str) -> str:
        """Generates deterministic, collision-resistant campaign identifier."""
        raw = f"{tenant_id}:{entity_key}".encode()
        h = hashlib.sha256(raw).hexdigest()[:8]
        return f"camp-{h}"

    def correlate_alert(self, alert: DetectionAlert) -> CorrelatedCampaign | None:
        """
        Evaluates an incoming alert against historical window for the same entity and tenant.
        Returns a CorrelatedCampaign if a multi-stage attack pattern is identified.
        """
        tenant_id = alert.tenant_id or "default"
        source_ip = alert.source_ip or "unknown"

        if source_ip in ("127.0.0.1", "localhost", "unknown"):
            # If internal/loopback, group by hostname or rule if available
            entity = f"{alert.hostname or 'host'}:{alert.attack_type}"
        else:
            entity = source_ip

        # Prefix entity key with tenant_id to guarantee absolute cross-tenant isolation
        entity_key = f"{tenant_id}:{entity}"

        # Resolve event timestamp
        event_time = time.time()
        if hasattr(alert, "timestamp") and alert.timestamp:
            if isinstance(alert.timestamp, datetime):
                event_time = alert.timestamp.timestamp()
            elif isinstance(alert.timestamp, (int, float)):
                event_time = float(alert.timestamp)

        # Clean expired alerts from entity window
        cutoff = event_time - self.window_seconds
        self._ip_alerts[entity_key] = [
            a for a in self._ip_alerts[entity_key] if a["timestamp"] >= cutoff
        ]

        # Record current alert
        entry = {
            "alert_id": alert.alert_id,
            "title": alert.title,
            "attack_type": alert.attack_type,
            "severity": (
                alert.severity.value
                if hasattr(alert.severity, "value")
                else str(alert.severity)
            ),
            "mitre_technique": alert.mitre_technique or "",
            "timestamp": event_time,
        }
        self._ip_alerts[entity_key].append(entry)

        recent = self._ip_alerts[entity_key]
        distinct_attack_types = {a["attack_type"] for a in recent}
        alert_ids = [a["alert_id"] for a in recent]
        campaign_id = self._generate_campaign_id(tenant_id, entity)

        # Multi-stage detection scenarios
        has_sqli = any(
            "SQL" in a["attack_type"].upper() or "SQLI" in a["attack_type"].upper()
            for a in recent
        )
        has_rce = any(
            "COMMAND" in a["attack_type"].upper()
            or "POWERSHELL" in a["attack_type"].upper()
            for a in recent
        )
        has_probe = any(
            "PROBE" in a["attack_type"].upper()
            or "TRAVERSAL" in a["attack_type"].upper()
            or "ENUM" in a["attack_type"].upper()
            for a in recent
        )
        has_brute = any("BRUTE" in a["attack_type"].upper() for a in recent)

        # 1. Multi-Stage Web Intrusion Campaign: Probe/Recon -> Exploit -> Post-Exploitation
        if (
            (has_probe and has_sqli)
            or (has_sqli and has_rce)
            or (has_probe and has_rce)
        ):
            tactics = ["Initial Access (T1190)", "Execution (T1059)"]
            campaign = CorrelatedCampaign(
                campaign_id=campaign_id,
                tenant_id=tenant_id,
                source_ip=source_ip,
                title=f"Multi-Stage Web Intrusion Campaign from {source_ip}",
                severity="CRITICAL",
                confidence=0.96,
                tactics=tactics,
                alert_ids=alert_ids,
                attack_types=list(distinct_attack_types),
                first_seen=min(a["timestamp"] for a in recent),
                last_seen=max(a["timestamp"] for a in recent),
                summary=(
                    f"Correlated {len(recent)} security events across {len(distinct_attack_types)} vectors "
                    f"({', '.join(distinct_attack_types)}) within {self.window_seconds}s for tenant '{tenant_id}'. "
                    "Attacker progressed from reconnaissance/injection to remote execution."
                ),
            )
            self._active_campaigns[campaign.campaign_id] = campaign
            return campaign

        # 2. Brute Force followed by High-Severity Exploit
        if has_brute and (has_sqli or has_rce or len(recent) >= 4):
            tactics = ["Credential Access (T1110)", "Execution (T1059)"]
            campaign = CorrelatedCampaign(
                campaign_id=campaign_id,
                tenant_id=tenant_id,
                source_ip=source_ip,
                title=f"Coordinated Brute Force & Breach Attempt from {source_ip}",
                severity="HIGH",
                confidence=0.92,
                tactics=tactics,
                alert_ids=alert_ids,
                attack_types=list(distinct_attack_types),
                first_seen=min(a["timestamp"] for a in recent),
                last_seen=max(a["timestamp"] for a in recent),
                summary=(
                    f"Detected repeated authentication attacks followed by high-severity exploit probes "
                    f"from {source_ip} targeting corporate assets in tenant '{tenant_id}'."
                ),
            )
            self._active_campaigns[campaign.campaign_id] = campaign
            return campaign

        # 3. High-Velocity Multi-Vector Attack (3+ distinct vectors within 5 min)
        if len(distinct_attack_types) >= 3:
            campaign = CorrelatedCampaign(
                campaign_id=campaign_id,
                tenant_id=tenant_id,
                source_ip=source_ip,
                title=f"High-Velocity Multi-Vector Attack Cluster ({source_ip})",
                severity="HIGH",
                confidence=0.90,
                tactics=["Initial Access", "Discovery"],
                alert_ids=alert_ids,
                attack_types=list(distinct_attack_types),
                first_seen=min(a["timestamp"] for a in recent),
                last_seen=max(a["timestamp"] for a in recent),
                summary=(
                    f"Correlated cluster of {len(recent)} alerts representing 3 distinct attack methodologies "
                    f"simultaneously probing infrastructure in tenant '{tenant_id}'."
                ),
            )
            self._active_campaigns[campaign.campaign_id] = campaign
            return campaign

        return None


# Global singleton correlation engine
correlation_engine = CorrelationEngine()
