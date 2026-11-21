"""LogSentry Multi-Stage Event Correlation Intelligence Engine.

Correlates individual low-level security alerts across sliding time windows
into unified, high-confidence attack campaigns (e.g. Port Scan -> Web Exploit -> Command Execution).
"""

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from app.schemas.detection_alert import DetectionAlert

logger = logging.getLogger(__name__)


@dataclass
class CorrelatedCampaign:
    campaign_id: str
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
    """Stateful multi-event attack chain correlation engine."""

    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        # Mapping: source_ip -> list of recent alerts
        self._ip_alerts: dict[str, list[dict[str, Any]]] = defaultdict(list)
        # Active campaigns: campaign_id -> CorrelatedCampaign
        self._active_campaigns: dict[str, CorrelatedCampaign] = {}

    def correlate_alert(self, alert: DetectionAlert) -> CorrelatedCampaign | None:
        """
        Evaluates an incoming alert against historical window for the same entity (source IP/host).
        Returns a CorrelatedCampaign if a multi-stage attack pattern is identified.
        """
        source_ip = alert.source_ip or "unknown"
        if source_ip in ("127.0.0.1", "localhost", "unknown"):
            # If internal/loopback, group by hostname or rule if available
            entity_key = f"{alert.hostname or 'host'}:{alert.attack_type}"
        else:
            entity_key = source_ip

        now = time.time()
        # Clean expired alerts from entity window
        cutoff = now - self.window_seconds
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
            "timestamp": now,
        }
        self._ip_alerts[entity_key].append(entry)

        recent = self._ip_alerts[entity_key]
        distinct_attack_types = {a["attack_type"] for a in recent}
        alert_ids = [a["alert_id"] for a in recent]

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
                campaign_id=f"camp-{abs(hash(entity_key)) % 100000:05d}",
                source_ip=source_ip,
                title=f"Multi-Stage Web Intrusion Campaign from {source_ip}",
                severity="CRITICAL",
                confidence=0.96,
                tactics=tactics,
                alert_ids=alert_ids,
                attack_types=list(distinct_attack_types),
                summary=(
                    f"Correlated {len(recent)} security events across {len(distinct_attack_types)} vectors "
                    f"({', '.join(distinct_attack_types)}) within {self.window_seconds}s. "
                    "Attacker progressed from reconnaissance/injection to remote execution."
                ),
            )
            self._active_campaigns[campaign.campaign_id] = campaign
            return campaign

        # 2. Brute Force followed by High-Severity Exploit
        if has_brute and (has_sqli or has_rce or len(recent) >= 4):
            tactics = ["Credential Access (T1110)", "Execution (T1059)"]
            campaign = CorrelatedCampaign(
                campaign_id=f"camp-{abs(hash(entity_key)) % 100000:05d}",
                source_ip=source_ip,
                title=f"Coordinated Brute Force & Breach Attempt from {source_ip}",
                severity="HIGH",
                confidence=0.92,
                tactics=tactics,
                alert_ids=alert_ids,
                attack_types=list(distinct_attack_types),
                summary=(
                    f"Detected repeated authentication attacks followed by high-severity exploit probes "
                    f"from {source_ip} targeting corporate assets."
                ),
            )
            self._active_campaigns[campaign.campaign_id] = campaign
            return campaign

        # 3. High-Velocity Multi-Vector Attack (3+ distinct vectors within 5 min)
        if len(distinct_attack_types) >= 3:
            campaign = CorrelatedCampaign(
                campaign_id=f"camp-{abs(hash(entity_key)) % 100000:05d}",
                source_ip=source_ip,
                title=f"High-Velocity Multi-Vector Attack Cluster ({source_ip})",
                severity="HIGH",
                confidence=0.90,
                tactics=["Initial Access", "Discovery"],
                alert_ids=alert_ids,
                attack_types=list(distinct_attack_types),
                summary=(
                    f"Correlated cluster of {len(recent)} alerts representing 3 distinct attack methodologies "
                    f"simultaneously probing infrastructure."
                ),
            )
            self._active_campaigns[campaign.campaign_id] = campaign
            return campaign

        return None


# Global singleton correlation engine
correlation_engine = CorrelationEngine()
