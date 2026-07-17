from datetime import datetime
from typing import Dict, List
from app.detection.base import BaseRule
from app.schemas.log_event import LogEvent
from app.schemas.detection_alert import DetectionAlert
from app.schemas.severity import Severity
from app.config.settings import settings
import logging

logger = logging.getLogger(__name__)

class BruteForceRule(BaseRule):
    """
    Detects brute force attacks based on failed authentications.
    Uses an in-memory dictionary. Designed so internal storage can be swapped later.
    """
    def __init__(self):
        self._state: Dict[str, List[datetime]] = {}
        self.threshold = settings.DETECTION_BRUTE_FORCE_THRESHOLD
        self.window_seconds = settings.DETECTION_BRUTE_FORCE_WINDOW_SECONDS
        self._cleanup_counter = 0

    @property
    def rule_name(self) -> str: return "brute_force"
    @property
    def rule_version(self) -> str: return "1.1.0"
    @property
    def description(self) -> str: return "Detects brute force authentication attempts."
    @property
    def severity(self) -> Severity: return Severity.HIGH

    def _is_failed_auth(self, event: LogEvent) -> bool:
        if not event.endpoint or not event.status_code:
            return False
        return "login" in event.endpoint.lower() and event.status_code in [401, 403]
        
    def _cleanup_stale_ips(self, current_time: datetime):
        """Prevents memory leaks by aggressively removing stale IP records."""
        stale_ips = []
        for ip, timestamps in self._state.items():
            valid_timestamps = [ts for ts in timestamps if (current_time - ts).total_seconds() <= self.window_seconds]
            if not valid_timestamps:
                stale_ips.append(ip)
            else:
                self._state[ip] = valid_timestamps
                
        for ip in stale_ips:
            del self._state[ip]

    def match(self, event: LogEvent) -> bool:
        # Periodic cleanup to prevent OOM errors over long uptimes
        self._cleanup_counter += 1
        if self._cleanup_counter > 1000 and event.timestamp:
            self._cleanup_stale_ips(event.timestamp)
            self._cleanup_counter = 0

        if not self._is_failed_auth(event) or not event.source_ip or not event.timestamp:
            return False
            
        ip = event.source_ip
        current_time = event.timestamp
        
        if ip not in self._state:
            self._state[ip] = []
            
        self._state[ip].append(current_time)
        
        # Cleanup old events for THIS IP outside the window
        self._state[ip] = [
            ts for ts in self._state[ip] 
            if (current_time - ts).total_seconds() <= self.window_seconds
        ]
        
        if len(self._state[ip]) >= self.threshold:
            # Clear state to prevent spamming
            del self._state[ip]
            return True
            
        return False
        
    def generate_alert(self, event: LogEvent) -> DetectionAlert:
        return DetectionAlert(
            rule_name=self.rule_name,
            rule_version=self.rule_version,
            severity=self.severity,
            confidence=0.95,
            risk_score=90.0,
            title="Brute Force Authentication Detected",
            description=f"Multiple failed login attempts detected from {event.source_ip} within {self.window_seconds} seconds.",
            source_ip=event.source_ip,
            endpoint=event.endpoint,
            attack_type="Brute Force",
            mitre_technique="T1110",
            mitre_tactic="Credential Access",
            recommendation="Block IP temporarily or enforce rate limiting.",
            evidence={"endpoint": event.endpoint, "threshold": self.threshold},
            raw_log_reference=event.raw_log
        )
