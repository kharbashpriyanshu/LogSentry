from datetime import datetime
from typing import Dict, List, Tuple
from app.detection.base import BaseRule
from app.schemas.log_event import LogEvent
from app.schemas.detection_alert import DetectionAlert
from app.schemas.severity import Severity
from app.config.settings import settings
import logging
import re

logger = logging.getLogger(__name__)

# Preserved for backward compatibility
DIR_ENUM_PATTERN = re.compile(r'(?i)(/admin|/login|/\.git|/backup|/config|/phpmyadmin)')

class DirectoryEnumerationRule(BaseRule):
    """
    Behavioral detection rule for Directory Enumeration (MITRE T1083).
    Detects when the same source IP probes multiple distinct unusual or administrative
    paths within a configurable time window.
    """
    def __init__(self):
        # Maps source_ip -> List of (timestamp, endpoint, raw_log)
        self._state: Dict[str, List[Tuple[datetime, str, str]]] = {}
        self.threshold = getattr(settings, "DETECTION_DIR_ENUM_THRESHOLD", 3)
        self.window_seconds = getattr(settings, "DETECTION_DIR_ENUM_WINDOW_SECONDS", 60)
        self._cleanup_counter = 0

    @property
    def rule_name(self) -> str: return "dir_enum"
    @property
    def rule_version(self) -> str: return "2.0.0"
    @property
    def description(self) -> str: return "Detects directory enumeration or sensitive file reconnaissance."
    @property
    def severity(self) -> Severity: return Severity.LOW

    def _is_benign_path(self, endpoint: str) -> bool:
        """
        Classifies common ordinary requests that should NOT independently trigger
        Directory Enumeration. Note: /robots.txt is checked separately so it can
        participate in recon sequences without triggering alerts by itself.
        """
        if not endpoint:
            return True

        path = endpoint.split("?")[0].lower()

        # Exact ordinary benign paths (excluding /robots.txt which has special handling)
        benign_exact = {
            "/",
            "/index.html",
            "/index.htm",
            "/about",
            "/about.html",
            "/contact",
            "/contact.html",
            "/login",
            "/favicon.ico",
            "/sitemap.xml",
            "/home",
            "/dashboard",
            "/products",
            "/item",
            "/search",
            "/feedback",
            "/api/login",
            "/api/v1/health",
            "/metrics",
            "/api/v1/alerts",
            "/api/v1/users",
            "/api/v1/incidents",
            "/api/v1/reports",
        }
        if path in benign_exact:
            return True

        # Static assets directories
        if path.startswith(("/css/", "/js/", "/assets/", "/images/", "/fonts/", "/static/", "/public/", "/media/")):
            return True

        # Common static file extensions
        benign_exts = (".css", ".js", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2", ".map", ".gif", ".html", ".htm")
        if path.endswith(benign_exts):
            return True

        return False

    def _cleanup_stale_ips(self, current_time: datetime):
        """Prevents memory leaks by aggressively removing stale IP records."""
        stale_ips = []
        for ip, records in self._state.items():
            valid_records = [r for r in records if (current_time - r[0]).total_seconds() <= self.window_seconds]
            if not valid_records:
                stale_ips.append(ip)
            else:
                self._state[ip] = valid_records
                
        for ip in stale_ips:
            del self._state[ip]

    def match(self, event: LogEvent) -> bool:
        self._cleanup_counter += 1
        if self._cleanup_counter > 1000 and event.timestamp:
            self._cleanup_stale_ips(event.timestamp)
            self._cleanup_counter = 0

        if not event.endpoint or not event.source_ip or not event.timestamp:
            return False

        path = event.endpoint.split("?")[0]
        if self._is_benign_path(path):
            return False

        ip = event.source_ip
        current_time = event.timestamp

        if ip not in self._state:
            self._state[ip] = []

        self._state[ip].append((current_time, path, event.raw_log or ""))

        # Prune events outside the time window
        self._state[ip] = [
            r for r in self._state[ip]
            if (current_time - r[0]).total_seconds() <= self.window_seconds
        ]

        # Calculate unique paths probed (preserving order of first request)
        unique_paths = list(dict.fromkeys(r[1] for r in self._state[ip]))

        # Special robots.txt handling:
        # /robots.txt alone MUST NOT trigger Directory Enumeration.
        # But if part of a reconnaissance sequence with other distinct paths, it contributes.
        non_robots_paths = [p for p in unique_paths if p.lower() != "/robots.txt"]

        if len(unique_paths) >= self.threshold and len(non_robots_paths) >= 1 and (len(unique_paths) > 1 or "/robots.txt" not in [p.lower() for p in unique_paths]):
            return True

        return False

    def generate_alert(self, event: LogEvent) -> DetectionAlert:
        ip = event.source_ip or "unknown"
        records = self._state.get(ip, [(event.timestamp, event.endpoint, event.raw_log or "")])

        unique_paths = list(dict.fromkeys(r[1] for r in records))
        sample_paths = unique_paths[:15]  # provide up to 15 sample paths
        request_count = len(records)
        first_seen = records[0][0]
        last_seen = records[-1][0]
        window = int((last_seen - first_seen).total_seconds())
        if window <= 0:
            window = self.window_seconds

        description = (
            f"Source {ip} requested {len(unique_paths)} distinct administrative or sensitive paths "
            f"within {window} seconds, consistent with web directory reconnaissance."
        )

        combined_raw_logs = "\n".join(r[2] for r in records if r[2]) or (event.raw_log or "")

        evidence = {
            "unique_paths_probed": len(unique_paths),
            "request_count": request_count,
            "window_seconds": window,
            "source_ip": ip,
            "sample_paths": sample_paths,
            "first_seen": first_seen.isoformat(),
            "last_seen": last_seen.isoformat(),
        }

        # Clear state after generating alert to prevent duplicate alert spamming for the same burst
        if ip in self._state:
            del self._state[ip]

        return DetectionAlert(
            rule_name=self.rule_name,
            rule_version=self.rule_version,
            severity=self.severity,
            confidence=0.85,
            risk_score=35.0,
            title="Directory Enumeration Attempt",
            description=description,
            source_ip=ip,
            endpoint=event.endpoint,
            attack_type="Directory Enumeration",
            mitre_technique="T1083",
            mitre_tactic="Discovery",
            recommendation="Monitor source IP for reconnaissance behavior. Restrict access to administrative paths and implement rate limiting.",
            evidence=evidence,
            raw_log_reference=combined_raw_logs,
        )
