"""
LogSentry — TIORE Operational Telemetry & Metrics Tracker
=========================================================
Tracks enrichment latency, cache hit ratios, extraction rates, background external
lookups, and structured error logs to eliminate silent failures across the SIEM.
"""

import re
from collections import deque
from datetime import UTC, datetime
from threading import Lock
from typing import Any

EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
PHONE_REGEX = re.compile(
    r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
)
TOKEN_REGEX = re.compile(
    r"(?:Bearer\s+[A-Za-z0-9._\-]+|ey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+)"
)
URL_AUTH_REGEX = re.compile(
    r"([a-zA-Z][a-zA-Z0-9+.-]*://)([^:\s/@]+):([^@\s/]+)@"
)
CREDENTIAL_REGEX = re.compile(
    r"(?i)\b(?:api[_\-\s]?key|access[_\-\s]?token|secret[_\-\s]?key|auth[_\-\s]?token|client[_\-\s]?secret|private[_\-\s]?key)\b[\s:=]+(['\"]?)[A-Za-z0-9_\-]{8,}\b"
)
CLOUD_KEY_REGEX = re.compile(
    r"\b(?:AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{22,})\b"
)


def sanitize_text(text: str) -> str:
    """Redacts raw PII, auth tokens, URL credentials, and API keys from telemetry log text."""
    if not isinstance(text, str):
        return str(text)
    sanitized = EMAIL_REGEX.sub("[REDACTED_EMAIL]", text)
    sanitized = PHONE_REGEX.sub("[REDACTED_PHONE]", sanitized)
    sanitized = TOKEN_REGEX.sub("[REDACTED_TOKEN]", sanitized)
    sanitized = URL_AUTH_REGEX.sub(r"\1[REDACTED_USER]:[REDACTED_PASS]@", sanitized)
    sanitized = CREDENTIAL_REGEX.sub("[REDACTED_CREDENTIAL]", sanitized)
    sanitized = CLOUD_KEY_REGEX.sub("[REDACTED_API_KEY]", sanitized)
    return sanitized


def sanitize_context(ctx: Any) -> Any:
    """Recursively sanitizes context data structures against sensitive parameter leakage."""
    if isinstance(ctx, dict):
        clean_dict: dict[str, Any] = {}
        for k, v in ctx.items():
            k_lower = str(k).lower()
            if any(
                s in k_lower
                for s in (
                    "email",
                    "phone",
                    "pass",
                    "token",
                    "secret",
                    "auth",
                    "key",
                    "credential",
                    "cookie",
                    "session",
                )
            ):
                clean_dict[k] = "[REDACTED]"
            else:
                clean_dict[k] = sanitize_context(v)
        return clean_dict
    elif isinstance(ctx, (list, tuple, set)):
        return [sanitize_context(item) for item in ctx]
    elif isinstance(ctx, str):
        return sanitize_text(ctx)
    else:
        return ctx


class TIOREMetricsTracker:
    """
    Thread-safe operational telemetry tracker for TIORE.
    """

    def __init__(self, max_recent_errors: int = 50):
        self._lock = Lock()
        self.events_processed = 0
        self.observables_extracted = 0
        self.local_matches = 0
        self.background_lookups_queued = 0
        self.background_lookups_completed = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.errors_count = 0
        self.errors_by_type: dict[str, int] = {}
        self.recent_errors: deque[dict[str, Any]] = deque(maxlen=max_recent_errors)

    def record_event_processed(self, observable_count: int = 0) -> None:
        with self._lock:
            self.events_processed += 1
            self.observables_extracted += observable_count

    def record_match(self) -> None:
        with self._lock:
            self.local_matches += 1

    def record_cache_hit(self) -> None:
        with self._lock:
            self.cache_hits += 1

    def record_cache_miss(self) -> None:
        with self._lock:
            self.cache_misses += 1

    def record_background_queued(self, count: int = 1) -> None:
        with self._lock:
            self.background_lookups_queued += count

    def record_background_completed(self, count: int = 1) -> None:
        with self._lock:
            self.background_lookups_completed += count

    def record_error(
        self,
        error_type: str,
        message: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        sanitized_msg = sanitize_text(message)
        sanitized_ctx = sanitize_context(context or {})
        with self._lock:
            self.errors_count += 1
            self.errors_by_type[error_type] = self.errors_by_type.get(error_type, 0) + 1
            entry = {
                "timestamp": datetime.now(UTC).isoformat(),
                "error_type": error_type,
                "message": sanitized_msg,
                "context": sanitized_ctx,
            }
            self.recent_errors.append(entry)

    def get_summary(self) -> dict[str, Any]:
        with self._lock:
            total_cache_queries = self.cache_hits + self.cache_misses
            hit_ratio = (
                round(self.cache_hits / total_cache_queries, 4)
                if total_cache_queries > 0
                else 0.0
            )
            return {
                "events_processed": self.events_processed,
                "observables_extracted": self.observables_extracted,
                "local_matches": self.local_matches,
                "background_lookups_queued": self.background_lookups_queued,
                "background_lookups_completed": self.background_lookups_completed,
                "cache_hits": self.cache_hits,
                "cache_misses": self.cache_misses,
                "cache_hit_ratio": hit_ratio,
                "errors_total": self.errors_count,
                "errors_by_type": dict(self.errors_by_type),
                "recent_errors": list(self.recent_errors)[-10:],
            }


# Global singleton metrics instance
tiore_metrics = TIOREMetricsTracker()
