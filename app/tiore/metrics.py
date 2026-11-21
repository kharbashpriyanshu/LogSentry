"""
LogSentry — TIORE Operational Telemetry & Metrics Tracker
=========================================================
Tracks enrichment latency, cache hit ratios, extraction rates, background external
lookups, and structured error logs to eliminate silent failures across the SIEM.
"""

from collections import deque
from datetime import UTC, datetime
from threading import Lock
from typing import Any


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
        with self._lock:
            self.errors_count += 1
            self.errors_by_type[error_type] = self.errors_by_type.get(error_type, 0) + 1
            entry = {
                "timestamp": datetime.now(UTC).isoformat(),
                "error_type": error_type,
                "message": message,
                "context": context or {},
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
