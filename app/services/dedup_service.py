"""LogSentry Idempotent Ingestion Deduplication Service.

Prevents duplicate event ingestion across network retries, agent restarts, and redundant shippers.
Uses a time-bounded SHA-256 fingerprint cache.
"""

import hashlib
import time
from typing import Any


class EventDeduplicator:
    """In-memory LRU time-bounded deduplication cache."""

    def __init__(self, ttl_seconds: int = 3600, max_size: int = 50000):
        self.ttl = ttl_seconds
        self.max_size = max_size
        self._seen: dict[str, float] = {}

    def compute_event_fingerprint(self, event_data: dict[str, Any]) -> str:
        """Computes a deterministic hash of the event's immutable identity attributes."""
        raw_log = str(event_data.get("raw_log", "")).strip()
        timestamp = str(event_data.get("timestamp", ""))
        source_ip = str(event_data.get("source_ip", ""))
        event_id = str(event_data.get("event_id", ""))

        if event_id and event_id != "None":
            # If collector provided a unique event ID, use that
            seed = f"id:{event_id}"
        else:
            seed = f"{timestamp}|{source_ip}|{raw_log}"

        return hashlib.sha256(seed.encode("utf-8")).hexdigest()

    def is_duplicate(self, fingerprint: str) -> bool:
        """Checks if fingerprint was processed within the TTL window."""
        now = time.time()
        self._prune(now)

        if fingerprint in self._seen:
            return True

        if len(self._seen) >= self.max_size:
            # Drop oldest 10% when capacity reached
            sorted_keys = sorted(self._seen.keys(), key=lambda k: self._seen[k])
            for k in sorted_keys[: int(self.max_size * 0.1)]:
                self._seen.pop(k, None)

        self._seen[fingerprint] = now
        return False

    def _prune(self, now: float):
        """Cleans up expired fingerprints."""
        cutoff = now - self.ttl
        expired = [k for k, ts in self._seen.items() if ts < cutoff]
        for k in expired:
            self._seen.pop(k, None)


# Global singleton deduplicator
event_deduplicator = EventDeduplicator()
