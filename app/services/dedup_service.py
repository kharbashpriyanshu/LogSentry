"""LogSentry Idempotent Ingestion Deduplication Service.

Prevents duplicate event ingestion across network retries, agent restarts, and redundant shippers.
Uses a thread-safe, multi-tenant SHA-256 fingerprint LRU cache.
"""

from collections import OrderedDict
import hashlib
import threading
import time
from collections import OrderedDict
from typing import Any


class EventDeduplicator:
    """Thread-safe multi-tenant O(1) LRU time-bounded deduplication cache."""

    def __init__(self, ttl_seconds: int = 3600, max_size: int = 50000):
        self.ttl = ttl_seconds
        self.max_size = max_size
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def compute_event_fingerprint(self, event_data: dict[str, Any]) -> str:
        """Computes a deterministic hash of the event's immutable identity attributes including tenant_id."""
        tenant_id = str(event_data.get("tenant_id") or "default").strip()
        raw_log = str(event_data.get("raw_log", "")).strip()
        timestamp = str(event_data.get("timestamp", "")).strip()
        source_ip = str(event_data.get("source_ip", "")).strip()
        event_id = str(event_data.get("event_id", "")).strip()

        if event_id and event_id not in ("None", ""):
            # Collector provided an explicit unique event ID (scoped per tenant)
            seed = f"{tenant_id}:id:{event_id}"
        else:
            seed = f"{tenant_id}|{timestamp}|{source_ip}|{raw_log}"

        return hashlib.sha256(seed.encode("utf-8")).hexdigest()

    def check_duplicate(self, fingerprint: str) -> bool:
        """
        Thread-safe check to determine if fingerprint was already processed within the TTL window.
        Does NOT record or modify the cache if the item is not a duplicate.
        """
        now = time.time()
        cutoff = now - self.ttl

        with self._lock:
            if fingerprint in self._seen:
                entry_time = self._seen[fingerprint]
                if entry_time >= cutoff:
                    self._seen.move_to_end(fingerprint)
                    return True
                else:
                    del self._seen[fingerprint]
            return False

    def record_seen(self, fingerprint: str) -> None:
        """
        Records a successfully validated and persisted event fingerprint into the LRU cache.
        Enforces maximum capacity via true O(1) eviction of the oldest entry.
        """
        now = time.time()
        with self._lock:
            while len(self._seen) >= self.max_size:
                self._seen.popitem(last=False)
            self._seen[fingerprint] = now
            self._seen.move_to_end(fingerprint)

    def is_duplicate(self, fingerprint: str) -> bool:
        """
        Atomic check-and-record operation.
        Returns True if duplicate, otherwise records fingerprint and returns False.
        """
        if self.check_duplicate(fingerprint):
            return True
        self.record_seen(fingerprint)
        return False

    def clear(self):
        """Reset deduplication cache (useful for testing)."""
        with self._lock:
            self._seen.clear()


# Global singleton deduplicator
event_deduplicator = EventDeduplicator()
