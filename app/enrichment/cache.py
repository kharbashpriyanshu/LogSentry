"""
Thread-safe InMemoryCache with LRU eviction and size cap.

Production improvements from Sprint 7:
  - threading.Lock wraps all mutations (thread-safe for sync FastAPI workers)
  - Maximum cache size (evicts oldest entry on overflow — simple LRU)
  - get() / set() / invalidate() / clear() / stats() interface
  - Logging on cache hits/misses for observability
  - Easily swappable with Redis: replace set()/get() implementations only.
"""

import logging
import threading
import time
from collections import OrderedDict
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Hard cap: never store more than this many entries regardless of TTL
_DEFAULT_MAX_ENTRIES = 1000


class InMemoryCache:
    """
    TTL-based in-memory cache with thread-safe operations and LRU eviction.

    Designed to be swapped with a Redis-backed implementation by replacing
    only the get() and set() methods — the interface is intentionally minimal.
    """

    def __init__(
        self,
        ttl_seconds: int = 3600,
        max_entries: int = _DEFAULT_MAX_ENTRIES,
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        # OrderedDict preserves insertion order for LRU eviction
        self._cache: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> Optional[Any]:
        """Return cached value if present and not expired, else None."""
        with self._lock:
            if key not in self._cache:
                self._misses += 1
                return None

            entry = self._cache[key]
            if time.monotonic() - entry["ts"] >= self.ttl_seconds:
                del self._cache[key]
                self._misses += 1
                logger.debug("Cache miss (expired): %s", key)
                return None

            # Move to end (most recently used)
            self._cache.move_to_end(key)
            self._hits += 1
            return entry["value"]

    def set(self, key: str, value: Any) -> None:
        """Store a value. Evicts the oldest entry if the cache is full."""
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            elif len(self._cache) >= self.max_entries:
                # Evict the oldest (first) entry
                evicted_key, _ = self._cache.popitem(last=False)
                logger.debug("Cache eviction (LRU): %s", evicted_key)

            self._cache[key] = {"value": value, "ts": time.monotonic()}

    def invalidate(self, key: str) -> bool:
        """Remove a specific key. Returns True if the key existed."""
        with self._lock:
            existed = key in self._cache
            self._cache.pop(key, None)
            return existed

    def clear(self) -> None:
        """Remove all entries and reset stats."""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0

    def stats(self) -> Dict[str, Any]:
        """Return cache statistics for the /metrics endpoint."""
        with self._lock:
            total = self._hits + self._misses
            return {
                "size": len(self._cache),
                "max_entries": self.max_entries,
                "ttl_seconds": self.ttl_seconds,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": round(self._hits / total, 4) if total else 0.0,
            }
