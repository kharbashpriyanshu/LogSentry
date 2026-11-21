"""
LogSentry — TIORE Base Provider Adapter (TIORE Phase 4)
======================================================
Defines unified interface for external threat intelligence feeds,
incorporating circuit breakers, rate limiting, strict privacy gating,
and latency boundaries (< 3.0s timeout).
"""

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
import threading
import time
from typing import Any

from app.tiore.models import (
    ExtractedObservable,
    ObservableType,
    PrivacyClassification,
    ThreatClassification,
)


class CircuitState(str, Enum):
    CLOSED = "closed"        # Healthy, normal operation
    OPEN = "open"            # Failing, requests blocked
    HALF_OPEN = "half_open"  # Probing single request for recovery


@dataclass
class ProviderLookupResult:
    source_id: str
    classification: ThreatClassification
    confidence: float
    threat_types: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    raw_payload: dict[str, Any] = field(default_factory=dict)
    status: str = "success"  # "success", "not_found", "rate_limited", "circuit_open", "error", "skipped", "unconfigured"
    error_message: str | None = None
    duration_ms: float = 0.0
    retrieved_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class BaseObservableAdapter(ABC):
    """
    Abstract base adapter for all threat intelligence providers.
    Enforces circuit breaking, timeout bounding, and privacy policies.
    """

    def __init__(
        self,
        source_id: str,
        name: str,
        category: str = "commercial",
        reliability_tier: int = 2,
        supported_types: list[ObservableType] | None = None,
        timeout_seconds: float = 3.0,
        failure_threshold: int = 5,
        recovery_timeout_sec: float = 60.0,
        requests_per_minute: int = 60,
    ):
        self.source_id = source_id
        self.name = name
        self.category = category
        self.reliability_tier = reliability_tier
        self.supported_types = supported_types or []
        self.timeout_seconds = timeout_seconds

        # Circuit breaker state
        self.failure_threshold = failure_threshold
        self.recovery_timeout_sec = recovery_timeout_sec
        self._circuit_state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._last_state_change = datetime.now(UTC)
        self._circuit_lock = threading.Lock()

        # Rate limiter state
        self.requests_per_minute = requests_per_minute
        self._request_timestamps: list[float] = []
        self._rate_lock = threading.Lock()

    # -------------------------------------------------------------------------
    # Circuit Breaker Mechanics
    # -------------------------------------------------------------------------

    def get_circuit_state(self) -> CircuitState:
        with self._circuit_lock:
            now = datetime.now(UTC)
            if self._circuit_state == CircuitState.OPEN:
                if now - self._last_state_change > timedelta(seconds=self.recovery_timeout_sec):
                    self._circuit_state = CircuitState.HALF_OPEN
                    self._last_state_change = now
            return self._circuit_state

    def record_success(self) -> None:
        with self._circuit_lock:
            self._consecutive_failures = 0
            if self._circuit_state != CircuitState.CLOSED:
                self._circuit_state = CircuitState.CLOSED
                self._last_state_change = datetime.now(UTC)

    def record_failure(self) -> None:
        with self._circuit_lock:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self.failure_threshold:
                self._circuit_state = CircuitState.OPEN
                self._last_state_change = datetime.now(UTC)

    # -------------------------------------------------------------------------
    # Rate Limiting
    # -------------------------------------------------------------------------

    def is_rate_limited(self) -> bool:
        with self._rate_lock:
            now = time.time()
            cutoff = now - 60.0
            # Evict timestamps older than 1 minute
            self._request_timestamps = [t for t in self._request_timestamps if t > cutoff]
            if len(self._request_timestamps) >= self.requests_per_minute:
                return True
            self._request_timestamps.append(now)
            return False

    # -------------------------------------------------------------------------
    # Privacy & Eligibility
    # -------------------------------------------------------------------------

    def is_eligible(self, observable: ExtractedObservable) -> bool:
        """
        Verifies indicator compatibility and privacy compliance before lookup.
        """
        if observable.observable_type not in self.supported_types:
            return False

        # If indicator is explicitly marked ineligible for external lookup (RFC 1918, metadata, internal domains)
        if not observable.is_eligible_for_external_lookup:
            return False

        # Only public routable indicators can be queried externally
        # (Exception: PII handled only by specialized k-anonymity prefix providers)
        if observable.privacy_classification != PrivacyClassification.PUBLIC_ROUTABLE:
            return False

        return True

    # -------------------------------------------------------------------------
    # Execution Lifecycle
    # -------------------------------------------------------------------------

    def lookup(self, observable: ExtractedObservable) -> ProviderLookupResult:
        start_time = time.time()

        # 1. Eligibility Check
        if not self.is_eligible(observable):
            return ProviderLookupResult(
                source_id=self.source_id,
                classification=ThreatClassification.UNKNOWN,
                confidence=0.0,
                status="skipped",
                error_message="Observable not eligible for external lookup under privacy boundary.",
                duration_ms=0.0,
            )

        # 2. Circuit Breaker Check
        state = self.get_circuit_state()
        if state == CircuitState.OPEN:
            return ProviderLookupResult(
                source_id=self.source_id,
                classification=ThreatClassification.UNKNOWN,
                confidence=0.0,
                status="circuit_open",
                error_message=f"Circuit breaker OPEN for provider {self.source_id} due to prior errors.",
                duration_ms=0.0,
            )

        # 3. Rate Limit Check
        if self.is_rate_limited():
            return ProviderLookupResult(
                source_id=self.source_id,
                classification=ThreatClassification.UNKNOWN,
                confidence=0.0,
                status="rate_limited",
                error_message=f"Provider {self.source_id} request quota exceeded ({self.requests_per_minute}/min).",
                duration_ms=0.0,
            )

        # 4. Execute Lookup
        try:
            result = self._execute_lookup(observable)
            self.record_success()
            result.duration_ms = round((time.time() - start_time) * 1000, 2)
            return result
        except Exception as e:
            self.record_failure()
            duration = round((time.time() - start_time) * 1000, 2)
            return ProviderLookupResult(
                source_id=self.source_id,
                classification=ThreatClassification.UNKNOWN,
                confidence=0.0,
                status="error",
                error_message=str(e),
                duration_ms=duration,
            )

    @abstractmethod
    def _execute_lookup(self, observable: ExtractedObservable) -> ProviderLookupResult:
        """Provider-specific external lookup logic."""
        pass
