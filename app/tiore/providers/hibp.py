"""
LogSentry — TIORE HIBP k-Anonymity Prefix Adapter
=================================================
Performs privacy-preserving breach reputation checks on email observables.
Uses the mathematical k-anonymity model:
  1. Computes SHA-1 hash of normalized email.
  2. Sends ONLY the 5-character prefix to the API.
  3. Evaluates returned suffix list locally on the server.
Never discloses raw email addresses or complete hashes to external entities.
"""

import hashlib
from typing import Any
import httpx

from app.tiore.models import ExtractedObservable, ObservableType, ThreatClassification
from app.tiore.providers.base import BaseObservableAdapter, ProviderLookupResult


class HIBPPrefixAdapter(BaseObservableAdapter):
    def __init__(
        self,
        timeout_seconds: float = 3.0,
        requests_per_minute: int = 60,
    ):
        super().__init__(
            source_id="hibp_prefix",
            name="HaveIBeenPwned k-Anonymity Feed",
            category="commercial",
            reliability_tier=2,
            supported_types=[ObservableType.EMAIL],
            timeout_seconds=timeout_seconds,
            requests_per_minute=requests_per_minute,
        )

    def is_eligible(self, observable: ExtractedObservable) -> bool:
        """
        Special eligibility exception for EMAIL observables:
        Permitted ONLY because this adapter uses k-anonymity 5-char prefix lookups.
        """
        return observable.observable_type == ObservableType.EMAIL

    def _execute_lookup(self, observable: ExtractedObservable) -> ProviderLookupResult:
        email = observable.normalized_value.lower()
        sha1_hash = hashlib.sha1(email.encode("utf-8")).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        headers = {
            "User-Agent": "LogSentry-SOC-TIORE-kAnonymity",
            "Add-Padding": "true",  # Defend against network traffic analysis
        }

        with httpx.Client(timeout=self.timeout_seconds) as client:
            resp = client.get(url, headers=headers)

            if resp.status_code != 200:
                return ProviderLookupResult(
                    source_id=self.source_id,
                    classification=ThreatClassification.UNKNOWN,
                    confidence=0.0,
                    status="error",
                    error_message=f"HIBP HTTP {resp.status_code}",
                )

            # Response format: SUFFIX:COUNT\r\n
            lines = resp.text.splitlines()
            breach_count = 0
            for line in lines:
                parts = line.split(":")
                if len(parts) == 2 and parts[0].strip().upper() == suffix:
                    try:
                        breach_count = int(parts[1].strip())
                    except ValueError:
                        breach_count = 1
                    break

            if breach_count > 0:
                evidence: dict[str, Any] = {
                    "breached": True,
                    "exposure_count": breach_count,
                    "k_anonymity_prefix": prefix,
                }
                return ProviderLookupResult(
                    source_id=self.source_id,
                    classification=ThreatClassification.EXPOSED,
                    confidence=0.95,
                    threat_types=["credential_exposure", "data_breach"],
                    evidence=evidence,
                    raw_payload={"prefix": prefix, "exposure_count": breach_count},
                    status="success",
                )

            return ProviderLookupResult(
                source_id=self.source_id,
                classification=ThreatClassification.BENIGN,
                confidence=0.85,
                threat_types=[],
                evidence={"breached": False, "k_anonymity_prefix": prefix},
                status="success",
            )
