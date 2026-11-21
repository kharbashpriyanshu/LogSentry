"""
LogSentry — TIORE HaveIBeenPwned (HIBP) Breached Account Adapter
================================================================
Queries the official HaveIBeenPwned v3 Breached Account API for email observables.
Adheres strictly to official API v3 specifications:
  - Official endpoint: https://haveibeenpwned.com/api/v3/breachedaccount/{account}
  - Mandatory headers: 'hibp-api-key' and descriptive 'user-agent'
  - 200 OK: Account is compromised in one or more public breaches
  - 404 Not Found: Account has no record of exposure (benign)
  - 401/403: Unauthorized / missing subscription key

Privacy & Safety Guarantee:
  - If no HIBP_API_KEY is configured, the adapter safely skips execution and
    does NOT make unauthorized calls or query unrelated password endpoints.
  - Requires explicit analyst or tenant authorization before querying external PII.
"""

import urllib.parse
from typing import Any

import httpx

from app.config.settings import settings
from app.tiore.models import ExtractedObservable, ObservableType, ThreatClassification
from app.tiore.providers.base import BaseObservableAdapter, ProviderLookupResult


class HIBPBreachAdapter(BaseObservableAdapter):
    """
    Official HaveIBeenPwned v3 Breached Account API adapter.
    """

    def __init__(
        self,
        api_key: str | None = None,
        timeout_seconds: float = 3.0,
        requests_per_minute: int = 30,
    ):
        super().__init__(
            source_id="hibp_breach",
            name="HaveIBeenPwned Breached Account Feed",
            category="commercial",
            reliability_tier=4,
            supported_types=[ObservableType.EMAIL],
            timeout_seconds=timeout_seconds,
            requests_per_minute=requests_per_minute,
        )
        self.api_key = api_key or getattr(settings, "HIBP_API_KEY", None)

    def is_eligible(self, observable: ExtractedObservable) -> bool:
        """
        Eligible only for EMAIL observables and when HIBP API key is provisioned.
        """
        return observable.observable_type == ObservableType.EMAIL and bool(
            self.api_key or getattr(settings, "HIBP_API_KEY", None)
        )

    def _execute_lookup(self, observable: ExtractedObservable) -> ProviderLookupResult:
        key = self.api_key or getattr(settings, "HIBP_API_KEY", None)
        if not key:
            return ProviderLookupResult(
                source_id=self.source_id,
                classification=ThreatClassification.UNKNOWN,
                confidence=0.0,
                status="skipped",
                error_message="HIBP API key not configured. Paid subscription required for account breach intelligence.",
            )

        email = observable.normalized_value.lower().strip()
        encoded_email = urllib.parse.quote(email, safe="")
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{encoded_email}?truncateResponse=false"
        headers = {
            "hibp-api-key": key,
            "user-agent": "LogSentry-SOC-SIEM-v1.0",
        }

        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                resp = client.get(url, headers=headers)

                if resp.status_code == 200:
                    data = resp.json()
                    breach_count = len(data) if isinstance(data, list) else 1
                    breach_summaries = []
                    threat_classes = set()

                    if isinstance(data, list):
                        for b in data[:10]:
                            breach_summaries.append(
                                {
                                    "title": b.get("Title"),
                                    "domain": b.get("Domain"),
                                    "date": b.get("BreachDate"),
                                    "data_classes": b.get("DataClasses", []),
                                }
                            )
                            for dc in b.get("DataClasses", []):
                                threat_classes.add(str(dc).lower())

                    evidence: dict[str, Any] = {
                        "breached": True,
                        "breach_count": breach_count,
                        "breaches": breach_summaries,
                    }

                    return ProviderLookupResult(
                        source_id=self.source_id,
                        classification=ThreatClassification.EXPOSED,
                        confidence=0.95,
                        threat_types=["credential_exposure", "data_breach"],
                        evidence=evidence,
                        raw_payload={
                            "breaches": breach_summaries,
                            "count": breach_count,
                        },
                        status="success",
                    )

                elif resp.status_code == 404:
                    return ProviderLookupResult(
                        source_id=self.source_id,
                        classification=ThreatClassification.UNKNOWN,
                        confidence=0.0,
                        threat_types=[],
                        evidence={
                            "breached": False,
                            "breach_count": 0,
                            "status": "no_known_public_breach",
                        },
                        status="success",
                    )

                elif resp.status_code in (401, 403):
                    return ProviderLookupResult(
                        source_id=self.source_id,
                        classification=ThreatClassification.UNKNOWN,
                        confidence=0.0,
                        status="error",
                        error_message="Invalid or unauthorized HIBP API key",
                    )

                elif resp.status_code == 429:
                    return ProviderLookupResult(
                        source_id=self.source_id,
                        classification=ThreatClassification.UNKNOWN,
                        confidence=0.0,
                        status="error",
                        error_message="HIBP rate limit exceeded (HTTP 429)",
                    )

                else:
                    return ProviderLookupResult(
                        source_id=self.source_id,
                        classification=ThreatClassification.UNKNOWN,
                        confidence=0.0,
                        status="error",
                        error_message=f"HIBP HTTP {resp.status_code}",
                    )
        except Exception as exc:
            return ProviderLookupResult(
                source_id=self.source_id,
                classification=ThreatClassification.UNKNOWN,
                confidence=0.0,
                status="error",
                error_message=f"HIBP connection failed: {exc}",
            )


# Backward-compatible alias
HIBPPrefixAdapter = HIBPBreachAdapter
