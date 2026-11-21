"""
LogSentry — TIORE AbuseIPDB Provider Adapter
============================================
Checks IPv4 and IPv6 reputation against the AbuseIPDB REST API v2.
"""

from typing import Any

import httpx

from app.config.settings import settings
from app.tiore.models import ExtractedObservable, ObservableType, ThreatClassification
from app.tiore.providers.base import BaseObservableAdapter, ProviderLookupResult


class AbuseIPDBAdapter(BaseObservableAdapter):
    def __init__(
        self,
        api_key: str | None = None,
        timeout_seconds: float = 3.0,
        requests_per_minute: int = 60,
    ):
        super().__init__(
            source_id="abuseipdb",
            name="AbuseIPDB Threat Intelligence",
            category="commercial",
            reliability_tier=1,
            supported_types=[ObservableType.IPV4, ObservableType.IPV6],
            timeout_seconds=timeout_seconds,
            requests_per_minute=requests_per_minute,
        )
        self.api_key = api_key or getattr(settings, "ABUSEIPDB_API_KEY", "")

    def _execute_lookup(self, observable: ExtractedObservable) -> ProviderLookupResult:
        if not self.api_key or self.api_key in ("mock", "test", ""):
            # Graceful unconfigured response or mock fixture in dev
            return ProviderLookupResult(
                source_id=self.source_id,
                classification=ThreatClassification.UNKNOWN,
                confidence=0.0,
                status="unconfigured",
                error_message="AbuseIPDB API key not configured.",
            )

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": observable.normalized_value,
            "maxAgeInDays": 90,
            "verbose": True,
        }

        with httpx.Client(timeout=self.timeout_seconds) as client:
            resp = client.get(url, headers=headers, params=params)

            if resp.status_code == 429:
                return ProviderLookupResult(
                    source_id=self.source_id,
                    classification=ThreatClassification.UNKNOWN,
                    confidence=0.0,
                    status="rate_limited",
                    error_message="AbuseIPDB rate limit exceeded.",
                )

            if resp.status_code != 200:
                return ProviderLookupResult(
                    source_id=self.source_id,
                    classification=ThreatClassification.UNKNOWN,
                    confidence=0.0,
                    status="error",
                    error_message=f"AbuseIPDB HTTP {resp.status_code}: {resp.text[:200]}",
                )

            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            reports_count = data.get("totalReports", 0)
            country = data.get("countryCode")
            isp = data.get("isp")
            usage_type = data.get("usageType")

            threat_types: list[str] = []
            if score >= 75:
                classification = ThreatClassification.MALICIOUS
                confidence = round(score / 100.0, 2)
                threat_types = ["abuse_ip", "active_attacker"]
            elif score >= 20:
                classification = ThreatClassification.SUSPICIOUS
                confidence = round(score / 100.0, 2)
                threat_types = ["suspicious_probe"]
            else:
                classification = ThreatClassification.BENIGN
                confidence = 0.90

            evidence: dict[str, Any] = {
                "abuse_score": score,
                "reports_count": reports_count,
                "country": country,
                "isp": isp,
                "usage_type": usage_type,
            }

            return ProviderLookupResult(
                source_id=self.source_id,
                classification=classification,
                confidence=confidence,
                threat_types=threat_types,
                evidence=evidence,
                raw_payload={"data": data},
                status="success",
            )
