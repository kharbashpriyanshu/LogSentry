"""
LogSentry — TIORE VirusTotal Provider Adapter
=============================================
Checks files, domains, IPs, and URLs against VirusTotal v3 REST API.
"""

import base64
from typing import Any
import httpx

from app.config.settings import settings
from app.tiore.models import ExtractedObservable, ObservableType, ThreatClassification
from app.tiore.providers.base import BaseObservableAdapter, ProviderLookupResult


class VirusTotalAdapter(BaseObservableAdapter):
    def __init__(
        self,
        api_key: str | None = None,
        timeout_seconds: float = 3.0,
        requests_per_minute: int = 4,  # Standard free tier is 4 requests/min
    ):
        super().__init__(
            source_id="virustotal",
            name="VirusTotal Intelligence",
            category="commercial",
            reliability_tier=1,
            supported_types=[
                ObservableType.MD5,
                ObservableType.SHA1,
                ObservableType.SHA256,
                ObservableType.DOMAIN,
                ObservableType.IPV4,
                ObservableType.URL,
            ],
            timeout_seconds=timeout_seconds,
            requests_per_minute=requests_per_minute,
        )
        self.api_key = api_key or getattr(settings, "VIRUSTOTAL_API_KEY", "")

    def _get_endpoint(self, observable: ExtractedObservable) -> str:
        obs_type = observable.observable_type
        val = observable.normalized_value

        if obs_type in (ObservableType.MD5, ObservableType.SHA1, ObservableType.SHA256):
            return f"https://www.virustotal.com/api/v3/files/{val}"
        if obs_type == ObservableType.DOMAIN:
            return f"https://www.virustotal.com/api/v3/domains/{val}"
        if obs_type == ObservableType.IPV4:
            return f"https://www.virustotal.com/api/v3/ip_addresses/{val}"
        # URL identifier in VT v3 is base64 urlsafe without padding
        url_id = base64.urlsafe_b64encode(val.encode()).decode().strip("=")
        return f"https://www.virustotal.com/api/v3/urls/{url_id}"

    def _execute_lookup(self, observable: ExtractedObservable) -> ProviderLookupResult:
        if not self.api_key or self.api_key in ("mock", "test", ""):
            return ProviderLookupResult(
                source_id=self.source_id,
                classification=ThreatClassification.UNKNOWN,
                confidence=0.0,
                status="unconfigured",
                error_message="VirusTotal API key not configured.",
            )

        endpoint = self._get_endpoint(observable)
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

        with httpx.Client(timeout=self.timeout_seconds) as client:
            resp = client.get(endpoint, headers=headers)

            if resp.status_code == 404:
                return ProviderLookupResult(
                    source_id=self.source_id,
                    classification=ThreatClassification.BENIGN,
                    confidence=0.80,
                    status="not_found",
                    threat_types=[],
                    evidence={"found": False},
                )

            if resp.status_code == 429:
                return ProviderLookupResult(
                    source_id=self.source_id,
                    classification=ThreatClassification.UNKNOWN,
                    confidence=0.0,
                    status="rate_limited",
                    error_message="VirusTotal rate limit exceeded.",
                )

            if resp.status_code != 200:
                return ProviderLookupResult(
                    source_id=self.source_id,
                    classification=ThreatClassification.UNKNOWN,
                    confidence=0.0,
                    status="error",
                    error_message=f"VirusTotal HTTP {resp.status_code}",
                )

            data = resp.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            threat_types: list[str] = []
            suggested_threat = attrs.get("popular_threat_classification", {}).get("suggested_threat_label")
            if suggested_threat:
                threat_types.append(suggested_threat.lower())

            if malicious >= 3:
                classification = ThreatClassification.MALICIOUS
                confidence = min(1.0, round(malicious / max(total, 1) + 0.5, 2))
            elif malicious > 0 or suspicious > 0:
                classification = ThreatClassification.SUSPICIOUS
                confidence = 0.75
            else:
                classification = ThreatClassification.BENIGN
                confidence = 0.90

            evidence: dict[str, Any] = {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "total_scanners": total,
                "suggested_threat": suggested_threat,
            }

            return ProviderLookupResult(
                source_id=self.source_id,
                classification=classification,
                confidence=confidence,
                threat_types=threat_types,
                evidence=evidence,
                raw_payload={"stats": stats},
                status="success",
            )
