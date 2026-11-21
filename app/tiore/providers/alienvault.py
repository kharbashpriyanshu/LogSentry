"""
LogSentry — TIORE AlienVault OTX Provider Adapter
=================================================
Checks multi-indicator reputation against AlienVault Open Threat Exchange (OTX).
"""

from typing import Any
import httpx

from app.config.settings import settings
from app.tiore.models import ExtractedObservable, ObservableType, ThreatClassification
from app.tiore.providers.base import BaseObservableAdapter, ProviderLookupResult


class AlienVaultOTXAdapter(BaseObservableAdapter):
    def __init__(
        self,
        api_key: str | None = None,
        timeout_seconds: float = 3.0,
        requests_per_minute: int = 60,
    ):
        super().__init__(
            source_id="alienvault_otx",
            name="AlienVault OTX Community Feed",
            category="community",
            reliability_tier=2,
            supported_types=[
                ObservableType.IPV4,
                ObservableType.IPV6,
                ObservableType.DOMAIN,
                ObservableType.URL,
                ObservableType.MD5,
                ObservableType.SHA1,
                ObservableType.SHA256,
            ],
            timeout_seconds=timeout_seconds,
            requests_per_minute=requests_per_minute,
        )
        self.api_key = api_key or getattr(settings, "OTX_API_KEY", "")

    def _get_section_for_type(self, obs_type: ObservableType) -> str:
        if obs_type in (ObservableType.IPV4, ObservableType.IPV6):
            return "IPv4" if obs_type == ObservableType.IPV4 else "IPv6"
        if obs_type == ObservableType.DOMAIN:
            return "domain"
        if obs_type == ObservableType.URL:
            return "url"
        return "file"

    def _execute_lookup(self, observable: ExtractedObservable) -> ProviderLookupResult:
        if not self.api_key or self.api_key in ("mock", "test", ""):
            return ProviderLookupResult(
                source_id=self.source_id,
                classification=ThreatClassification.UNKNOWN,
                confidence=0.0,
                status="unconfigured",
                error_message="AlienVault OTX API key not configured.",
            )

        section = self._get_section_for_type(observable.observable_type)
        url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{observable.normalized_value}/general"
        headers = {
            "X-OTX-API-KEY": self.api_key,
            "Accept": "application/json",
        }

        with httpx.Client(timeout=self.timeout_seconds) as client:
            resp = client.get(url, headers=headers)

            if resp.status_code == 404:
                return ProviderLookupResult(
                    source_id=self.source_id,
                    classification=ThreatClassification.BENIGN,
                    confidence=0.75,
                    status="not_found",
                    threat_types=[],
                    evidence={"pulse_count": 0},
                )

            if resp.status_code != 200:
                return ProviderLookupResult(
                    source_id=self.source_id,
                    classification=ThreatClassification.UNKNOWN,
                    confidence=0.0,
                    status="error",
                    error_message=f"OTX HTTP {resp.status_code}: {resp.text[:200]}",
                )

            data = resp.json()
            pulse_info = data.get("pulse_info", {})
            pulse_count = pulse_info.get("count", 0)
            pulses = pulse_info.get("pulses", [])

            tags: set[str] = set()
            for p in pulses[:5]:
                for tag in p.get("tags", []):
                    tags.add(tag.lower())

            threat_types = list(tags)[:5]
            if pulse_count >= 5:
                classification = ThreatClassification.MALICIOUS
                confidence = 0.90
            elif pulse_count >= 1:
                classification = ThreatClassification.SUSPICIOUS
                confidence = 0.75
            else:
                classification = ThreatClassification.BENIGN
                confidence = 0.80

            evidence: dict[str, Any] = {
                "pulse_count": pulse_count,
                "tags": threat_types,
                "asn": data.get("asn"),
                "country_name": data.get("country_name"),
            }

            return ProviderLookupResult(
                source_id=self.source_id,
                classification=classification,
                confidence=confidence,
                threat_types=threat_types,
                evidence=evidence,
                raw_payload={"pulse_count": pulse_count},
                status="success",
            )
