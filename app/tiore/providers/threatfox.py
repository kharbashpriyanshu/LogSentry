"""
LogSentry — TIORE ThreatFox Provider Adapter
============================================
Checks indicators of compromise against abuse.ch ThreatFox IOC platform.
"""

from typing import Any

import httpx

from app.tiore.models import ExtractedObservable, ObservableType, ThreatClassification
from app.tiore.providers.base import BaseObservableAdapter, ProviderLookupResult


class ThreatFoxAdapter(BaseObservableAdapter):
    def __init__(
        self,
        timeout_seconds: float = 3.0,
        requests_per_minute: int = 120,
    ):
        super().__init__(
            source_id="threatfox",
            name="abuse.ch ThreatFox Feed",
            category="open_source",
            reliability_tier=1,
            supported_types=[
                ObservableType.IPV4,
                ObservableType.DOMAIN,
                ObservableType.URL,
                ObservableType.MD5,
                ObservableType.SHA256,
            ],
            timeout_seconds=timeout_seconds,
            requests_per_minute=requests_per_minute,
        )

    def _execute_lookup(self, observable: ExtractedObservable) -> ProviderLookupResult:
        api_url = "https://threatfox-api.abuse.ch/api/v1/"
        payload = {
            "query": "search_ioc",
            "search_term": observable.normalized_value,
        }

        with httpx.Client(timeout=self.timeout_seconds) as client:
            resp = client.post(api_url, json=payload)

            if resp.status_code != 200:
                return ProviderLookupResult(
                    source_id=self.source_id,
                    classification=ThreatClassification.UNKNOWN,
                    confidence=0.0,
                    status="error",
                    error_message=f"ThreatFox HTTP {resp.status_code}",
                )

            data = resp.json()
            query_status = data.get("query_status")

            if query_status in ("no_result", "not_found"):
                return ProviderLookupResult(
                    source_id=self.source_id,
                    classification=ThreatClassification.BENIGN,
                    confidence=0.85,
                    status="not_found",
                    threat_types=[],
                    evidence={"query_status": query_status},
                )

            if query_status == "ok":
                items = data.get("data", [])
                threat_types: set[str] = set()
                max_confidence = 0.85

                for item in items[:5]:
                    malware = item.get("malware_printable")
                    if malware:
                        threat_types.add(malware.lower())
                    conf_level = item.get("confidence_level", 0)
                    if conf_level:
                        max_confidence = max(max_confidence, conf_level / 100.0)

                first_match = items[0] if items else {}
                evidence: dict[str, Any] = {
                    "threat_type": first_match.get("threat_type"),
                    "malware": first_match.get("malware_printable"),
                    "reporter": first_match.get("reporter"),
                    "tags": first_match.get("tags") or [],
                }

                return ProviderLookupResult(
                    source_id=self.source_id,
                    classification=ThreatClassification.MALICIOUS,
                    confidence=round(max_confidence, 2),
                    threat_types=list(threat_types),
                    evidence=evidence,
                    raw_payload={"matches_count": len(items)},
                    status="success",
                )

            return ProviderLookupResult(
                source_id=self.source_id,
                classification=ThreatClassification.UNKNOWN,
                confidence=0.0,
                status="error",
                error_message=f"ThreatFox returned status: {query_status}",
            )
