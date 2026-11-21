"""
LogSentry — TIORE URLhaus Provider Adapter
=========================================
Checks URLs and hostnames against abuse.ch URLhaus malware repository.
"""

from typing import Any
import httpx

from app.tiore.models import ExtractedObservable, ObservableType, ThreatClassification
from app.tiore.providers.base import BaseObservableAdapter, ProviderLookupResult


class URLhausAdapter(BaseObservableAdapter):
    def __init__(
        self,
        timeout_seconds: float = 3.0,
        requests_per_minute: int = 120,
    ):
        super().__init__(
            source_id="urlhaus",
            name="abuse.ch URLhaus Feed",
            category="open_source",
            reliability_tier=1,
            supported_types=[ObservableType.URL, ObservableType.DOMAIN],
            timeout_seconds=timeout_seconds,
            requests_per_minute=requests_per_minute,
        )

    def _execute_lookup(self, observable: ExtractedObservable) -> ProviderLookupResult:
        if observable.observable_type == ObservableType.URL:
            api_url = "https://urlhaus-api.abuse.ch/v1/url/"
            data_payload = {"url": observable.normalized_value}
        else:
            api_url = "https://urlhaus-api.abuse.ch/v1/host/"
            data_payload = {"host": observable.normalized_value}

        with httpx.Client(timeout=self.timeout_seconds) as client:
            resp = client.post(api_url, data=data_payload)

            if resp.status_code != 200:
                return ProviderLookupResult(
                    source_id=self.source_id,
                    classification=ThreatClassification.UNKNOWN,
                    confidence=0.0,
                    status="error",
                    error_message=f"URLhaus HTTP {resp.status_code}",
                )

            data = resp.json()
            query_status = data.get("query_status")

            if query_status in ("no_results", "not_found"):
                return ProviderLookupResult(
                    source_id=self.source_id,
                    classification=ThreatClassification.BENIGN,
                    confidence=0.85,
                    status="not_found",
                    threat_types=[],
                    evidence={"query_status": query_status},
                )

            if query_status == "ok":
                threat = data.get("threat") or "malware_download"
                url_status = data.get("url_status", "unknown")
                tags = data.get("tags") or []
                threat_types = list(set([threat] + tags))

                evidence: dict[str, Any] = {
                    "url_status": url_status,
                    "threat": threat,
                    "tags": tags,
                    "reporter": data.get("reporter"),
                }

                return ProviderLookupResult(
                    source_id=self.source_id,
                    classification=ThreatClassification.MALICIOUS,
                    confidence=0.98,
                    threat_types=threat_types,
                    evidence=evidence,
                    raw_payload=data,
                    status="success",
                )

            return ProviderLookupResult(
                source_id=self.source_id,
                classification=ThreatClassification.UNKNOWN,
                confidence=0.0,
                status="error",
                error_message=f"URLhaus returned query status: {query_status}",
            )
