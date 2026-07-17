import httpx
import logging
from typing import Optional
from app.enrichment.providers.base_provider import BaseThreatProvider
from app.schemas.detection_alert import DetectionAlert
from app.enrichment.models import ThreatEnrichment
from app.config.settings import settings
from app.enrichment.exceptions import (
    ProviderUnavailableError, ProviderTimeoutError, 
    ProviderRateLimitError, MalformedResponseError
)

logger = logging.getLogger(__name__)

class AbuseIPDBProvider(BaseThreatProvider):
    def __init__(self):
        self.api_key = settings.ABUSEIPDB_API_KEY
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.timeout = settings.ENRICHMENT_REQUEST_TIMEOUT
        
    @property
    def provider_name(self) -> str:
        return "abuseipdb"

    def health(self) -> bool:
        return bool(self.api_key) and settings.ENABLE_ABUSEIPDB

    def enrich(self, alert: DetectionAlert) -> Optional[ThreatEnrichment]:
        if not self.health():
            return None
            
        ip_to_check = alert.source_ip
        if not ip_to_check:
            return None
            
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(
                    f"{self.base_url}/check",
                    headers={"Key": self.api_key, "Accept": "application/json"},
                    params={"ipAddress": ip_to_check, "maxAgeInDays": 90}
                )
                
            if response.status_code == 429:
                raise ProviderRateLimitError("AbuseIPDB rate limit exceeded")
            elif response.status_code == 401 or response.status_code == 403:
                raise ProviderUnavailableError("AbuseIPDB authentication failed")
            elif response.status_code != 200:
                logger.error(f"AbuseIPDB returned {response.status_code}: {response.text}")
                raise ProviderUnavailableError(f"AbuseIPDB returned {response.status_code}")
                
            data = response.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            
            reputation = "malicious" if score > 50 else "suspicious" if score > 0 else "clean"
            
            return ThreatEnrichment(
                provider=self.provider_name,
                reputation=reputation,
                confidence=float(score) / 100.0,
                country=data.get("countryCode"),
                isp=data.get("isp"),
                ioc_tags=[data.get("domain")] if data.get("domain") else []
            )
            
        except httpx.TimeoutException:
            raise ProviderTimeoutError("AbuseIPDB request timed out")
        except httpx.RequestError as e:
            raise ProviderUnavailableError(f"AbuseIPDB request failed: {e}")
        except ValueError as e:
            raise MalformedResponseError(f"AbuseIPDB response malformed: {e}")
