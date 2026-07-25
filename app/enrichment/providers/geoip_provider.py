import httpx
import logging
from typing import Optional
from app.enrichment.providers.base_provider import BaseThreatProvider
from app.schemas.detection_alert import DetectionAlert
from app.enrichment.models import ThreatEnrichment
from app.enrichment.exceptions import (
    ProviderUnavailableError, ProviderTimeoutError, MalformedResponseError
)
import ipaddress

logger = logging.getLogger(__name__)

class GeoIPProvider(BaseThreatProvider):
    def __init__(self):
        # We degrade gracefully to ip-api if no local maxmind db is provided
        self.base_url = "http://ip-api.com/json"
        self.timeout = 5.0
        
    @property
    def provider_name(self) -> str:
        return "geoip"

    def health(self) -> bool:
        # Since it's an external free API for this demonstration, it's generally healthy.
        # In a real environment, this checks MaxMind DB existence.
        return True

    def _is_valid_public_ip(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return not ip.is_private and not ip.is_loopback and not ip.is_multicast and not ip.is_reserved
        except ValueError:
            return False

    def enrich(self, alert: DetectionAlert) -> Optional[ThreatEnrichment]:
        if not alert.source_ip:
            return None
        return self.enrich_ioc(alert.source_ip)

    def enrich_ioc(self, observable: str) -> Optional[ThreatEnrichment]:
        if not self._is_valid_public_ip(observable):
            return None
            
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(f"{self.base_url}/{observable}")
                
            if response.status_code != 200:
                logger.error(f"GeoIP returned {response.status_code}")
                raise ProviderUnavailableError(f"GeoIP returned {response.status_code}")
                
            data = response.json()
            if data.get("status") == "fail":
                return None
                
            return ThreatEnrichment(
                provider=self.provider_name,
                country=data.get("countryCode"),
                isp=data.get("isp"),
                reputation="clean",
                confidence=0.0
            )
            
        except httpx.TimeoutException:
            raise ProviderTimeoutError("GeoIP request timed out")
        except httpx.RequestError as e:
            raise ProviderUnavailableError(f"GeoIP request failed: {e}")
        except ValueError as e:
            raise MalformedResponseError(f"GeoIP response malformed: {e}")
