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

class OTXProvider(BaseThreatProvider):
    def __init__(self):
        self.api_key = settings.OTX_API_KEY
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.timeout = settings.ENRICHMENT_REQUEST_TIMEOUT
        
    @property
    def provider_name(self) -> str:
        return "otx"

    def health(self) -> bool:
        return bool(self.api_key) and settings.ENABLE_OTX

    def enrich(self, alert: DetectionAlert) -> Optional[ThreatEnrichment]:
        if not alert.source_ip:
            return None
        return self.enrich_ioc(alert.source_ip)
        
    def _is_valid_observable(self, obs: str) -> bool:
        # Check if it's an IP
        import ipaddress
        try:
            ip = ipaddress.ip_address(obs)
            return not ip.is_private and not ip.is_loopback and not ip.is_multicast and not ip.is_reserved
        except ValueError:
            # Maybe domain or hash, we will allow basic domains for OTX
            import re
            domain_regex = re.compile(
                r'^(?:[a-zA-Z0-9]'
                r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
                r'[a-zA-Z]{2,6}$'
            )
            hash_regex = re.compile(r'^[a-fA-F0-9]{32,64}$')
            return bool(domain_regex.match(obs) or hash_regex.match(obs))

    def enrich_ioc(self, observable: str) -> Optional[ThreatEnrichment]:
        if not self.health():
            return None
            
        if not self._is_valid_observable(observable):
            return None
            
        # Determine indicator type for OTX url (IPv4, domain, file)
        import ipaddress
        try:
            ipaddress.ip_address(observable)
            ind_type = "IPv4"
        except ValueError:
            ind_type = "domain" if "." in observable else "file"
            
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(
                    f"{self.base_url}/indicators/{ind_type}/{observable}/general",
                    headers={"X-OTX-API-KEY": self.api_key}
                )
                
            if response.status_code == 429:
                raise ProviderRateLimitError("OTX rate limit exceeded")
            elif response.status_code == 401 or response.status_code == 403:
                raise ProviderUnavailableError("OTX authentication failed")
            elif response.status_code == 404:
                # Not found is okay, just no enrichment
                return None
            elif response.status_code != 200:
                logger.error(f"OTX returned {response.status_code}: {response.text}")
                raise ProviderUnavailableError(f"OTX returned {response.status_code}")
                
            data = response.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            
            reputation = "malicious" if pulse_count > 5 else "suspicious" if pulse_count > 0 else "clean"
            
            tags = set()
            for pulse in data.get("pulse_info", {}).get("pulses", []):
                for tag in pulse.get("tags", []):
                    tags.add(str(tag))
            
            return ThreatEnrichment(
                provider=self.provider_name,
                reputation=reputation,
                pulse_count=pulse_count,
                ioc_tags=list(tags)[:10] # limit to top 10 tags
            )
            
        except httpx.TimeoutException:
            raise ProviderTimeoutError("OTX request timed out")
        except httpx.RequestError as e:
            raise ProviderUnavailableError(f"OTX request failed: {e}")
        except ValueError as e:
            raise MalformedResponseError(f"OTX response malformed: {e}")
