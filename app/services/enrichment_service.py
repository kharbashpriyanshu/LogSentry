import logging
import time
from typing import List, Dict, Any, Optional
from app.enrichment.providers.base_provider import BaseThreatProvider
from app.schemas.detection_alert import DetectionAlert
from app.enrichment.models import ThreatEnrichment
from app.enrichment.cache import InMemoryCache
from app.enrichment.exceptions import EnrichmentError
from app.config.settings import settings

logger = logging.getLogger(__name__)

class EnrichmentService:
    def __init__(self, providers: List[BaseThreatProvider], cache: InMemoryCache):
        self.providers = providers
        self.cache = cache
        logger.info(f"EnrichmentService initialized with {len(providers)} providers.")

    def get_providers_health(self) -> Dict[str, Any]:
        result = {}
        overall_health = True
        for p in self.providers:
            is_healthy = p.health()
            result[p.provider_name] = is_healthy
            if not is_healthy and getattr(settings, f"ENABLE_{p.provider_name.upper()}", False):
                overall_health = False
        return {
            "overall": overall_health,
            "providers": result
        }

    def enrich_alert(self, alert: DetectionAlert) -> List[ThreatEnrichment]:
        enrichments = []
        
        # We cache per alert indicator. 
        # Cache keys could be "ip:1.1.1.1" or "mitre:T1190"
        
        for provider in self.providers:
            if not provider.health():
                continue
                
            start_time = time.time()
            
            # Determine cache key based on provider type
            cache_key = None
            if provider.provider_name in ["abuseipdb", "otx"] and alert.source_ip:
                cache_key = f"{provider.provider_name}:ip:{alert.source_ip}"
            elif provider.provider_name == "mitre" and alert.mitre_technique:
                cache_key = f"{provider.provider_name}:mitre:{alert.mitre_technique}"
                
            if cache_key:
                cached_data = self.cache.get(cache_key)
                if cached_data:
                    latency = (time.time() - start_time) * 1000
                    logger.info(f"Cache hit for {cache_key} ({latency:.2f}ms)")
                    enrichments.append(cached_data)
                    continue
            
            try:
                result = provider.enrich(alert)
                latency = (time.time() - start_time) * 1000
                logger.info(f"Provider {provider.provider_name} completed in {latency:.2f}ms")
                
                if result:
                    enrichments.append(result)
                    if cache_key:
                        self.cache.set(cache_key, result)
            except EnrichmentError as e:
                latency = (time.time() - start_time) * 1000
                logger.error(f"Provider {provider.provider_name} failed ({latency:.2f}ms): {e}")
            except Exception as e:
                latency = (time.time() - start_time) * 1000
                logger.error(f"Unexpected error in {provider.provider_name} ({latency:.2f}ms): {e}", exc_info=True)
                
        return enrichments
