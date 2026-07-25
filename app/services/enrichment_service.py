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

    def enrich_ioc(self, observable: str) -> "NormalizedThreatIntel":
        from app.enrichment.models import NormalizedThreatIntel, RiskScore, GeoData, ProviderStatus
        import ipaddress
        
        try:
            ipaddress.ip_address(observable)
            obs_type = "ip"
        except ValueError:
            obs_type = "domain" if "." in observable else "file"
            
        providers_status = []
        mitre_tags = set()
        ioc_tags = set()
        max_confidence = 0.0
        max_abuse_score = 0
        pulse_count = 0
        geo_data = GeoData()
        
        for provider in self.providers:
            if not provider.health():
                providers_status.append(ProviderStatus(name=provider.provider_name, status="inactive"))
                continue
                
            start_time = time.time()
            try:
                result = provider.enrich_ioc(observable)
                latency = (time.time() - start_time) * 1000
                if result:
                    providers_status.append(ProviderStatus(name=provider.provider_name, status="active", score=result.confidence * 100 if result.confidence else None, latency=latency))
                    
                    if result.confidence:
                        max_confidence = max(max_confidence, result.confidence)
                    if provider.provider_name == "abuseipdb" and result.confidence:
                        max_abuse_score = max(max_abuse_score, int(result.confidence * 100))
                    if result.pulse_count:
                        pulse_count = max(pulse_count, result.pulse_count)
                    if result.country:
                        geo_data.countryCode = result.country
                    if result.isp:
                        geo_data.isp = result.isp
                    if result.mitre_technique:
                        mitre_tags.add(result.mitre_technique)
                    for tag in result.ioc_tags:
                        ioc_tags.add(tag)
                else:
                    providers_status.append(ProviderStatus(name=provider.provider_name, status="active", latency=latency))
            except EnrichmentError as e:
                latency = (time.time() - start_time) * 1000
                providers_status.append(ProviderStatus(name=provider.provider_name, status="error", latency=latency))
                logger.error(f"Provider {provider.provider_name} failed on {observable}: {e}")
            except Exception as e:
                latency = (time.time() - start_time) * 1000
                providers_status.append(ProviderStatus(name=provider.provider_name, status="error", latency=latency))
                logger.error(f"Unexpected error in {provider.provider_name} on {observable}: {e}", exc_info=True)

        # Risk Calculation
        # AbuseIPDB weight: up to 100
        # OTX weight: 5 pulses -> ~50 score
        risk_score = max(max_abuse_score, min(100, pulse_count * 10))
        
        level = "low"
        if risk_score > 70:
            level = "critical"
        elif risk_score > 40:
            level = "high"
        elif risk_score > 10:
            level = "medium"
            
        return NormalizedThreatIntel(
            observable=observable,
            observable_type=obs_type,
            risk=RiskScore(score=risk_score, level=level),
            geo=geo_data,
            providers=providers_status,
            mitre=list(mitre_tags),
            ioc_tags=list(ioc_tags)[:20],
            cached=False
        )
