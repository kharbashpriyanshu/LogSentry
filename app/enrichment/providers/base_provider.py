from abc import ABC, abstractmethod

from app.enrichment.models import ThreatEnrichment
from app.schemas.detection_alert import DetectionAlert


class BaseThreatProvider(ABC):
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Returns the name of the enrichment provider."""
        pass

    @abstractmethod
    def health(self) -> bool:
        """Returns True if the provider is healthy and ready."""
        pass

    @abstractmethod
    def enrich(self, alert: DetectionAlert) -> ThreatEnrichment | None:
        """
        Enriches the alert with threat intelligence.
        Returns a ThreatEnrichment object, or None if no enrichment was possible or applicable.
        """
        pass

    def enrich_ioc(self, observable: str) -> ThreatEnrichment | None:
        """
        Enriches a specific IOC (like IP or domain).
        Default implementation returns None.
        """
        return None
