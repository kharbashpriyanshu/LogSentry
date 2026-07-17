from abc import ABC, abstractmethod
from typing import Optional
from app.schemas.detection_alert import DetectionAlert
from app.enrichment.models import ThreatEnrichment

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
    def enrich(self, alert: DetectionAlert) -> Optional[ThreatEnrichment]:
        """
        Enriches the alert with threat intelligence.
        Returns a ThreatEnrichment object, or None if no enrichment was possible or applicable.
        """
        pass
