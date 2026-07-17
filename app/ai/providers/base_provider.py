from abc import ABC, abstractmethod
from app.schemas.detection_alert import DetectionAlert
from app.ai.models import AIAnalysisResponse

class BaseAIProvider(ABC):
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Returns the name of the AI provider."""
        pass

    @abstractmethod
    def analyze_alert(self, alert: DetectionAlert) -> AIAnalysisResponse:
        """Analyzes a detection alert and returns structured AI insights."""
        pass
        
    @abstractmethod
    def health(self) -> bool:
        """Returns True if the provider is reachable and healthy."""
        pass
