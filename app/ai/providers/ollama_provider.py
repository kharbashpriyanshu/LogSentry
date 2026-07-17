import logging
from app.ai.providers.base_provider import BaseAIProvider
from app.schemas.detection_alert import DetectionAlert
from app.ai.models import AIAnalysisResponse
from app.ai.exceptions import AIProviderUnavailableError

logger = logging.getLogger(__name__)

class OllamaProvider(BaseAIProvider):
    @property
    def provider_name(self) -> str:
        return "ollama"

    def health(self) -> bool:
        return False

    def analyze_alert(self, alert: DetectionAlert) -> AIAnalysisResponse:
        raise AIProviderUnavailableError("Ollama provider is not yet fully implemented.")
