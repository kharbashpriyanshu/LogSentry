import logging
from app.ai.providers.base_provider import BaseAIProvider
from app.schemas.detection_alert import DetectionAlert
from app.ai.models import AIAnalysisResponse
from app.ai.exceptions import AIProviderUnavailableError

logger = logging.getLogger(__name__)

class GeminiProvider(BaseAIProvider):
    @property
    def provider_name(self) -> str:
        return "gemini"

    def health(self) -> bool:
        return False

    def analyze_alert(self, alert: DetectionAlert) -> AIAnalysisResponse:
        raise AIProviderUnavailableError("Gemini provider is not yet fully implemented.")
