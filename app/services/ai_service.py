import logging
import time
from app.ai.providers import BaseAIProvider
from app.schemas.detection_alert import DetectionAlert
from app.ai.models import AIAnalysisResponse
from app.ai.exceptions import AIError

logger = logging.getLogger(__name__)

class AIService:
    def __init__(self, provider: BaseAIProvider):
        self.provider = provider
        logger.info(f"AIService initialized with provider: {self.provider.provider_name}")
        
    def get_provider_name(self) -> str:
        return self.provider.provider_name
        
    def check_health(self) -> bool:
        start_time = time.time()
        is_healthy = self.provider.health()
        latency = (time.time() - start_time) * 1000
        logger.info(f"AI Provider '{self.provider.provider_name}' health check: {is_healthy} ({latency:.2f}ms)")
        return is_healthy

    def analyze(self, alert: DetectionAlert) -> AIAnalysisResponse:
        start_time = time.time()
        logger.info(f"Starting AI analysis for alert {alert.alert_id} using {self.provider.provider_name}")
        
        try:
            response = self.provider.analyze_alert(alert)
            latency = (time.time() - start_time) * 1000
            logger.info(f"AI analysis completed in {latency:.2f}ms")
            return response
        except AIError as e:
            latency = (time.time() - start_time) * 1000
            logger.error(f"AI Provider error during analysis ({latency:.2f}ms): {e}")
            raise
        except Exception as e:
            latency = (time.time() - start_time) * 1000
            logger.error(f"Unexpected error during AI analysis ({latency:.2f}ms): {e}", exc_info=True)
            raise
