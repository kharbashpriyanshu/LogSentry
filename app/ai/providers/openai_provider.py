import httpx
import json
import logging
from app.ai.providers.base_provider import BaseAIProvider
from app.schemas.detection_alert import DetectionAlert
from app.ai.models import AIAnalysisResponse
from app.ai.prompts import SOC_ANALYST_SYSTEM_PROMPT, SOC_ANALYST_USER_PROMPT_TEMPLATE
from app.config.settings import settings
from app.ai.exceptions import (
    AIProviderUnavailableError, AITimeoutError, 
    AIRateLimitError, AIInvalidResponseError
)

logger = logging.getLogger(__name__)

class OpenAIProvider(BaseAIProvider):
    def __init__(self):
        self.api_key = settings.OPENAI_API_KEY
        self.model = settings.AI_MODEL_NAME
        self.base_url = "https://api.openai.com/v1"
        self.timeout = settings.AI_REQUEST_TIMEOUT
        
    @property
    def provider_name(self) -> str:
        return "openai"

    def health(self) -> bool:
        if not self.api_key:
            return False
        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.get(
                    f"{self.base_url}/models",
                    headers={"Authorization": f"Bearer {self.api_key}"}
                )
                return res.status_code == 200
        except Exception:
            return False

    def analyze_alert(self, alert: DetectionAlert) -> AIAnalysisResponse:
        if not self.api_key:
            raise AIProviderUnavailableError("OpenAI API key is missing. Configure OPENAI_API_KEY.")
            
        user_prompt = SOC_ANALYST_USER_PROMPT_TEMPLATE.format(
            alert_id=alert.alert_id,
            timestamp=alert.timestamp.isoformat(),
            rule_name=alert.rule_name,
            attack_type=alert.attack_type,
            severity=alert.severity.value,
            source_ip=alert.source_ip,
            endpoint=alert.endpoint,
            evidence=json.dumps(alert.evidence)
        )
        
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SOC_ANALYST_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": settings.AI_TEMPERATURE,
            "max_tokens": settings.AI_MAX_TOKENS,
            "response_format": {"type": "json_object"}
        }
        
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(
                    f"{self.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json"
                    },
                    json=payload
                )
                
            if response.status_code == 429:
                raise AIRateLimitError("OpenAI rate limit exceeded.")
            elif response.status_code != 200:
                logger.error(f"OpenAI error: {response.text}")
                raise AIProviderUnavailableError(f"OpenAI API returned {response.status_code}")
                
            data = response.json()
            content = data["choices"][0]["message"]["content"]
            
            # Log usage but NEVER log keys or prompt text
            usage = data.get("usage", {})
            logger.info(f"OpenAI usage: {usage.get('total_tokens', 0)} tokens")
            
            return AIAnalysisResponse.model_validate_json(content)
            
        except httpx.TimeoutException:
            raise AITimeoutError("OpenAI API request timed out.")
        except httpx.RequestError as e:
            raise AIProviderUnavailableError(f"Failed to connect to OpenAI: {e}")
        except Exception as e:
            raise AIInvalidResponseError(f"Failed to parse OpenAI response: {e}")
