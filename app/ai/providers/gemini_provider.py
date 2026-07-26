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

# Gemini REST API v1beta — no SDK required
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
GEMINI_MODEL = "gemini-2.5-flash"


class GeminiProvider(BaseAIProvider):
    def __init__(self):
        self.api_key = settings.GEMINI_API_KEY
        self.timeout = settings.AI_REQUEST_TIMEOUT
        self.temperature = settings.AI_TEMPERATURE
        self.max_tokens = settings.AI_MAX_TOKENS

    @property
    def provider_name(self) -> str:
        return "gemini"

    def health(self) -> bool:
        if not self.api_key:
            return False
        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.get(
                    f"{GEMINI_BASE_URL}/models",
                    params={"key": self.api_key}
                )
                return res.status_code == 200
        except Exception:
            return False

    def analyze_alert(self, alert: DetectionAlert) -> AIAnalysisResponse:
        if not self.api_key:
            raise AIProviderUnavailableError(
                "Gemini API key is missing. Set GEMINI_API_KEY in .env."
            )

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

        # Gemini uses a single "contents" array; system instruction is separate
        payload = {
            "system_instruction": {
                "parts": [{"text": SOC_ANALYST_SYSTEM_PROMPT}]
            },
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": user_prompt}]
                }
            ],
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": self.max_tokens,
                "responseMimeType": "application/json",
            }
        }

        url = f"{GEMINI_BASE_URL}/models/{GEMINI_MODEL}:generateContent"

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(
                    url,
                    params={"key": self.api_key},
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )

            if response.status_code == 429:
                raise AIRateLimitError("Gemini rate limit exceeded. Retry after a moment.")
            elif response.status_code == 401 or response.status_code == 403:
                raise AIProviderUnavailableError(
                    f"Gemini authentication failed (HTTP {response.status_code}). "
                    "Verify GEMINI_API_KEY."
                )
            elif response.status_code != 200:
                logger.error(f"Gemini error {response.status_code}: {response.text[:500]}")
                raise AIProviderUnavailableError(
                    f"Gemini API returned HTTP {response.status_code}."
                )

            data = response.json()

            # Extract content from Gemini response structure
            try:
                content = data["candidates"][0]["content"]["parts"][0]["text"]
            except (KeyError, IndexError) as e:
                logger.error(f"Unexpected Gemini response structure: {data}")
                raise AIInvalidResponseError(
                    f"Could not extract text from Gemini response: {e}"
                )

            usage = data.get("usageMetadata", {})
            logger.info(
                f"Gemini usage: {usage.get('totalTokenCount', '?')} tokens "
                f"(in={usage.get('promptTokenCount','?')}, out={usage.get('candidatesTokenCount','?')})"
            )

            try:
                return AIAnalysisResponse.model_validate_json(content)
            except Exception as parse_err:
                logger.error(f"Failed to parse Gemini JSON response: {parse_err}\nContent: {content[:500]}")
                raise AIInvalidResponseError(
                    f"Gemini returned valid JSON but it did not match the expected schema: {parse_err}"
                )

        except httpx.TimeoutException:
            raise AITimeoutError(
                f"Gemini API request timed out after {self.timeout}s."
            )
        except httpx.RequestError as e:
            raise AIProviderUnavailableError(
                f"Network error connecting to Gemini: {e}"
            )
        except (AIRateLimitError, AIProviderUnavailableError, AITimeoutError, AIInvalidResponseError):
            raise
        except Exception as e:
            raise AIInvalidResponseError(f"Unexpected error in Gemini provider: {e}")
