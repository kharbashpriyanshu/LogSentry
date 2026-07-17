from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator, model_validator
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables / .env file.

    Validation rules (enforced at startup — fail fast before accepting traffic):
      - ENVIRONMENT must be one of: development, staging, production
      - LOG_LEVEL must be a recognised Python logging level
      - AI_PROVIDER must be one of: openai, gemini, ollama
      - DETECTION_DEFAULT_CONFIDENCE must be in [0.0, 1.0]
      - AI_TEMPERATURE must be in [0.0, 2.0]
      - Production environments MUST have DATABASE_URI set
    """

    # ---------------------------------------------------------------------------
    # Core
    # ---------------------------------------------------------------------------
    PROJECT_NAME: str = "LogSentry SIEM"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"
    VERSION: str = "1.0.0"

    # ---------------------------------------------------------------------------
    # Security
    # ---------------------------------------------------------------------------
    # Maximum allowed request body size in bytes (1 MB)
    MAX_REQUEST_SIZE_BYTES: int = 1 * 1024 * 1024
    # Maximum file upload size in bytes (10 MB)
    MAX_UPLOAD_SIZE_BYTES: int = 10 * 1024 * 1024
    # Allowed CORS origins — empty list = deny all (override in production)
    CORS_ALLOWED_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:3000"]
    # API rate limit: requests per minute per IP (0 = disabled)
    RATE_LIMIT_RPM: int = 0

    # ---------------------------------------------------------------------------
    # Database
    # ---------------------------------------------------------------------------
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    POSTGRES_DB: str = "logsentry_db"
    POSTGRES_PORT: str = "5432"
    DATABASE_URI: Optional[str] = None

    # ---------------------------------------------------------------------------
    # Logging
    # ---------------------------------------------------------------------------
    LOG_LEVEL: str = "INFO"
    LOG_FILE_PATH: str = "logs/logsentry.log"

    # ---------------------------------------------------------------------------
    # Detection
    # ---------------------------------------------------------------------------
    DETECTION_BRUTE_FORCE_THRESHOLD: int = 5
    DETECTION_BRUTE_FORCE_WINDOW_SECONDS: int = 60
    DETECTION_ENABLED_RULES: List[str] = [
        "sqli", "xss", "path_traversal", "cmd_injection", "dir_enum", "brute_force"
    ]
    DETECTION_DEFAULT_CONFIDENCE: float = 0.8

    # ---------------------------------------------------------------------------
    # AI
    # ---------------------------------------------------------------------------
    AI_PROVIDER: str = "openai"
    OPENAI_API_KEY: Optional[str] = None
    GEMINI_API_KEY: Optional[str] = None
    OLLAMA_URL: str = "http://localhost:11434"
    AI_MODEL_NAME: str = "gpt-4-turbo"
    AI_REQUEST_TIMEOUT: int = 30
    AI_TEMPERATURE: float = 0.2
    AI_MAX_TOKENS: int = 1500

    # ---------------------------------------------------------------------------
    # Enrichment
    # ---------------------------------------------------------------------------
    ABUSEIPDB_API_KEY: Optional[str] = None
    OTX_API_KEY: Optional[str] = None
    ENRICHMENT_CACHE_TTL: int = 3600
    ENABLE_ABUSEIPDB: bool = True
    ENABLE_OTX: bool = True
    ENABLE_MITRE: bool = True
    ENRICHMENT_REQUEST_TIMEOUT: int = 10

    # ---------------------------------------------------------------------------
    # Validators
    # ---------------------------------------------------------------------------

    @field_validator("ENVIRONMENT")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        allowed = {"development", "staging", "production"}
        if v not in allowed:
            raise ValueError(f"ENVIRONMENT must be one of {allowed}, got '{v}'")
        return v

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        if v.upper() not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError(f"Invalid LOG_LEVEL: '{v}'")
        return v.upper()

    @field_validator("AI_PROVIDER")
    @classmethod
    def validate_ai_provider(cls, v: str) -> str:
        allowed = {"openai", "gemini", "ollama"}
        if v.lower() not in allowed:
            raise ValueError(f"AI_PROVIDER must be one of {allowed}, got '{v}'")
        return v.lower()

    @field_validator("DETECTION_DEFAULT_CONFIDENCE")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"DETECTION_DEFAULT_CONFIDENCE must be in [0.0, 1.0], got {v}")
        return v

    @field_validator("AI_TEMPERATURE")
    @classmethod
    def validate_temperature(cls, v: float) -> float:
        if not 0.0 <= v <= 2.0:
            raise ValueError(f"AI_TEMPERATURE must be in [0.0, 2.0], got {v}")
        return v

    @field_validator("MAX_REQUEST_SIZE_BYTES", "MAX_UPLOAD_SIZE_BYTES")
    @classmethod
    def validate_size_limits(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("Size limits must be positive integers.")
        return v

    @model_validator(mode="after")
    def validate_production_requirements(self) -> "Settings":
        """Enforce stricter requirements when ENVIRONMENT=production."""
        if self.ENVIRONMENT == "production":
            if not self.DATABASE_URI:
                raise ValueError(
                    "DATABASE_URI must be set when ENVIRONMENT=production. "
                    "Do not rely on default credentials in production."
                )
            if self.POSTGRES_PASSWORD == "postgres":
                logger.warning(
                    "⚠️  Default POSTGRES_PASSWORD detected in production environment. "
                    "Change immediately."
                )
        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",  # Silently ignore unknown env vars (prevents startup failures)
    )


# Module-level singleton — validated at import time (fail-fast)
settings = Settings()
