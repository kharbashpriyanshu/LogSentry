import logging

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

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
    # Security & Authentication
    # ---------------------------------------------------------------------------
    SECRET_KEY: str = Field(
        default="logsentry-insecure-dev-secret-key-min-32-chars-2026!",
        description="Cryptographic signing key for JWT tokens and internal HMACs",
    )
    AUTH_TOKEN_EXPIRE_MINUTES: int = Field(
        default=120,
        description="JWT access token expiration lifetime in minutes",
    )
    AUTH_STRICT_MODE: bool = Field(
        default=False,
        description="When True, enforces signed JWT Bearer authentication for all endpoints",
    )
    INITIAL_ADMIN_USERNAME: str = Field(
        default="admin",
        description="Default administrator username provisioned at initial bootstrap",
    )
    INITIAL_ADMIN_PASSWORD: str = Field(
        default="admin",
        description="Default administrator bootstrap password",
    )
    # Maximum allowed request body size in bytes (1 MB)
    MAX_REQUEST_SIZE_BYTES: int = 1 * 1024 * 1024
    # Maximum file upload size in bytes (10 MB)
    MAX_UPLOAD_SIZE_BYTES: int = 10 * 1024 * 1024
    # Allowed CORS origins — empty list = deny all (override in production)
    CORS_ALLOWED_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]
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
    DATABASE_URI: str | None = None

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
    DETECTION_DIR_ENUM_THRESHOLD: int = 3
    DETECTION_DIR_ENUM_WINDOW_SECONDS: int = 60
    DETECTION_ENABLED_RULES: list[str] = [
        "sqli",
        "xss",
        "path_traversal",
        "cmd_injection",
        "dir_enum",
        "brute_force",
    ]
    DETECTION_DEFAULT_CONFIDENCE: float = 0.8

    # ---------------------------------------------------------------------------
    # AI
    # ---------------------------------------------------------------------------
    AI_PROVIDER: str = "openai"
    OPENAI_API_KEY: str | None = None
    GEMINI_API_KEY: str | None = None
    OLLAMA_URL: str = "http://localhost:11434"
    AI_MODEL_NAME: str = "gpt-4-turbo"
    AI_REQUEST_TIMEOUT: int = 30
    AI_TEMPERATURE: float = 0.2
    AI_MAX_TOKENS: int = 1500

    # ---------------------------------------------------------------------------
    # Threat Intelligence & Observable Reputation (TIORE)
    # ---------------------------------------------------------------------------
    ABUSEIPDB_API_KEY: str | None = None
    OTX_API_KEY: str | None = None
    VIRUSTOTAL_API_KEY: str | None = None
    HIBP_API_KEY: str | None = None
    PII_ENCRYPTION_KEY: str | None = None
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
            raise ValueError(
                f"DETECTION_DEFAULT_CONFIDENCE must be in [0.0, 1.0], got {v}"
            )
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
        """Enforce stricter security requirements when ENVIRONMENT in (production, staging)."""
        insecure_secrets = {
            "logsentry-insecure-dev-secret-key-min-32-chars-2026!",
            "CHANGE_ME_GENERATE_HIGH_ENTROPY_HEX_SECRET_MIN_32_CHARS",
            "logsentry-enterprise-soc-jwt-secret-key-2026",
        }
        insecure_passwords = {
            "admin",
            "password",
            "123456",
            "admin123",
            "LogSentry#Admin2026!Enterprise",
            "CHANGE_ME_GENERATE_STRONG_RANDOM_ADMIN_PASSWORD",
        }

        if self.ENVIRONMENT in ("production", "staging"):
            self.AUTH_STRICT_MODE = True

            if (
                not self.SECRET_KEY
                or self.SECRET_KEY in insecure_secrets
                or "CHANGE_ME" in self.SECRET_KEY
            ):
                raise ValueError(
                    f"SECRET_KEY must be set to a secure, randomly generated secret in {self.ENVIRONMENT}. "
                    "Default development secret key is strictly prohibited."
                )
            if len(self.SECRET_KEY) < 32:
                raise ValueError(
                    f"SECRET_KEY length must be at least 32 characters in {self.ENVIRONMENT} (got {len(self.SECRET_KEY)})."
                )

            if (
                not self.INITIAL_ADMIN_PASSWORD
                or self.INITIAL_ADMIN_PASSWORD in insecure_passwords
                or "CHANGE_ME" in self.INITIAL_ADMIN_PASSWORD
                or len(self.INITIAL_ADMIN_PASSWORD) < 12
            ):
                raise ValueError(
                    f"INITIAL_ADMIN_PASSWORD must be a strong unique credential (>= 12 characters) in {self.ENVIRONMENT}. "
                    "Default or known example passwords are strictly prohibited."
                )

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
