from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional, List

class Settings(BaseSettings):
    # App Settings
    PROJECT_NAME: str = "LogSentry SIEM"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"

    # Database Settings
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    POSTGRES_DB: str = "logsentry_db"
    POSTGRES_PORT: str = "5432"
    DATABASE_URI: Optional[str] = None

    # Logging Settings
    LOG_LEVEL: str = "INFO"
    LOG_FILE_PATH: str = "logs/logsentry.log"
    LOG_ROTATION: str = "500 MB"
    LOG_RETENTION: str = "10 days"
    
    # Detection Settings
    DETECTION_BRUTE_FORCE_THRESHOLD: int = 5
    DETECTION_BRUTE_FORCE_WINDOW_SECONDS: int = 60
    DETECTION_ENABLED_RULES: List[str] = ["sqli", "xss", "path_traversal", "cmd_injection", "dir_enum", "brute_force"]
    DETECTION_DEFAULT_CONFIDENCE: float = 0.8

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=True)

settings = Settings()
