"""Configuration settings with security-first defaults."""

from functools import lru_cache
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application
    APP_NAME: str = "Snapper"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "production"

    # Security - These are critical and must be set in production
    SECRET_KEY: str = Field(..., min_length=32)

    # Database
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://snapper:snapper@localhost:5432/snapper"
    )
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20
    DATABASE_QUERY_TIMEOUT: int = 30  # seconds

    # Redis
    REDIS_URL: str = Field(default="redis://localhost:6379/0")
    REDIS_MAX_CONNECTIONS: int = 50

    # Security Defaults - Fail-safe configuration
    DENY_BY_DEFAULT: bool = True  # Critical: deny unless explicitly allowed
    VALIDATE_WEBSOCKET_ORIGIN: bool = True  # CVE-2026-25253 mitigation
    REQUIRE_LOCALHOST_ONLY: bool = True  # Auth bypass mitigation

    # Allowed origins for WebSocket connections (CVE-2026-25253)
    ALLOWED_ORIGINS: str = Field(
        default="http://localhost:8000,http://127.0.0.1:8000"
    )

    # Allowed hosts for Host header validation
    ALLOWED_HOSTS: str = Field(
        default="localhost,127.0.0.1"
    )

    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_DEFAULT_MAX_REQUESTS: int = 100
    RATE_LIMIT_DEFAULT_WINDOW_SECONDS: int = 60

    # Circuit Breaker
    CIRCUIT_BREAKER_FAILURE_THRESHOLD: int = 5
    CIRCUIT_BREAKER_RECOVERY_TIMEOUT: int = 30  # seconds
    CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS: int = 3

    # Session
    SESSION_EXPIRE_SECONDS: int = 3600  # 1 hour

    # API
    API_V1_PREFIX: str = "/api/v1"

    # CORS
    CORS_ORIGINS: str = Field(
        default="http://localhost:8000,http://127.0.0.1:8000"
    )

    # Celery
    CELERY_BROKER_URL: str = Field(default="redis://localhost:6379/1")
    CELERY_RESULT_BACKEND: str = Field(default="redis://localhost:6379/2")

    # External APIs for security research
    NVD_API_KEY: Optional[str] = None
    GITHUB_TOKEN: Optional[str] = None
    CLAWHUB_API_URL: str = "https://api.clawhub.io/v1"

    # Alerting
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_FROM_EMAIL: str = "alerts@snapper.local"

    SLACK_WEBHOOK_URL: Optional[str] = None
    PAGERDUTY_API_KEY: Optional[str] = None
    GENERIC_WEBHOOK_URL: Optional[str] = None

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"

    @property
    def allowed_origins_list(self) -> List[str]:
        """Get allowed origins as a list."""
        return [item.strip() for item in self.ALLOWED_ORIGINS.split(",") if item.strip()]

    @property
    def allowed_hosts_list(self) -> List[str]:
        """Get allowed hosts as a list."""
        return [item.strip() for item in self.ALLOWED_HOSTS.split(",") if item.strip()]

    @property
    def cors_origins_list(self) -> List[str]:
        """Get CORS origins as a list."""
        return [item.strip() for item in self.CORS_ORIGINS.split(",") if item.strip()]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
