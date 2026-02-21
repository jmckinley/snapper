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
    DENY_BY_DEFAULT: bool = False  # False = learning mode (log only), True = enforce
    LEARNING_MODE: bool = True  # When true, log violations but don't block
    REQUIRE_API_KEY: bool = False  # Require API key for agent requests
    VALIDATE_WEBSOCKET_ORIGIN: bool = True  # CVE-2026-25253 mitigation
    REQUIRE_LOCALHOST_ONLY: bool = False  # Auth bypass mitigation (relaxed for beta)

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

    # Base URL for email links (password reset, invitations)
    BASE_URL: str = "https://app.snapperprotect.com"

    # Alerting
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_FROM_EMAIL: str = "alerts@snapper.local"

    SLACK_WEBHOOK_URL: Optional[str] = None
    SLACK_BOT_TOKEN: Optional[str] = None      # xoxb-... for Snapper's Slack app
    SLACK_APP_TOKEN: Optional[str] = None      # xapp-... for Socket Mode
    SLACK_ALERT_CHANNEL: Optional[str] = None  # Default channel ID for alerts (fallback)
    PAGERDUTY_API_KEY: Optional[str] = None
    GENERIC_WEBHOOK_URL: Optional[str] = None

    # Telegram - Popular with OpenClaw users
    TELEGRAM_BOT_TOKEN: Optional[str] = None
    TELEGRAM_CHAT_ID: Optional[str] = None  # Can be user ID or group chat ID

    # Notification preferences
    NOTIFY_ON_BLOCK: bool = True  # Send notification when action is blocked
    NOTIFY_ON_APPROVAL_REQUEST: bool = True  # Send notification for approval requests
    NOTIFY_ON_ALLOW: bool = False  # Send notification when action is allowed (verbose)

    # PII Vault
    PII_VAULT_TOKEN_TTL_SECONDS: int = 30  # Resolved value Redis TTL (one-time retrieval)
    REQUIRE_VAULT_AUTH: bool = False  # Require API key or internal source for vault writes

    # Account lockout
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 30

    # Audit retention
    AUDIT_RETENTION_DAYS: int = 90

    # Authentication (JWT)
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Multi-tenancy
    SELF_HOSTED: bool = False  # When true, bypasses all plan limits
    REGISTRATION_ENABLED: bool = True

    # Meta Admin
    META_ADMIN_ENABLED: bool = True
    META_ADMIN_IMPERSONATION_TIMEOUT_MINUTES: int = 60

    # Stripe billing
    STRIPE_SECRET_KEY: Optional[str] = None
    STRIPE_PUBLISHABLE_KEY: Optional[str] = None
    STRIPE_WEBHOOK_SECRET: Optional[str] = None
    STRIPE_PRICE_PRO_MONTHLY: Optional[str] = None
    STRIPE_PRICE_PRO_YEARLY: Optional[str] = None

    # Threat Detection
    THREAT_DETECTION_ENABLED: bool = True
    AUTO_MITIGATE_THREATS: bool = True  # Auto-mitigate new CVEs from threat feeds
    SECURITY_FEEDS_ENABLED: bool = True  # Disable for air-gapped deployments
    THREAT_DENY_THRESHOLD: float = 80.0
    THREAT_APPROVAL_THRESHOLD: float = 60.0
    THREAT_ALERT_THRESHOLD: float = 40.0
    THREAT_AUTO_QUARANTINE: bool = False
    THREAT_SIGNAL_STREAM_MAXLEN: int = 10000
    THREAT_BASELINE_WINDOW_DAYS: int = 7
    THREAT_SCORE_TTL_SECONDS: int = 300

    # AI Threat Review
    THREAT_AI_REVIEW_ENABLED: bool = False  # Requires ANTHROPIC_API_KEY
    ANTHROPIC_API_KEY: Optional[str] = None
    THREAT_AI_MODEL: str = "claude-sonnet-4-5-20250929"
    THREAT_AI_REVIEW_INTERVAL_SECONDS: int = 900  # 15 minutes
    THREAT_AI_MAX_EVENTS_PER_REVIEW: int = 50

    # Unknown agent protection
    UNKNOWN_AGENT_ALERT_THRESHOLD: int = 10       # Alert after N attempts in window
    UNKNOWN_AGENT_LOCKOUT_THRESHOLD: int = 20     # IP lockout after N attempts
    UNKNOWN_AGENT_LOCKOUT_SECONDS: int = 900      # 15min lockout
    UNKNOWN_AGENT_WINDOW_SECONDS: int = 300       # 5min sliding window

    # Auto-quarantine thresholds (THREAT_AUTO_QUARANTINE toggle already above)
    QUARANTINE_ON_THREAT_SCORE: int = 90          # Auto-quarantine at this threat score
    QUARANTINE_ON_DEVICE_ANOMALY: bool = False    # Auto-quarantine on device IP mismatch

    # Shadow AI detection
    SHADOW_AI_DETECTION_ENABLED: bool = False      # Off by default (needs host access)
    SHADOW_AI_SCAN_INTERVAL_SECONDS: int = 300    # 5min scan interval
    SHADOW_AI_KNOWN_AI_DOMAINS: str = ""          # Comma-separated extra domains

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"

    # SIEM Integration
    SIEM_OUTPUT: str = "none"  # none | syslog | webhook | splunk | both | all
    SIEM_SYSLOG_HOST: Optional[str] = None
    SIEM_SYSLOG_PORT: int = 514
    SIEM_SYSLOG_PROTOCOL: str = "udp"  # udp | tcp
    SIEM_WEBHOOK_URL: Optional[str] = None
    SIEM_WEBHOOK_SECRET: Optional[str] = None
    SIEM_SPLUNK_HEC_URL: Optional[str] = None
    SIEM_SPLUNK_HEC_TOKEN: Optional[str] = None
    SIEM_SPLUNK_INDEX: str = "main"
    SIEM_SPLUNK_SOURCETYPE: str = "snapper:security"
    SIEM_SPLUNK_VERIFY_SSL: bool = True

    # Prometheus Metrics
    METRICS_ENABLED: bool = True

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
        extra="ignore",
    )


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
