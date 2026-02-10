"""Background tasks using Celery."""

from celery import Celery

from app.config import get_settings

settings = get_settings()

# Create Celery app
celery_app = Celery(
    "snapper_rules",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

# Configure Celery
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max per task
    worker_prefetch_multiplier=1,
    task_acks_late=True,
)

# Import task modules to register them
from app.tasks import security_research, alerts, telegram_cleanup  # noqa

# Configure periodic tasks (Celery Beat)
celery_app.conf.beat_schedule = {
    # Fetch NVD updates every 6 hours
    "fetch-nvd-updates": {
        "task": "app.tasks.security_research.fetch_nvd_updates",
        "schedule": 21600,  # 6 hours in seconds
    },
    # Fetch GitHub advisories every 4 hours
    "fetch-github-advisories": {
        "task": "app.tasks.security_research.fetch_github_advisories",
        "schedule": 14400,  # 4 hours
    },
    # Scan ClawHub skills every 2 hours
    "scan-clawhub-skills": {
        "task": "app.tasks.security_research.scan_clawhub_skills",
        "schedule": 7200,  # 2 hours
    },
    # Generate recommendations daily at 6 AM UTC
    "generate-recommendations": {
        "task": "app.tasks.security_research.generate_recommendations",
        "schedule": 86400,  # 24 hours
    },
    # Calculate security scores hourly
    "calculate-security-scores": {
        "task": "app.tasks.security_research.calculate_security_scores",
        "schedule": 3600,  # 1 hour
    },
    # Weekly security digest on Mondays at 8 AM UTC
    "weekly-security-digest": {
        "task": "app.tasks.security_research.send_weekly_digest",
        "schedule": 604800,  # 7 days
    },
    # Clean up old Telegram bot messages every 6 hours
    "cleanup-telegram-bot-messages": {
        "task": "app.tasks.telegram_cleanup.cleanup_bot_messages",
        "schedule": 21600,  # 6 hours
    },
}
