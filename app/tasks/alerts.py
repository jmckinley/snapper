"""Alert notification tasks."""

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Optional

import httpx

from app.config import get_settings
from app.tasks import celery_app

logger = logging.getLogger(__name__)
settings = get_settings()


@celery_app.task(bind=True, max_retries=3, default_retry_delay=60)
def send_alert(
    self,
    title: str,
    message: str,
    severity: str = "info",
    channels: Optional[List[str]] = None,
    metadata: Optional[dict] = None,
):
    """
    Send alert notification to configured channels.

    Channels:
    - email: Send via SMTP
    - slack: Send via Slack webhook
    - pagerduty: Send via PagerDuty (critical alerts only)
    - webhook: Send to generic webhook URL
    """
    if channels is None:
        # Default channels based on severity
        if severity == "critical":
            channels = ["email", "slack", "pagerduty"]
        elif severity in ("error", "high"):
            channels = ["email", "slack"]
        else:
            channels = ["slack"]

    logger.info(f"Sending alert: {title} (severity: {severity}) to {channels}")

    errors = []

    for channel in channels:
        try:
            if channel == "email":
                _send_email_alert(title, message, severity)
            elif channel == "slack":
                _send_slack_alert(title, message, severity)
            elif channel == "pagerduty":
                _send_pagerduty_alert(title, message, severity, metadata)
            elif channel == "webhook":
                _send_webhook_alert(title, message, severity, metadata)
            else:
                logger.warning(f"Unknown alert channel: {channel}")
        except Exception as e:
            logger.exception(f"Failed to send alert to {channel}: {e}")
            errors.append(f"{channel}: {str(e)}")

    if errors:
        # Log errors but don't fail the task
        logger.error(f"Alert delivery errors: {errors}")


def _send_email_alert(title: str, message: str, severity: str):
    """Send alert via email."""
    if not settings.SMTP_HOST or not settings.SMTP_USER:
        logger.warning("SMTP not configured, skipping email alert")
        return

    # Create message
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[{severity.upper()}] {title}"
    msg["From"] = settings.SMTP_FROM_EMAIL
    msg["To"] = settings.SMTP_USER  # Send to configured user

    # Plain text version
    text_content = f"""
Snapper Rules Manager Alert
----------------------------
Severity: {severity.upper()}
Title: {title}

{message}

---
This is an automated alert from Snapper Rules Manager.
    """

    # HTML version
    severity_colors = {
        "critical": "#dc2626",
        "error": "#ea580c",
        "warning": "#ca8a04",
        "info": "#2563eb",
    }
    color = severity_colors.get(severity, "#6b7280")

    html_content = f"""
    <html>
    <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background-color: {color}; color: white; padding: 16px; border-radius: 8px 8px 0 0;">
            <h2 style="margin: 0;">{severity.upper()}: {title}</h2>
        </div>
        <div style="border: 1px solid #e5e7eb; border-top: none; padding: 16px; border-radius: 0 0 8px 8px;">
            <p style="white-space: pre-wrap;">{message}</p>
        </div>
        <p style="color: #6b7280; font-size: 12px; margin-top: 16px;">
            This is an automated alert from Snapper Rules Manager.
        </p>
    </body>
    </html>
    """

    msg.attach(MIMEText(text_content, "plain"))
    msg.attach(MIMEText(html_content, "html"))

    # Send email
    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.starttls()
            if settings.SMTP_PASSWORD:
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.send_message(msg)
        logger.info(f"Email alert sent: {title}")
    except Exception as e:
        logger.exception(f"Failed to send email: {e}")
        raise


def _send_slack_alert(title: str, message: str, severity: str):
    """Send alert via Slack webhook."""
    if not settings.SLACK_WEBHOOK_URL:
        logger.warning("Slack webhook not configured, skipping Slack alert")
        return

    # Severity colors for Slack
    severity_colors = {
        "critical": "#dc2626",
        "error": "#ea580c",
        "warning": "#ca8a04",
        "info": "#2563eb",
    }
    color = severity_colors.get(severity, "#6b7280")

    # Build Slack message
    payload = {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"{severity.upper()}: {title}",
                        },
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": message[:3000],  # Slack limit
                        },
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": "Snapper Rules Manager",
                            }
                        ],
                    },
                ],
            }
        ]
    }

    try:
        with httpx.Client() as client:
            response = client.post(
                settings.SLACK_WEBHOOK_URL,
                json=payload,
                timeout=30.0,
            )
            response.raise_for_status()
        logger.info(f"Slack alert sent: {title}")
    except Exception as e:
        logger.exception(f"Failed to send Slack alert: {e}")
        raise


def _send_pagerduty_alert(
    title: str,
    message: str,
    severity: str,
    metadata: Optional[dict] = None,
):
    """Send alert via PagerDuty."""
    if not settings.PAGERDUTY_API_KEY:
        logger.warning("PagerDuty not configured, skipping PagerDuty alert")
        return

    # Only send critical alerts to PagerDuty
    if severity not in ("critical", "error"):
        logger.info("Skipping PagerDuty for non-critical alert")
        return

    # Map severity to PagerDuty severity
    pd_severity = "critical" if severity == "critical" else "error"

    payload = {
        "routing_key": settings.PAGERDUTY_API_KEY,
        "event_action": "trigger",
        "payload": {
            "summary": f"{title}: {message[:100]}",
            "severity": pd_severity,
            "source": "snapper-rules-manager",
            "custom_details": metadata or {},
        },
    }

    try:
        with httpx.Client() as client:
            response = client.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload,
                timeout=30.0,
            )
            response.raise_for_status()
        logger.info(f"PagerDuty alert sent: {title}")
    except Exception as e:
        logger.exception(f"Failed to send PagerDuty alert: {e}")
        raise


def _send_webhook_alert(
    title: str,
    message: str,
    severity: str,
    metadata: Optional[dict] = None,
):
    """Send alert to generic webhook."""
    if not settings.GENERIC_WEBHOOK_URL:
        logger.warning("Generic webhook not configured, skipping webhook alert")
        return

    payload = {
        "title": title,
        "message": message,
        "severity": severity,
        "source": "snapper-rules-manager",
        "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
        "metadata": metadata or {},
    }

    try:
        with httpx.Client() as client:
            response = client.post(
                settings.GENERIC_WEBHOOK_URL,
                json=payload,
                timeout=30.0,
            )
            response.raise_for_status()
        logger.info(f"Webhook alert sent: {title}")
    except Exception as e:
        logger.exception(f"Failed to send webhook alert: {e}")
        raise


@celery_app.task
def send_test_alert(channel: str):
    """Send a test alert to verify configuration."""
    send_alert.delay(
        title="Test Alert",
        message="This is a test alert from Snapper Rules Manager. If you received this, your alert configuration is working correctly.",
        severity="info",
        channels=[channel],
    )
