"""Alert notification tasks."""

import asyncio
import logging
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Optional
from uuid import UUID

import httpx

from app.config import get_settings
from app.tasks import celery_app

logger = logging.getLogger(__name__)
settings = get_settings()


def _run_async(coro):
    """Run async coroutine in sync Celery context."""
    loop = asyncio.get_event_loop()
    if loop.is_closed():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


async def _persist_alert(title, message, severity, channels, metadata):
    """Persist Alert record to database."""
    try:
        from app.database import get_db_context
        from app.models.audit_logs import Alert, AuditSeverity

        severity_map = {
            "critical": AuditSeverity.CRITICAL,
            "error": AuditSeverity.ERROR,
            "high": AuditSeverity.ERROR,
            "warning": AuditSeverity.WARNING,
            "info": AuditSeverity.INFO,
        }

        # Extract agent_id from metadata if present
        agent_id = None
        if metadata and metadata.get("agent_id"):
            try:
                agent_id = UUID(metadata["agent_id"]) if isinstance(metadata["agent_id"], str) else None
            except (ValueError, TypeError):
                pass

        async with get_db_context() as db:
            alert = Alert(
                alert_type="rule_enforcement",
                severity=severity_map.get(severity, AuditSeverity.INFO),
                agent_id=agent_id,
                title=title,
                message=message,
                details=metadata or {},
                notification_channels=channels or [],
                notification_sent_at=datetime.utcnow(),
            )
            db.add(alert)
    except Exception as e:
        logger.warning(f"Failed to persist alert to database: {e}")


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
            channels = ["email", "slack", "telegram", "pagerduty"]
        elif severity in ("error", "high"):
            channels = ["email", "slack", "telegram"]
        else:
            channels = ["slack", "telegram"]

    logger.info(f"Sending alert: {title} (severity: {severity}) to {channels}")

    errors = []

    for channel in channels:
        try:
            if channel == "email":
                _send_email_alert(title, message, severity)
            elif channel == "slack":
                _send_slack_alert(title, message, severity, metadata)
            elif channel == "telegram":
                _send_telegram_alert(title, message, severity, metadata)
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

    # Persist alert record to database
    try:
        _run_async(_persist_alert(title, message, severity, channels, metadata))
    except Exception as e:
        logger.warning(f"Failed to persist alert record: {e}")


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


def _send_slack_alert(title: str, message: str, severity: str, metadata: Optional[dict] = None):
    """Send alert via Slack Bot API (interactive buttons) or webhook fallback.

    Routes to the appropriate Slack target:
    - If owner_chat_id starts with 'U' → DM that Slack user via Bot API
    - Else fallback to SLACK_ALERT_CHANNEL or SLACK_WEBHOOK_URL
    """
    # Try Bot API first (supports interactive buttons)
    if settings.SLACK_BOT_TOKEN:
        # Determine target Slack user/channel
        target = None
        if metadata:
            pii_ctx = metadata.get("pii_context")
            if pii_ctx and isinstance(pii_ctx, dict):
                owner = pii_ctx.get("owner_chat_id", "")
                if isinstance(owner, str) and owner.startswith("U"):
                    target = owner
            if not target:
                owner = metadata.get("agent_owner_chat_id", "")
                if isinstance(owner, str) and owner.startswith("U"):
                    target = owner

        if not target and settings.SLACK_ALERT_CHANNEL:
            target = settings.SLACK_ALERT_CHANNEL

        if target:
            try:
                _run_async(_send_slack_bot_alert(target, title, message, severity, metadata))
                return
            except Exception as e:
                logger.warning(f"Slack Bot API alert failed, falling back to webhook: {e}")

    # Fallback: webhook-only (no interactivity)
    if not settings.SLACK_WEBHOOK_URL:
        logger.warning("Slack not configured (no bot token or webhook), skipping Slack alert")
        return

    severity_colors = {
        "critical": "#dc2626",
        "error": "#ea580c",
        "warning": "#ca8a04",
        "info": "#2563eb",
    }
    color = severity_colors.get(severity, "#6b7280")

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
                            "text": message[:3000],
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
        logger.info(f"Slack webhook alert sent: {title}")
    except Exception as e:
        logger.exception(f"Failed to send Slack alert: {e}")
        raise


async def _send_slack_bot_alert(target: str, title: str, message: str, severity: str, metadata: Optional[dict] = None):
    """Send alert via Slack Bot API with interactive buttons."""
    from app.routers.slack import send_slack_approval
    await send_slack_approval(
        target_user_id=target,
        title=title,
        message=message,
        severity=severity,
        metadata=metadata,
    )


def _send_telegram_alert(
    title: str,
    message: str,
    severity: str,
    metadata: Optional[dict] = None,
    target_chat_id: Optional[str] = None,
):
    """Send alert via Telegram bot with per-user routing."""
    if not settings.TELEGRAM_BOT_TOKEN:
        logger.warning("Telegram bot token not configured, skipping Telegram alert")
        return

    # Resolution chain for target chat:
    # 1. Explicit target_chat_id parameter
    # 2. PII context owner_chat_id (vault entry owner)
    # 3. Agent owner_chat_id (agent owner)
    # 4. Fallback: global TELEGRAM_CHAT_ID
    effective_chat_id = target_chat_id
    if not effective_chat_id and metadata:
        pii_ctx = metadata.get("pii_context")
        if pii_ctx and isinstance(pii_ctx, dict):
            effective_chat_id = pii_ctx.get("owner_chat_id")
        if not effective_chat_id:
            effective_chat_id = metadata.get("agent_owner_chat_id")
    if not effective_chat_id:
        effective_chat_id = settings.TELEGRAM_CHAT_ID
    if not effective_chat_id:
        logger.warning("No target chat ID for Telegram alert, skipping")
        return

    # Skip if the resolved target is a Slack user (U... prefix) — Slack handler owns this
    if isinstance(effective_chat_id, str) and effective_chat_id.startswith("U"):
        logger.debug(f"Skipping Telegram alert for Slack user {effective_chat_id}")
        return

    # Severity emojis for Telegram
    severity_emojis = {
        "critical": "🚨",
        "error": "❌",
        "warning": "⚠️",
        "info": "ℹ️",
    }
    emoji = severity_emojis.get(severity, "📢")

    # Check if this is a PII-specific alert
    pii_context = metadata.get("pii_context") if metadata else None

    if pii_context:
        # Build rich PII submission message
        text = f"🔐 *PII SUBMISSION DETECTED*\n\n"
        text += f"*Agent:* {metadata.get('agent_name', 'Unknown')}\n"

        action = pii_context.get("action") or metadata.get("tool_name") or "tool call"
        text += f"*Action:* {action}\n"

        dest = pii_context.get("destination_url") or pii_context.get("destination_domain")
        if dest:
            text += f"*Site:* {dest}\n"

        # Show monetary amounts if detected
        amounts = pii_context.get("amounts", [])
        if amounts:
            text += f"*Amount:* `{', '.join(amounts)}`\n"

        # List detected data
        vault_token_details = pii_context.get("vault_token_details", [])
        vault_tokens = pii_context.get("vault_tokens", [])
        raw_pii = pii_context.get("raw_pii", [])

        if vault_token_details or vault_tokens or raw_pii:
            text += "\n*Data being sent:*\n"
            if vault_token_details:
                for detail in vault_token_details:
                    label = detail.get("label")
                    category = detail.get("category", "").replace("_", " ").title()
                    masked = detail.get("masked_value")
                    if label and masked:
                        text += f"  • {category}: `{masked}` ({label})\n"
                    elif label:
                        text += f"  • {label}\n"
                    else:
                        token = detail.get("token", "unknown")
                        text += f"  • Vault Token: `{token[:20]}...`\n"
            elif vault_tokens:
                for token in vault_tokens:
                    text += f"  • Vault Token: `{token[:20]}...`\n"
            for pii_item in raw_pii:
                pii_type = pii_item.get("type", "unknown").replace("_", " ").title()
                masked = pii_item.get("masked", "****")
                text += f"  • {pii_type}: `{masked}`\n"
    else:
        # Standard alert message
        text = f"{emoji} *{severity.upper()}: {title}*\n\n{message}"

    reply_markup = None

    # Add approval buttons if this is an approval request
    if metadata and metadata.get("request_id") and metadata.get("requires_approval"):
        request_id = metadata["request_id"]
        reply_markup = {
            "inline_keyboard": [
                [
                    {"text": "✅ Approve", "callback_data": f"approve:{request_id}"},
                    {"text": "❌ Deny", "callback_data": f"deny:{request_id}"},
                ]
            ]
        }
    # Add Allow Once/Always buttons for blocked commands
    elif metadata and metadata.get("command") and metadata.get("agent_id"):
        import hashlib
        import json
        import redis

        # Build context for the allow rule
        context_data = json.dumps({
            "type": "run",
            "value": metadata["command"],
            "agent_id": metadata.get("agent_name", metadata["agent_id"]),  # Use name for lookup
        })
        # Create a short hash key for the context (callback_data has 64 byte limit)
        context_key = hashlib.sha256(context_data.encode()).hexdigest()[:12]

        # Store context in Redis with 1 hour expiry
        try:
            redis_url = settings.REDIS_URL or "redis://localhost:6379/0"
            r = redis.from_url(redis_url)
            r.setex(f"tg_ctx:{context_key}", 3600, context_data)

            buttons = [
                [
                    {"text": "✅ Allow Once", "callback_data": f"once:{context_key}"},
                    {"text": "📝 Allow Always", "callback_data": f"always:{context_key}"},
                ],
            ]

            # Add View Rule button if we have the rule name
            if metadata.get("rule_name"):
                rule_id = metadata.get("rule_id", "")[:12] if metadata.get("rule_id") else ""
                if rule_id:
                    buttons.append([{"text": "📋 View Rule", "callback_data": f"rule:{rule_id}"}])

            reply_markup = {"inline_keyboard": buttons}
        except Exception as e:
            logger.exception(f"Failed to store context for Telegram buttons: {e}")

    # Add metadata footer (skip if PII context already provided details)
    if metadata and not pii_context:
        agent = metadata.get("agent_id", "Unknown")
        command = metadata.get("command", "")
        if command:
            text += f"\n\n📋 *Agent:* `{agent}`\n🔧 *Command:* `{command[:100]}`"

    text += "\n\n_Snapper Security_"

    # Send via Telegram Bot API
    url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": effective_chat_id,
        "text": text,
        "parse_mode": "Markdown",
    }

    if reply_markup:
        payload["reply_markup"] = reply_markup

    try:
        with httpx.Client() as client:
            response = client.post(url, json=payload, timeout=30.0)
            response.raise_for_status()
        logger.info(f"Telegram alert sent: {title}")
    except Exception as e:
        logger.exception(f"Failed to send Telegram alert: {e}")
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
