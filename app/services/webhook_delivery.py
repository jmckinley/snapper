"""Generic webhook event delivery with HMAC-SHA256 signatures and retry.

Supports configurable event filters and exponential backoff via Celery.
"""

import hashlib
import hmac
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db_context

logger = logging.getLogger(__name__)

# Retry configuration
MAX_RETRIES = 5
RETRY_BASE_DELAY = 2  # seconds, exponential backoff: 2, 4, 8, 16, 32


class WebhookDeliveryResult:
    """Result of a webhook delivery attempt."""

    def __init__(
        self,
        success: bool,
        status_code: Optional[int] = None,
        response_body: Optional[str] = None,
        error: Optional[str] = None,
        attempt: int = 1,
    ):
        self.success = success
        self.status_code = status_code
        self.response_body = response_body
        self.error = error
        self.attempt = attempt
        self.timestamp = datetime.now(timezone.utc)


def sign_payload(payload: bytes, secret: str) -> str:
    """Generate HMAC-SHA256 signature for a webhook payload."""
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify an incoming webhook signature."""
    expected = sign_payload(payload, secret)
    return hmac.compare_digest(f"sha256={expected}", signature)


async def deliver_webhook(
    url: str,
    payload: Dict[str, Any],
    secret: Optional[str] = None,
    event_type: str = "event",
    webhook_id: Optional[str] = None,
    timeout: float = 10.0,
) -> WebhookDeliveryResult:
    """Deliver a webhook payload to a URL with HMAC-SHA256 signature.

    Returns a WebhookDeliveryResult indicating success/failure.
    """
    body = json.dumps(payload, default=str).encode()
    ts = str(int(time.time()))

    headers = {
        "Content-Type": "application/json",
        "X-Snapper-Event": event_type,
        "X-Snapper-Timestamp": ts,
        "X-Snapper-Delivery": webhook_id or str(uuid.uuid4()),
    }

    if secret:
        sig = sign_payload(body, secret)
        headers["X-Snapper-Signature"] = f"sha256={sig}"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, content=body, headers=headers)

            success = response.status_code < 400
            try:
                from app.middleware.metrics import record_webhook_delivery
                record_webhook_delivery(success)
            except Exception:
                pass

            return WebhookDeliveryResult(
                success=success,
                status_code=response.status_code,
                response_body=response.text[:1000],
            )
    except httpx.TimeoutException:
        try:
            from app.middleware.metrics import record_webhook_delivery
            record_webhook_delivery(False)
        except Exception:
            pass
        return WebhookDeliveryResult(success=False, error="Request timed out")
    except httpx.ConnectError as e:
        try:
            from app.middleware.metrics import record_webhook_delivery
            record_webhook_delivery(False)
        except Exception:
            pass
        return WebhookDeliveryResult(success=False, error=f"Connection error: {e}")
    except Exception as e:
        try:
            from app.middleware.metrics import record_webhook_delivery
            record_webhook_delivery(False)
        except Exception:
            pass
        return WebhookDeliveryResult(success=False, error=str(e))


async def deliver_with_retry(
    url: str,
    payload: Dict[str, Any],
    secret: Optional[str] = None,
    event_type: str = "event",
    max_retries: int = MAX_RETRIES,
) -> List[WebhookDeliveryResult]:
    """Deliver a webhook with exponential backoff retry.

    Returns list of all delivery attempts.
    """
    import asyncio

    attempts: List[WebhookDeliveryResult] = []
    delivery_id = str(uuid.uuid4())

    for attempt in range(1, max_retries + 1):
        result = await deliver_webhook(
            url=url,
            payload=payload,
            secret=secret,
            event_type=event_type,
            webhook_id=delivery_id,
        )
        result.attempt = attempt
        attempts.append(result)

        if result.success:
            logger.info(f"Webhook delivered to {url} on attempt {attempt}")
            break

        if attempt < max_retries:
            delay = RETRY_BASE_DELAY ** attempt
            logger.warning(
                f"Webhook delivery to {url} failed (attempt {attempt}/{max_retries}), "
                f"retrying in {delay}s: {result.error or result.status_code}"
            )
            await asyncio.sleep(delay)
        else:
            logger.error(
                f"Webhook delivery to {url} failed after {max_retries} attempts"
            )

    return attempts


async def publish_to_org_webhooks(
    org_id: str,
    event_type: str,
    payload: Dict[str, Any],
) -> None:
    """Publish an event to all webhook endpoints configured for an org.

    Loads webhook configs from org.settings["webhooks"] list.
    Each webhook has: url, secret, event_filters (list of event types).
    """
    from app.models.organizations import Organization

    async with get_db_context() as db:
        stmt = select(Organization).where(Organization.id == uuid.UUID(org_id))
        result = await db.execute(stmt)
        org = result.scalar_one_or_none()

        if not org:
            return

        webhooks = (org.settings or {}).get("webhooks", [])

        for wh in webhooks:
            url = wh.get("url")
            if not url:
                continue

            # Check event filter
            event_filters = wh.get("event_filters", [])
            if event_filters and event_type not in event_filters:
                continue

            secret = wh.get("secret")
            try:
                await deliver_with_retry(
                    url=url,
                    payload=payload,
                    secret=secret,
                    event_type=event_type,
                )
            except Exception as e:
                logger.warning(f"Webhook delivery to {url} failed: {e}")
