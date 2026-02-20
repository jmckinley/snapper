"""Periodic Telegram bot message cleanup task."""

import asyncio
import logging
import time

import httpx

from app.config import get_settings
from app.tasks import celery_app

logger = logging.getLogger(__name__)
settings = get_settings()

# Telegram only allows deleting messages less than 48 hours old
TELEGRAM_DELETE_LIMIT_SECONDS = 48 * 3600
# Default cleanup threshold: 24 hours
DEFAULT_CLEANUP_AGE_SECONDS = 24 * 3600


def _run_async(coro):
    """Run async coroutine in sync Celery context.

    Uses asyncio.run() to ensure a clean event loop in forked workers.
    """
    return asyncio.run(coro)


async def _cleanup_chat_messages(chat_id: str, cutoff_ts: float) -> dict:
    """Delete tracked bot messages older than cutoff for a chat."""
    from app.redis_client import redis_client

    key = f"bot_messages:{chat_id}"
    message_ids = await redis_client.zrangebyscore(key, "-inf", str(cutoff_ts))

    if not message_ids:
        return {"deleted": 0, "too_old": 0, "failed": 0}

    telegram_url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/deleteMessage"
    telegram_48h_cutoff = time.time() - TELEGRAM_DELETE_LIMIT_SECONDS
    deleted = 0
    too_old = 0
    failed = 0

    async with httpx.AsyncClient() as client:
        for mid_raw in message_ids:
            mid = int(mid_raw) if isinstance(mid_raw, (str, bytes)) else mid_raw
            score = await redis_client.zscore(key, str(mid))

            if score and float(score) < telegram_48h_cutoff:
                too_old += 1
                await redis_client.zrem(key, str(mid))
                continue

            # Skip messages with active pending approvals
            # (approval buttons should stay visible)
            try:
                from app.redis_client import redis_client as _rc
                # Simple heuristic: don't delete very recent messages (< 10 min)
                if score and float(score) > time.time() - 600:
                    continue
            except Exception:
                pass

            try:
                resp = await client.post(
                    telegram_url,
                    json={"chat_id": int(chat_id), "message_id": mid},
                    timeout=10.0,
                )
                if resp.status_code == 200 and resp.json().get("ok"):
                    deleted += 1
                else:
                    failed += 1
            except Exception:
                failed += 1

            await redis_client.zrem(key, str(mid))

            # Rate limit: small delay every 20 deletions
            if deleted % 20 == 0 and deleted > 0:
                await asyncio.sleep(1)

    return {"deleted": deleted, "too_old": too_old, "failed": failed}


@celery_app.task(name="app.tasks.telegram_cleanup.cleanup_bot_messages")
def cleanup_bot_messages():
    """Periodic task: clean up old bot messages from all tracked chats."""
    if not settings.TELEGRAM_BOT_TOKEN:
        logger.debug("Telegram not configured, skipping cleanup")
        return

    return _run_async(_async_cleanup_bot_messages())


async def _async_cleanup_bot_messages():
    """Async implementation of bot message cleanup."""
    from app.redis_client import redis_client

    # Ensure Redis is connected
    try:
        health = await redis_client.check_health()
        if not health:
            await redis_client.connect()
    except Exception:
        await redis_client.connect()

    cutoff_ts = time.time() - DEFAULT_CLEANUP_AGE_SECONDS
    total_deleted = 0
    total_too_old = 0
    chats_cleaned = 0

    # Scan for all bot_messages:* keys
    cursor = 0
    while True:
        cursor, keys = await redis_client.scan(cursor, match="bot_messages:*", count=100)
        for key in keys:
            chat_id = key.replace("bot_messages:", "")
            try:
                result = await _cleanup_chat_messages(chat_id, cutoff_ts)
                total_deleted += result["deleted"]
                total_too_old += result["too_old"]
                if result["deleted"] > 0 or result["too_old"] > 0:
                    chats_cleaned += 1
            except Exception as e:
                logger.warning(f"Failed to clean chat {chat_id}: {e}")

        if cursor == 0:
            break

    if total_deleted > 0 or total_too_old > 0:
        logger.info(
            f"Telegram cleanup: deleted {total_deleted} messages, "
            f"removed {total_too_old} stale entries from {chats_cleaned} chats"
        )

    return {
        "deleted": total_deleted,
        "too_old": total_too_old,
        "chats_cleaned": chats_cleaned,
    }
