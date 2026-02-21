"""Unknown agent protection: sliding-window tracking and IP lockout.

Records unknown agent evaluate attempts per source IP using a Redis ZSET
with timestamp scores.  When thresholds are crossed, fires alerts and
applies a time-limited lockout to the offending IP.
"""

import logging
import time
from typing import Any, Dict

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


async def record_attempt(redis, ip: str, agent_id: str) -> Dict[str, Any]:
    """Record an unknown-agent evaluate attempt from *ip*.

    Returns a dict with:
      count         – total attempts in the current window
      should_alert  – True when alert threshold is first crossed
      should_lockout – True when lockout threshold is first crossed
    """
    key = f"unknown_agent:attempts:{ip}"
    now = time.time()
    window_start = now - settings.UNKNOWN_AGENT_WINDOW_SECONDS

    # Add this attempt
    member = f"{now}:{agent_id}"
    await redis.zadd(key, {member: now})

    # Expire stale entries outside the window
    await redis.zremrangebyscore(key, "-inf", str(window_start))

    # Set a generous TTL so the key doesn't live forever
    await redis.expire(key, settings.UNKNOWN_AGENT_WINDOW_SECONDS * 2)

    # Count remaining attempts in window
    count = await redis.zcard(key)

    should_alert = count == settings.UNKNOWN_AGENT_ALERT_THRESHOLD
    should_lockout = count >= settings.UNKNOWN_AGENT_LOCKOUT_THRESHOLD

    # Apply lockout if threshold reached (idempotent)
    if should_lockout:
        lockout_key = f"unknown_agent_lockout:{ip}"
        await redis.set(lockout_key, "1", ex=settings.UNKNOWN_AGENT_LOCKOUT_SECONDS)

    return {
        "count": count,
        "should_alert": should_alert,
        "should_lockout": should_lockout,
    }


async def is_locked_out(redis, ip: str) -> bool:
    """Return True if *ip* is currently locked out."""
    lockout_key = f"unknown_agent_lockout:{ip}"
    return bool(await redis.get(lockout_key))


async def get_attempt_stats(redis, ip: str) -> Dict[str, Any]:
    """Return current attempt stats for *ip* (for dashboard / API)."""
    key = f"unknown_agent:attempts:{ip}"
    now = time.time()
    window_start = now - settings.UNKNOWN_AGENT_WINDOW_SECONDS

    # Clean stale
    await redis.zremrangebyscore(key, "-inf", str(window_start))
    count = await redis.zcard(key)

    lockout_key = f"unknown_agent_lockout:{ip}"
    ttl = await redis.ttl(lockout_key)
    locked = ttl > 0

    return {
        "ip": ip,
        "attempts_in_window": count,
        "window_seconds": settings.UNKNOWN_AGENT_WINDOW_SECONDS,
        "locked_out": locked,
        "lockout_ttl_seconds": max(ttl, 0),
    }
