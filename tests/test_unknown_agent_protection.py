"""Tests for unknown agent protection: sliding-window tracking and IP lockout."""

import time
from unittest.mock import AsyncMock, patch

import pytest

from app.config import get_settings
from app.services.unknown_agent_protection import (
    get_attempt_stats,
    is_locked_out,
    record_attempt,
)

settings = get_settings()


class FakeRedis:
    """Minimal async Redis mock with ZSET + key/value support."""

    def __init__(self):
        self.store = {}
        self.ttls = {}

    async def zadd(self, key, mapping):
        if key not in self.store:
            self.store[key] = {}
        for member, score in mapping.items():
            self.store[key][member] = score

    async def zremrangebyscore(self, key, min_score, max_score):
        if key not in self.store:
            return 0
        min_val = float("-inf") if min_score == "-inf" else float(min_score)
        max_val = float("inf") if max_score == "+inf" else float(max_score)
        to_remove = [m for m, s in self.store[key].items() if min_val <= s <= max_val]
        for m in to_remove:
            del self.store[key][m]
        return len(to_remove)

    async def zcard(self, key):
        return len(self.store.get(key, {}))

    async def expire(self, key, seconds):
        self.ttls[key] = seconds

    async def set(self, key, value, ex=None):
        self.store[key] = value
        if ex:
            self.ttls[key] = ex

    async def get(self, key):
        return self.store.get(key)

    async def ttl(self, key):
        return self.ttls.get(key, -2)


@pytest.fixture
def redis():
    return FakeRedis()


@pytest.mark.asyncio
async def test_attempt_recorded_in_redis(redis):
    """ZSET tracks attempts per IP."""
    result = await record_attempt(redis, "10.0.0.1", "unknown-agent-1")
    assert result["count"] == 1
    assert not result["should_alert"]
    assert not result["should_lockout"]

    key = "unknown_agent:attempts:10.0.0.1"
    assert len(redis.store.get(key, {})) == 1


@pytest.mark.asyncio
async def test_multiple_attempts_accumulate(redis):
    """Multiple attempts from same IP accumulate."""
    for i in range(5):
        result = await record_attempt(redis, "10.0.0.1", f"agent-{i}")
    assert result["count"] == 5


@pytest.mark.asyncio
async def test_alert_threshold_triggered(redis):
    """Alert fires exactly at the threshold count."""
    for i in range(settings.UNKNOWN_AGENT_ALERT_THRESHOLD - 1):
        result = await record_attempt(redis, "10.0.0.1", f"agent-{i}")
        assert not result["should_alert"]

    # This one hits the threshold
    result = await record_attempt(redis, "10.0.0.1", "agent-final")
    assert result["should_alert"]
    assert result["count"] == settings.UNKNOWN_AGENT_ALERT_THRESHOLD


@pytest.mark.asyncio
async def test_lockout_threshold_triggered(redis):
    """Lockout fires when lockout threshold reached."""
    for i in range(settings.UNKNOWN_AGENT_LOCKOUT_THRESHOLD):
        result = await record_attempt(redis, "10.0.0.1", f"agent-{i}")

    assert result["should_lockout"]
    assert result["count"] >= settings.UNKNOWN_AGENT_LOCKOUT_THRESHOLD


@pytest.mark.asyncio
async def test_locked_out_ip_denied_immediately(redis):
    """Once locked out, is_locked_out returns True."""
    # Trigger lockout
    for i in range(settings.UNKNOWN_AGENT_LOCKOUT_THRESHOLD):
        await record_attempt(redis, "10.0.0.1", f"agent-{i}")

    assert await is_locked_out(redis, "10.0.0.1")


@pytest.mark.asyncio
async def test_non_locked_ip_passes(redis):
    """IP with no lockout returns False."""
    assert not await is_locked_out(redis, "192.168.1.1")


@pytest.mark.asyncio
async def test_different_ips_tracked_separately(redis):
    """Each IP has its own attempt counter."""
    for i in range(5):
        await record_attempt(redis, "10.0.0.1", f"agent-{i}")

    for i in range(3):
        await record_attempt(redis, "10.0.0.2", f"agent-{i}")

    stats1 = await get_attempt_stats(redis, "10.0.0.1")
    stats2 = await get_attempt_stats(redis, "10.0.0.2")

    assert stats1["attempts_in_window"] == 5
    assert stats2["attempts_in_window"] == 3


@pytest.mark.asyncio
async def test_attempt_stats_returns_correct_info(redis):
    """get_attempt_stats returns expected structure."""
    await record_attempt(redis, "10.0.0.1", "agent-x")
    stats = await get_attempt_stats(redis, "10.0.0.1")

    assert stats["ip"] == "10.0.0.1"
    assert stats["attempts_in_window"] == 1
    assert stats["window_seconds"] == settings.UNKNOWN_AGENT_WINDOW_SECONDS
    assert not stats["locked_out"]


@pytest.mark.asyncio
async def test_lockout_shows_in_stats(redis):
    """Stats reflect lockout state."""
    for i in range(settings.UNKNOWN_AGENT_LOCKOUT_THRESHOLD):
        await record_attempt(redis, "10.0.0.1", f"agent-{i}")

    stats = await get_attempt_stats(redis, "10.0.0.1")
    assert stats["locked_out"]
    assert stats["lockout_ttl_seconds"] > 0


@pytest.mark.asyncio
async def test_sliding_window_concept(redis):
    """Verify that attempts are timestamp-scored (sliding window structure)."""
    before = time.time()
    await record_attempt(redis, "10.0.0.1", "agent-1")
    after = time.time()

    key = "unknown_agent:attempts:10.0.0.1"
    scores = list(redis.store.get(key, {}).values())
    assert len(scores) == 1
    assert before <= scores[0] <= after


@pytest.mark.asyncio
async def test_alert_only_fires_once_at_threshold(redis):
    """Alert fires at exactly the threshold, not on subsequent attempts."""
    # Fill to one below threshold
    for i in range(settings.UNKNOWN_AGENT_ALERT_THRESHOLD - 1):
        await record_attempt(redis, "10.0.0.1", f"agent-{i}")

    # This one triggers the alert
    result = await record_attempt(redis, "10.0.0.1", "agent-threshold")
    assert result["should_alert"]

    # Next one should NOT trigger (count > threshold, not ==)
    result = await record_attempt(redis, "10.0.0.1", "agent-extra")
    assert not result["should_alert"]
