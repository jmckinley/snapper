"""Tests for rate limiter service."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.services.rate_limiter import (
    RateLimiterService,
    AdaptiveRateLimiter,
    RateLimitInfo,
)
from app.redis_client import RedisClient


class TestRateLimiterService:
    """Tests for the basic rate limiter service."""

    @pytest.mark.asyncio
    async def test_first_request_allowed(self, redis: RedisClient):
        """First request should always be allowed."""
        limiter = RateLimiterService(redis)
        key = f"test:{id(self)}"

        result = await limiter.check_rate_limit(key, max_requests=10, window_seconds=60)

        assert result.allowed is True
        assert result.remaining >= 0

    @pytest.mark.asyncio
    async def test_within_limit_allowed(self, redis: RedisClient):
        """Requests within the limit should be allowed."""
        limiter = RateLimiterService(redis)
        key = f"test:within:{id(self)}"

        # Make several requests within limit
        for i in range(5):
            result = await limiter.check_rate_limit(
                key, max_requests=10, window_seconds=60
            )
            assert result.allowed is True
            assert result.remaining >= 0

    @pytest.mark.asyncio
    async def test_exceeds_limit_denied(self, redis: RedisClient):
        """Request at max+1 should be denied."""
        limiter = RateLimiterService(redis)
        key = f"test:exceed:{id(self)}"
        max_requests = 3

        # Exhaust the limit
        for i in range(max_requests):
            result = await limiter.check_rate_limit(
                key, max_requests=max_requests, window_seconds=60
            )
            assert result.allowed is True

        # Next request should be denied
        result = await limiter.check_rate_limit(
            key, max_requests=max_requests, window_seconds=60
        )
        assert result.allowed is False
        assert result.remaining == 0
        assert result.retry_after >= 0

    @pytest.mark.asyncio
    async def test_agent_key_prefix(self, redis: RedisClient):
        """Agent key uses 'agent:<id>' prefix."""
        limiter = RateLimiterService(redis)
        agent_id = "test-agent-123"

        result = await limiter.check_agent_limit(
            agent_id, max_requests=10, window_seconds=60
        )

        assert result.allowed is True
        # Verify the key format by checking the count
        count = await limiter.get_current_count(f"agent:{agent_id}", 60)
        assert count >= 1

    @pytest.mark.asyncio
    async def test_ip_key_prefix(self, redis: RedisClient):
        """IP key uses 'ip:<addr>' prefix."""
        limiter = RateLimiterService(redis)
        ip_address = "192.168.1.100"

        result = await limiter.check_ip_limit(
            ip_address, max_requests=10, window_seconds=60
        )

        assert result.allowed is True
        # Verify the key format
        count = await limiter.get_current_count(f"ip:{ip_address}", 60)
        assert count >= 1

    @pytest.mark.asyncio
    async def test_endpoint_key_prefix(self, redis: RedisClient):
        """Endpoint key uses 'endpoint:<ep>:<id>' prefix."""
        limiter = RateLimiterService(redis)
        endpoint = "/api/test"
        identifier = "user-123"

        result = await limiter.check_endpoint_limit(
            endpoint, identifier, max_requests=10, window_seconds=60
        )

        assert result.allowed is True
        # Verify the key format
        count = await limiter.get_current_count(f"endpoint:{endpoint}:{identifier}", 60)
        assert count >= 1

    @pytest.mark.asyncio
    async def test_reset_limit_clears_count(self, redis: RedisClient):
        """reset_limit should restore the quota."""
        limiter = RateLimiterService(redis)
        key = f"test:reset:{id(self)}"

        # Exhaust the limit
        for _ in range(5):
            await limiter.check_rate_limit(key, max_requests=5, window_seconds=60)

        # Should be denied
        result = await limiter.check_rate_limit(key, max_requests=5, window_seconds=60)
        assert result.allowed is False

        # Reset
        success = await limiter.reset_limit(key)
        assert success is True

        # Should be allowed again
        result = await limiter.check_rate_limit(key, max_requests=5, window_seconds=60)
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_get_limit_info_no_consume(self, redis: RedisClient):
        """get_limit_info should not consume a request."""
        limiter = RateLimiterService(redis)
        key = f"test:info:{id(self)}"

        # Make some requests
        for _ in range(3):
            await limiter.check_rate_limit(key, max_requests=10, window_seconds=60)

        # Get info
        info1 = await limiter.get_limit_info(key, max_requests=10, window_seconds=60)

        # Get info again - count should be the same
        info2 = await limiter.get_limit_info(key, max_requests=10, window_seconds=60)

        assert info1["current_count"] == info2["current_count"]
        assert info1["remaining"] == info2["remaining"]


class TestAdaptiveRateLimiter:
    """Tests for the adaptive rate limiter."""

    @pytest.mark.asyncio
    async def test_default_trust_score_is_one(self, redis: RedisClient):
        """New identifier gets trust score of 1.0."""
        base_limiter = RateLimiterService(redis)
        adaptive = AdaptiveRateLimiter(redis, base_limiter)
        identifier = f"new-user-{id(self)}"

        trust = await adaptive.get_trust_score(identifier)

        assert trust == 1.0

    @pytest.mark.asyncio
    async def test_violation_reduces_trust(self, redis: RedisClient):
        """Recording a violation reduces trust by 10%."""
        base_limiter = RateLimiterService(redis)
        adaptive = AdaptiveRateLimiter(redis, base_limiter)
        identifier = f"violator-{id(self)}"

        # Set initial trust
        await adaptive.set_trust_score(identifier, 1.0)

        # Record violation
        new_score = await adaptive.record_violation(identifier)

        # Should be reduced by 10% (1.0 * 0.9 = 0.9)
        assert new_score == pytest.approx(0.9, rel=0.01)

    @pytest.mark.asyncio
    async def test_good_behavior_increases_trust(self, redis: RedisClient):
        """Good behavior increases trust by 1%."""
        base_limiter = RateLimiterService(redis)
        adaptive = AdaptiveRateLimiter(redis, base_limiter)
        identifier = f"good-user-{id(self)}"

        # Set initial trust
        await adaptive.set_trust_score(identifier, 1.0)

        # Record good behavior
        new_score = await adaptive.record_good_behavior(identifier)

        # Should be increased by 1% (1.0 * 1.01 = 1.01)
        assert new_score == pytest.approx(1.01, rel=0.01)

    @pytest.mark.asyncio
    async def test_adaptive_limit_adjusts_max(self, redis: RedisClient):
        """Adaptive limit equals base_limit * trust_score."""
        base_limiter = RateLimiterService(redis)
        adaptive = AdaptiveRateLimiter(redis, base_limiter)
        identifier = f"adjust-{id(self)}"

        # Set trust to 0.5
        await adaptive.set_trust_score(identifier, 0.5)

        # Get adaptive limit
        adapted = await adaptive.get_adaptive_limit(identifier, base_limit=100)

        # Should be 100 * 0.5 = 50
        assert adapted == 50
