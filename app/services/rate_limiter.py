"""Rate limiting service with sliding window algorithm."""

import time
from dataclasses import dataclass
from typing import Optional

from app.config import get_settings
from app.redis_client import RedisClient

settings = get_settings()


@dataclass
class RateLimitInfo:
    """Rate limit status information."""

    allowed: bool
    remaining: int
    limit: int
    window_seconds: int
    retry_after: int  # Seconds until rate limit resets (0 if not limited)


class RateLimiterService:
    """
    Rate limiting service using sliding window algorithm.

    Features:
    - Sliding window for accurate rate limiting
    - Per-agent, per-IP, and combined rate limiting
    - Configurable limits per rule
    - Redis-backed for distributed systems
    """

    DEFAULT_MAX_REQUESTS = 100
    DEFAULT_WINDOW_SECONDS = 60

    def __init__(self, redis: RedisClient):
        self.redis = redis

    async def check_rate_limit(
        self,
        key: str,
        max_requests: Optional[int] = None,
        window_seconds: Optional[int] = None,
    ) -> RateLimitInfo:
        """
        Check if a request is within rate limits.

        Args:
            key: Unique identifier for rate limiting (e.g., agent_id, ip_address)
            max_requests: Maximum requests allowed in window
            window_seconds: Time window in seconds

        Returns:
            RateLimitInfo with current status
        """
        max_req = max_requests or settings.RATE_LIMIT_DEFAULT_MAX_REQUESTS
        window = window_seconds or settings.RATE_LIMIT_DEFAULT_WINDOW_SECONDS

        allowed, remaining, retry_after = await self.redis.check_rate_limit(
            key=key,
            max_requests=max_req,
            window_seconds=window,
        )

        return RateLimitInfo(
            allowed=allowed,
            remaining=remaining,
            limit=max_req,
            window_seconds=window,
            retry_after=retry_after,
        )

    async def check_agent_limit(
        self,
        agent_id: str,
        max_requests: Optional[int] = None,
        window_seconds: Optional[int] = None,
    ) -> RateLimitInfo:
        """Check rate limit for a specific agent."""
        key = f"agent:{agent_id}"
        return await self.check_rate_limit(key, max_requests, window_seconds)

    async def check_ip_limit(
        self,
        ip_address: str,
        max_requests: Optional[int] = None,
        window_seconds: Optional[int] = None,
    ) -> RateLimitInfo:
        """Check rate limit for a specific IP address."""
        key = f"ip:{ip_address}"
        return await self.check_rate_limit(key, max_requests, window_seconds)

    async def check_endpoint_limit(
        self,
        endpoint: str,
        identifier: str,
        max_requests: Optional[int] = None,
        window_seconds: Optional[int] = None,
    ) -> RateLimitInfo:
        """Check rate limit for a specific endpoint and identifier."""
        key = f"endpoint:{endpoint}:{identifier}"
        return await self.check_rate_limit(key, max_requests, window_seconds)

    async def get_current_count(self, key: str, window_seconds: int) -> int:
        """Get current request count in window."""
        full_key = f"rate_limit:{key}"
        current_time = int(time.time() * 1000)
        window_start = current_time - (window_seconds * 1000)

        # Use ZCOUNT to get count of requests in window
        client = self.redis.client
        count = await client.zcount(full_key, window_start, current_time)
        return count or 0

    async def reset_limit(self, key: str) -> bool:
        """Reset rate limit for a key."""
        full_key = f"rate_limit:{key}"
        result = await self.redis.delete(full_key)
        return result > 0

    async def get_limit_info(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> dict:
        """Get detailed rate limit information without consuming a request."""
        current_count = await self.get_current_count(key, window_seconds)
        remaining = max(0, max_requests - current_count)

        return {
            "key": key,
            "current_count": current_count,
            "limit": max_requests,
            "remaining": remaining,
            "window_seconds": window_seconds,
            "is_limited": current_count >= max_requests,
        }


class AdaptiveRateLimiter:
    """
    Adaptive rate limiter that adjusts limits based on behavior.

    Can increase limits for well-behaved clients and decrease
    limits for suspicious activity.
    """

    def __init__(self, redis: RedisClient, base_limiter: RateLimiterService):
        self.redis = redis
        self.base_limiter = base_limiter

        # Trust score ranges
        self.MIN_TRUST = 0.1  # 10% of base limit
        self.MAX_TRUST = 2.0  # 200% of base limit
        self.DEFAULT_TRUST = 1.0

        # Adjustment factors
        self.VIOLATION_PENALTY = 0.1  # Reduce trust by 10% per violation
        self.GOOD_BEHAVIOR_BONUS = 0.01  # Increase trust by 1% per successful request
        self.TRUST_DECAY_RATE = 0.001  # Trust decays slowly over time

    async def get_trust_score(self, identifier: str) -> float:
        """Get current trust score for identifier."""
        key = f"trust:{identifier}"
        score = await self.redis.get(key)
        if score:
            return float(score)
        return self.DEFAULT_TRUST

    async def set_trust_score(self, identifier: str, score: float) -> None:
        """Set trust score for identifier."""
        # Clamp to valid range
        score = max(self.MIN_TRUST, min(self.MAX_TRUST, score))
        key = f"trust:{identifier}"
        await self.redis.set(key, str(score), expire=86400)  # 24 hour TTL

    async def record_violation(self, identifier: str) -> float:
        """Record a rate limit violation and reduce trust."""
        current = await self.get_trust_score(identifier)
        new_score = current * (1 - self.VIOLATION_PENALTY)
        await self.set_trust_score(identifier, new_score)
        return new_score

    async def record_good_behavior(self, identifier: str) -> float:
        """Record good behavior and increase trust."""
        current = await self.get_trust_score(identifier)
        new_score = current * (1 + self.GOOD_BEHAVIOR_BONUS)
        await self.set_trust_score(identifier, new_score)
        return new_score

    async def get_adaptive_limit(
        self,
        identifier: str,
        base_limit: int,
    ) -> int:
        """Get adapted rate limit based on trust score."""
        trust = await self.get_trust_score(identifier)
        return int(base_limit * trust)

    async def check_rate_limit(
        self,
        identifier: str,
        base_max_requests: int,
        window_seconds: int,
    ) -> RateLimitInfo:
        """Check adaptive rate limit."""
        # Get adapted limit
        adapted_limit = await self.get_adaptive_limit(identifier, base_max_requests)

        # Check rate limit with adapted value
        info = await self.base_limiter.check_rate_limit(
            key=identifier,
            max_requests=adapted_limit,
            window_seconds=window_seconds,
        )

        # Update trust based on result
        if not info.allowed:
            await self.record_violation(identifier)
        elif info.remaining > adapted_limit * 0.5:  # Using less than half
            await self.record_good_behavior(identifier)

        return info
