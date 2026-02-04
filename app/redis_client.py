"""Redis client with rate limiting and circuit breaker functionality."""

import asyncio
import time
from enum import Enum
from typing import Optional

import redis.asyncio as redis

from app.config import get_settings

settings = get_settings()


class CircuitState(str, Enum):
    """Circuit breaker states."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Blocking all requests
    HALF_OPEN = "half_open"  # Testing if service recovered


class CircuitBreaker:
    """Circuit breaker for protecting against cascading failures."""

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 30,
        half_open_max_calls: int = 3,
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: Optional[float] = None
        self._half_open_calls = 0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        """Get current circuit state, transitioning if necessary."""
        if self._state == CircuitState.OPEN:
            if (
                self._last_failure_time
                and time.time() - self._last_failure_time >= self.recovery_timeout
            ):
                self._state = CircuitState.HALF_OPEN
                self._half_open_calls = 0
        return self._state

    async def call(self, func, *args, **kwargs):
        """Execute function with circuit breaker protection."""
        async with self._lock:
            current_state = self.state

            if current_state == CircuitState.OPEN:
                raise CircuitBreakerOpenError(
                    f"Circuit breaker is open. Retry after {self.recovery_timeout}s"
                )

            if current_state == CircuitState.HALF_OPEN:
                if self._half_open_calls >= self.half_open_max_calls:
                    raise CircuitBreakerOpenError(
                        "Circuit breaker in half-open state, max test calls reached"
                    )
                self._half_open_calls += 1

        try:
            result = await func(*args, **kwargs)
            await self._on_success()
            return result
        except Exception as e:
            await self._on_failure()
            raise e

    async def _on_success(self):
        """Handle successful call."""
        async with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                # Service recovered, close circuit
                self._state = CircuitState.CLOSED
            self._failure_count = 0

    async def _on_failure(self):
        """Handle failed call."""
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()

            if self._state == CircuitState.HALF_OPEN:
                # Service still failing, re-open circuit
                self._state = CircuitState.OPEN
            elif self._failure_count >= self.failure_threshold:
                # Too many failures, open circuit
                self._state = CircuitState.OPEN


class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is open."""

    pass


# Lua script for atomic sliding window rate limiting
SLIDING_WINDOW_SCRIPT = """
local key = KEYS[1]
local window_size = tonumber(ARGV[1])
local max_requests = tonumber(ARGV[2])
local current_time = tonumber(ARGV[3])
local window_start = current_time - window_size

-- Remove old entries outside the window
redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

-- Count current requests in window
local current_count = redis.call('ZCARD', key)

if current_count < max_requests then
    -- Add new request
    redis.call('ZADD', key, current_time, current_time .. '-' .. math.random())
    redis.call('EXPIRE', key, window_size + 1)
    return {1, max_requests - current_count - 1, window_size}
else
    -- Get oldest entry to calculate retry time
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local retry_after = 0
    if #oldest > 0 then
        retry_after = math.ceil(tonumber(oldest[2]) + window_size - current_time)
    end
    return {0, 0, retry_after}
end
"""


class RedisClient:
    """Redis client with rate limiting and circuit breaker."""

    def __init__(self):
        self._pool: Optional[redis.ConnectionPool] = None
        self._client: Optional[redis.Redis] = None
        self._circuit_breaker = CircuitBreaker(
            failure_threshold=settings.CIRCUIT_BREAKER_FAILURE_THRESHOLD,
            recovery_timeout=settings.CIRCUIT_BREAKER_RECOVERY_TIMEOUT,
            half_open_max_calls=settings.CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS,
        )
        self._rate_limit_script: Optional[str] = None

    async def connect(self) -> None:
        """Initialize Redis connection pool."""
        self._pool = redis.ConnectionPool.from_url(
            settings.REDIS_URL,
            max_connections=settings.REDIS_MAX_CONNECTIONS,
            decode_responses=True,
        )
        self._client = redis.Redis(connection_pool=self._pool)

        # Register Lua script
        self._rate_limit_script = self._client.register_script(SLIDING_WINDOW_SCRIPT)

    async def close(self) -> None:
        """Close Redis connections."""
        if self._client:
            await self._client.close()
        if self._pool:
            await self._pool.disconnect()

    async def check_health(self) -> bool:
        """Check Redis connectivity."""
        try:
            if self._client:
                await self._client.ping()
                return True
            return False
        except Exception:
            return False

    @property
    def client(self) -> redis.Redis:
        """Get Redis client."""
        if not self._client:
            raise RuntimeError("Redis client not initialized. Call connect() first.")
        return self._client

    async def check_rate_limit(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> tuple[bool, int, int]:
        """
        Check rate limit using sliding window algorithm.

        Returns:
            Tuple of (allowed, remaining, retry_after)
            - allowed: Whether the request is allowed
            - remaining: Number of remaining requests in window
            - retry_after: Seconds to wait if rate limited (0 if allowed)
        """
        if not settings.RATE_LIMIT_ENABLED:
            return True, max_requests, 0

        async def _check():
            current_time = int(time.time() * 1000)  # milliseconds
            result = await self._rate_limit_script(
                keys=[f"rate_limit:{key}"],
                args=[window_seconds * 1000, max_requests, current_time],
                client=self._client,
            )
            allowed = bool(result[0])
            remaining = int(result[1])
            retry_after = int(result[2]) // 1000  # Convert back to seconds
            return allowed, remaining, retry_after

        return await self._circuit_breaker.call(_check)

    async def get(self, key: str) -> Optional[str]:
        """Get value from Redis."""

        async def _get():
            return await self._client.get(key)

        return await self._circuit_breaker.call(_get)

    async def set(
        self, key: str, value: str, expire: Optional[int] = None
    ) -> bool:
        """Set value in Redis."""

        async def _set():
            return await self._client.set(key, value, ex=expire)

        return await self._circuit_breaker.call(_set)

    async def delete(self, key: str) -> int:
        """Delete key from Redis."""

        async def _delete():
            return await self._client.delete(key)

        return await self._circuit_breaker.call(_delete)

    async def exists(self, key: str) -> bool:
        """Check if key exists."""

        async def _exists():
            return await self._client.exists(key)

        return await self._circuit_breaker.call(_exists)

    async def incr(self, key: str) -> int:
        """Increment key value."""

        async def _incr():
            return await self._client.incr(key)

        return await self._circuit_breaker.call(_incr)

    async def expire(self, key: str, seconds: int) -> bool:
        """Set key expiration."""

        async def _expire():
            return await self._client.expire(key, seconds)

        return await self._circuit_breaker.call(_expire)

    async def hget(self, name: str, key: str) -> Optional[str]:
        """Get hash field value."""

        async def _hget():
            return await self._client.hget(name, key)

        return await self._circuit_breaker.call(_hget)

    async def hset(self, name: str, key: str, value: str) -> int:
        """Set hash field value."""

        async def _hset():
            return await self._client.hset(name, key, value)

        return await self._circuit_breaker.call(_hset)

    async def hgetall(self, name: str) -> dict:
        """Get all hash fields."""

        async def _hgetall():
            return await self._client.hgetall(name)

        return await self._circuit_breaker.call(_hgetall)

    async def sadd(self, name: str, *values: str) -> int:
        """Add members to set."""

        async def _sadd():
            return await self._client.sadd(name, *values)

        return await self._circuit_breaker.call(_sadd)

    async def smembers(self, name: str) -> set:
        """Get all set members."""

        async def _smembers():
            return await self._client.smembers(name)

        return await self._circuit_breaker.call(_smembers)

    async def sismember(self, name: str, value: str) -> bool:
        """Check if value is member of set."""

        async def _sismember():
            return await self._client.sismember(name, value)

        return await self._circuit_breaker.call(_sismember)

    @property
    def circuit_state(self) -> CircuitState:
        """Get current circuit breaker state."""
        return self._circuit_breaker.state


# Global Redis client instance
redis_client = RedisClient()


async def get_redis() -> RedisClient:
    """Dependency for getting Redis client."""
    return redis_client
