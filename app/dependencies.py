"""Dependency injection providers for FastAPI."""

from typing import Annotated, AsyncGenerator

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.database import get_db
from app.redis_client import RedisClient, get_redis


# Type aliases for dependency injection
SettingsDep = Annotated[Settings, Depends(get_settings)]
DbSessionDep = Annotated[AsyncSession, Depends(get_db)]
RedisDep = Annotated[RedisClient, Depends(get_redis)]


async def verify_localhost_only(request: Request) -> None:
    """
    Verify request comes from localhost.
    Mitigates authentication bypass vulnerabilities.
    """
    settings = get_settings()

    if not settings.REQUIRE_LOCALHOST_ONLY:
        return

    client_host = request.client.host if request.client else None
    allowed_localhost = ["127.0.0.1", "::1", "localhost"]

    if client_host not in allowed_localhost:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access restricted to localhost only",
        )


async def verify_origin(request: Request) -> None:
    """
    Verify Origin header for WebSocket/CORS requests.
    Mitigates CVE-2026-25253.
    """
    settings = get_settings()

    if not settings.VALIDATE_WEBSOCKET_ORIGIN:
        return

    origin = request.headers.get("origin")

    # No origin header is acceptable for same-origin requests
    if not origin:
        return

    if origin not in settings.allowed_origins_list:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Origin '{origin}' not allowed",
        )


async def get_request_id(request: Request) -> str:
    """Get or generate request ID for tracing."""
    request_id = request.headers.get("X-Request-ID")
    if not request_id:
        import uuid

        request_id = str(uuid.uuid4())
    return request_id


# Combined security dependencies
LocalhostOnlyDep = Annotated[None, Depends(verify_localhost_only)]
OriginVerifiedDep = Annotated[None, Depends(verify_origin)]
RequestIdDep = Annotated[str, Depends(get_request_id)]


class RateLimiter:
    """Rate limiter dependency factory."""

    def __init__(
        self,
        max_requests: int = 100,
        window_seconds: int = 60,
        key_prefix: str = "api",
    ):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.key_prefix = key_prefix

    async def __call__(
        self,
        request: Request,
        redis: RedisDep,
    ) -> None:
        """Check rate limit for request."""
        # Use client IP as rate limit key
        client_ip = request.client.host if request.client else "unknown"
        key = f"{self.key_prefix}:{client_ip}"

        allowed, remaining, retry_after = await redis.check_rate_limit(
            key=key,
            max_requests=self.max_requests,
            window_seconds=self.window_seconds,
        )

        # Add rate limit headers to response (via request state)
        request.state.rate_limit_remaining = remaining
        request.state.rate_limit_reset = retry_after

        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Retry after {retry_after} seconds.",
                headers={
                    "X-RateLimit-Remaining": str(remaining),
                    "Retry-After": str(retry_after),
                },
            )


# Pre-configured rate limiters
default_rate_limit = RateLimiter(max_requests=100, window_seconds=60)
strict_rate_limit = RateLimiter(max_requests=10, window_seconds=60)
api_rate_limit = RateLimiter(max_requests=1000, window_seconds=60, key_prefix="api_v1")

# Security-hardened rate limiters
vault_write_rate_limit = RateLimiter(max_requests=10, window_seconds=60, key_prefix="vault_write")
approval_status_rate_limit = RateLimiter(max_requests=120, window_seconds=60, key_prefix="approval_status")
approval_decide_rate_limit = RateLimiter(max_requests=10, window_seconds=60, key_prefix="approval_decide")
telegram_webhook_rate_limit = RateLimiter(max_requests=60, window_seconds=60, key_prefix="telegram_webhook")
