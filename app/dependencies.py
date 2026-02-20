"""Dependency injection providers for FastAPI."""

from typing import Annotated, AsyncGenerator, Optional
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
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


# --- Organization context ---


async def get_optional_org_id(request: Request) -> Optional[UUID]:
    """Get org ID from request state if available (set by auth middleware).

    Returns None when no user auth context exists (backward compat for
    API-key-only access where scoping uses agent.organization_id).
    """
    org_id = getattr(request.state, "org_id", None)
    if org_id:
        try:
            return UUID(str(org_id))
        except (ValueError, AttributeError):
            pass
    return None


async def require_org_id(request: Request) -> UUID:
    """Require org ID from request state. Raises 400 if missing."""
    org_id = await get_optional_org_id(request)
    if not org_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization context required",
        )
    return org_id


OptionalOrgIdDep = Annotated[Optional[UUID], Depends(get_optional_org_id)]
RequiredOrgIdDep = Annotated[UUID, Depends(require_org_id)]


async def verify_resource_org(
    resource_org_id: Optional[UUID],
    caller_org_id: Optional[UUID],
) -> None:
    """Raise 404 if resource belongs to a different org.

    Returns 404 (not 403) to avoid leaking existence of resources in
    other organizations.  Skips check when running in self-hosted mode
    or when either side has no org context (backward compat).
    """
    from app.config import get_settings

    if get_settings().SELF_HOSTED:
        return
    if caller_org_id is None or resource_org_id is None:
        return
    if resource_org_id != caller_org_id:
        raise HTTPException(status_code=404, detail="Not found")


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
        request.state.rate_limit_limit = self.max_requests

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
default_rate_limit = RateLimiter(max_requests=300, window_seconds=60)
strict_rate_limit = RateLimiter(max_requests=30, window_seconds=60)
api_rate_limit = RateLimiter(max_requests=3000, window_seconds=60, key_prefix="api_v1")

# Security-hardened rate limiters
vault_write_rate_limit = RateLimiter(max_requests=30, window_seconds=60, key_prefix="vault_write")
approval_status_rate_limit = RateLimiter(max_requests=360, window_seconds=60, key_prefix="approval_status")
approval_decide_rate_limit = RateLimiter(max_requests=30, window_seconds=60, key_prefix="approval_decide")
telegram_webhook_rate_limit = RateLimiter(max_requests=300, window_seconds=60, key_prefix="telegram_webhook")


# --- RBAC ---

async def get_current_user(request: Request, db: AsyncSession = Depends(get_db)):
    """Get current authenticated user from request state."""
    from app.models.users import User, ROLE_PERMISSIONS

    user_id = getattr(request.state, "user_id", None)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    stmt = select(User).where(User.id == UUID(str(user_id)), User.deleted_at.is_(None))
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or disabled",
        )
    # Merge role-based permissions into user.permissions for has_permission checks
    role_perms = ROLE_PERMISSIONS.get(user.role, [])
    user._effective_permissions = set(user.permissions or []) | set(role_perms)
    return user


class RoleChecker:
    """RBAC dependency that checks if the current user has a required permission."""

    def __init__(self, required_permission: str):
        self.required_permission = required_permission

    async def __call__(self, request: Request, db: AsyncSession = Depends(get_db)):
        # Skip RBAC when no user session (API key auth, unauthenticated requests)
        user_id = getattr(request.state, "user_id", None)
        if not user_id:
            return None
        user = await get_current_user(request, db)
        effective = getattr(user, "_effective_permissions", set())
        if user.is_admin or self.required_permission in effective:
            return user
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Insufficient permissions: requires '{self.required_permission}'",
        )


# Pre-configured RBAC checkers
require_manage_rules = RoleChecker("rules:write")
require_delete_rules = RoleChecker("rules:delete")
require_manage_agents = RoleChecker("agents:write")
require_delete_agents = RoleChecker("agents:delete")
require_manage_vault = RoleChecker("rules:write")
require_manage_org = RoleChecker("settings:write")


# --- Meta Admin ---


async def require_meta_admin(
    request: Request, db: AsyncSession = Depends(get_db),
):
    """Require platform operator access. Returns User, raises 403 if not meta admin."""
    user = await get_current_user(request, db)
    if not user.is_meta_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Platform admin access required",
        )
    return user


RequireMetaAdminDep = Annotated[object, Depends(require_meta_admin)]


def get_impersonation_context(request: Request) -> Optional[dict]:
    """Return impersonation info if the current request is impersonated."""
    imp = getattr(request.state, "impersonating_user_id", None)
    if imp:
        return {"impersonated_by": imp, "is_impersonation": True}
    return None
