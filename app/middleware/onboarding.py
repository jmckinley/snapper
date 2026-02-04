"""First-run onboarding middleware.

Redirects users to the setup wizard if no agents are registered.
"""

import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse
from sqlalchemy import select, func

from app.database import async_session_factory as async_session_maker
from app.models.agents import Agent

logger = logging.getLogger(__name__)

# Paths that should NOT trigger redirect (always accessible)
EXCLUDED_PATHS = {
    # Setup and wizard paths
    "/wizard",
    "/api/v1/setup",
    # Static assets
    "/static",
    # Health checks
    "/health",
    "/health/ready",
    # API docs
    "/api/docs",
    "/api/redoc",
    "/api/openapi.json",
    # Favicon
    "/favicon.ico",
}

# Paths that start with these prefixes are excluded
EXCLUDED_PREFIXES = (
    "/api/v1/setup",
    "/static/",
    "/api/docs",
    "/api/redoc",
)


class OnboardingMiddleware(BaseHTTPMiddleware):
    """Middleware to redirect to setup wizard on first run.

    Checks if any agents are registered. If not, redirects dashboard
    requests to the setup wizard for a guided onboarding experience.
    """

    def __init__(self, app, check_interval: int = 60):
        """Initialize the middleware.

        Args:
            app: The ASGI application
            check_interval: Seconds between database checks (caches result)
        """
        super().__init__(app)
        self._cache_has_agents: bool | None = None
        self._cache_timestamp: float = 0
        self._check_interval = check_interval

    async def dispatch(self, request: Request, call_next):
        """Process the request and redirect if needed."""
        path = request.url.path

        # Skip check for excluded paths
        if self._should_skip(path):
            return await call_next(request)

        # Skip for API requests (let them through regardless)
        if path.startswith("/api/"):
            return await call_next(request)

        # Check if we need to redirect to wizard
        if await self._is_first_run():
            # Only redirect HTML page requests, not XHR/fetch
            accept = request.headers.get("accept", "")
            if "text/html" in accept:
                logger.info(f"First run detected, redirecting {path} to /wizard")
                return RedirectResponse(url="/wizard", status_code=302)

        return await call_next(request)

    def _should_skip(self, path: str) -> bool:
        """Check if path should skip the onboarding check."""
        if path in EXCLUDED_PATHS:
            return True
        for prefix in EXCLUDED_PREFIXES:
            if path.startswith(prefix):
                return True
        return False

    async def _is_first_run(self) -> bool:
        """Check if this is a first-run scenario (no agents registered).

        Caches the result to avoid hitting the database on every request.
        """
        import time

        now = time.time()

        # Return cached value if still valid
        if (
            self._cache_has_agents is not None
            and (now - self._cache_timestamp) < self._check_interval
        ):
            return not self._cache_has_agents

        # Query database
        try:
            async with async_session_maker() as session:
                result = await session.execute(
                    select(func.count(Agent.id)).where(Agent.deleted_at.is_(None))
                )
                count = result.scalar() or 0

            self._cache_has_agents = count > 0
            self._cache_timestamp = now
            return not self._cache_has_agents

        except Exception as e:
            logger.error(f"Error checking first run status: {e}")
            # On error, don't redirect (fail open for UX)
            return False
