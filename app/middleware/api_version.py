"""API version header middleware."""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class APIVersionMiddleware(BaseHTTPMiddleware):
    """Adds X-API-Version and rate limit headers to API responses."""

    API_VERSION = "1.0.0"

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        if request.url.path.startswith("/api/"):
            response.headers["X-API-Version"] = self.API_VERSION
            remaining = getattr(request.state, "rate_limit_remaining", None)
            reset = getattr(request.state, "rate_limit_reset", None)
            limit = getattr(request.state, "rate_limit_limit", None)
            if remaining is not None:
                response.headers.setdefault("X-RateLimit-Remaining", str(remaining))
            if reset is not None:
                response.headers.setdefault("X-RateLimit-Reset", str(reset))
            if limit is not None:
                response.headers.setdefault("X-RateLimit-Limit", str(limit))
        return response
