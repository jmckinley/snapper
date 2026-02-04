"""Security middleware for request validation and protection."""

import logging
import uuid
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Security middleware implementing critical protections.

    Protections:
    - CVE-2026-25253: Origin header validation for WebSocket/CORS
    - Auth bypass: Host header validation
    - Request ID generation for tracing
    - Security headers (CSP, X-Frame-Options, etc.)
    """

    # Paths exempt from security checks (health checks, static files)
    EXEMPT_PATHS = {
        "/health",
        "/health/ready",
        "/api/docs",
        "/api/redoc",
        "/api/openapi.json",
    }

    # Security headers to add to all responses
    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Pragma": "no-cache",
    }

    async def dispatch(
        self, request: Request, call_next: Callable
    ) -> Response:
        """Process request through security checks."""
        # Generate request ID
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id

        # Check if path is exempt
        if self._is_exempt_path(request.url.path):
            response = await call_next(request)
            return self._add_security_headers(response, request_id)

        # Validate Origin header (CVE-2026-25253 mitigation)
        origin_error = self._validate_origin(request)
        if origin_error:
            logger.warning(
                f"Origin validation failed: {origin_error}",
                extra={"request_id": request_id, "path": request.url.path},
            )
            return JSONResponse(
                status_code=403,
                content={"detail": origin_error},
                headers={"X-Request-ID": request_id},
            )

        # Validate Host header (auth bypass mitigation)
        host_error = self._validate_host(request)
        if host_error:
            logger.warning(
                f"Host validation failed: {host_error}",
                extra={"request_id": request_id, "path": request.url.path},
            )
            return JSONResponse(
                status_code=403,
                content={"detail": host_error},
                headers={"X-Request-ID": request_id},
            )

        # Validate localhost restriction if enabled
        localhost_error = self._validate_localhost(request)
        if localhost_error:
            logger.warning(
                f"Localhost validation failed: {localhost_error}",
                extra={"request_id": request_id, "path": request.url.path},
            )
            return JSONResponse(
                status_code=403,
                content={"detail": localhost_error},
                headers={"X-Request-ID": request_id},
            )

        # Process request
        response = await call_next(request)

        # Add security headers
        return self._add_security_headers(response, request_id)

    def _is_exempt_path(self, path: str) -> bool:
        """Check if path is exempt from security checks."""
        # Exact match
        if path in self.EXEMPT_PATHS:
            return True

        # Static files
        if path.startswith("/static/"):
            return True

        return False

    def _validate_origin(self, request: Request) -> str | None:
        """
        Validate Origin header.

        CVE-2026-25253 mitigation: Prevent WebSocket RCE by validating
        that requests come from allowed origins.
        """
        if not settings.VALIDATE_WEBSOCKET_ORIGIN:
            return None

        origin = request.headers.get("origin")

        # No origin header - could be same-origin request or server-to-server
        # For API requests without origin, we allow (covered by other checks)
        if not origin:
            return None

        # Check if origin is in allowed list
        if origin not in settings.allowed_origins_list:
            return f"Origin '{origin}' is not allowed"

        return None

    def _validate_host(self, request: Request) -> str | None:
        """
        Validate Host header.

        Prevents host header injection attacks that could bypass
        authentication checks.
        """
        host = request.headers.get("host")

        if not host:
            return "Missing Host header"

        # Extract hostname (remove port if present)
        hostname = host.split(":")[0]

        if hostname not in settings.allowed_hosts_list:
            return f"Host '{hostname}' is not allowed"

        return None

    def _validate_localhost(self, request: Request) -> str | None:
        """
        Validate request comes from localhost.

        Auth bypass mitigation: In localhost-only mode, reject
        requests from non-local addresses.
        """
        if not settings.REQUIRE_LOCALHOST_ONLY:
            return None

        client_host = request.client.host if request.client else None

        if not client_host:
            return "Unable to determine client address"

        allowed_localhost = ["127.0.0.1", "::1", "localhost"]
        if client_host not in allowed_localhost:
            return f"Access restricted to localhost only"

        return None

    def _add_security_headers(
        self, response: Response, request_id: str
    ) -> Response:
        """Add security headers to response."""
        # Add standard security headers
        for header, value in self.SECURITY_HEADERS.items():
            response.headers[header] = value

        # Add request ID for tracing
        response.headers["X-Request-ID"] = request_id

        # Add CSP header (more restrictive)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )

        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for logging all requests for audit purposes."""

    async def dispatch(
        self, request: Request, call_next: Callable
    ) -> Response:
        """Log request and response details."""
        request_id = getattr(request.state, "request_id", str(uuid.uuid4()))

        # Log request
        logger.info(
            f"Request: {request.method} {request.url.path}",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "client_ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
            },
        )

        # Process request
        response = await call_next(request)

        # Log response
        logger.info(
            f"Response: {response.status_code}",
            extra={
                "request_id": request_id,
                "status_code": response.status_code,
            },
        )

        return response
