"""Authentication middleware for protecting dashboard and HTML routes."""

import logging
from typing import Callable
from uuid import UUID

from sqlalchemy import select
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from app.services.auth import create_access_token, verify_token

logger = logging.getLogger(__name__)


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Starlette middleware that protects dashboard (HTML) routes.

    Behavior:
    - SELF_HOSTED mode: pass through (no auth required)
    - Valid access token cookie: sets request.state user context, proceeds
    - Expired access + valid refresh: auto-rotates access token, proceeds
    - No valid tokens + HTML request: redirects to /login
    - No valid tokens + API request: returns 401 JSON
    """

    # Exact paths exempt from auth
    EXEMPT_PATHS = {
        "/login",
        "/register",
        "/forgot-password",
        "/reset-password",
        "/health",
        "/health/ready",
        "/favicon.ico",
        "/wizard",
        "/terms",
    }

    # Specific auth API paths exempt from auth (but NOT /me and /switch-org)
    EXEMPT_AUTH_PATHS = {
        "/api/v1/auth/register",
        "/api/v1/auth/login",
        "/api/v1/auth/logout",
        "/api/v1/auth/refresh",
        "/api/v1/auth/forgot-password",
        "/api/v1/auth/reset-password",
        "/api/v1/auth/mfa/verify",
    }

    # Path prefixes exempt from auth
    EXEMPT_PREFIXES = (
        "/static/",
        "/api/v1/rules/evaluate",
        "/api/v1/setup/",
        "/api/v1/telegram/",
        "/api/v1/slack/",
        "/api/v1/approvals/",
        "/api/v1/billing/webhook",
        "/api/docs",
        "/api/redoc",
        "/api/openapi.json",
        "/auth/saml/",
        "/auth/oidc/",
        "/scim/v2/",
        "/metrics",
    )

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request through authentication checks."""
        from app.config import get_settings

        settings = get_settings()

        # In self-hosted mode, skip authentication entirely
        if settings.SELF_HOSTED:
            return await call_next(request)

        path = request.url.path

        # Check if path is exempt
        if self._is_exempt(path):
            return await call_next(request)

        # Pass through requests with API key auth (validated at router level)
        api_key = request.headers.get("x-api-key") or ""
        auth_header = request.headers.get("authorization") or ""
        if api_key.startswith("snp_") or auth_header.startswith("Bearer snp_"):
            return await call_next(request)

        # Try to authenticate from access token cookie
        access_token = request.cookies.get("snapper_access_token")
        refresh_token = request.cookies.get("snapper_refresh_token")

        # Attempt 1: Valid access token
        if access_token:
            try:
                payload = verify_token(access_token)
            except ValueError:
                # Access token invalid/expired, fall through to refresh
                payload = None
            else:
                if payload.get("type") == "access":
                    self._set_request_state(request, payload)
                    return await call_next(request)

        # Attempt 2: Refresh token -> auto-rotate access token
        if refresh_token:
            try:
                refresh_payload = verify_token(refresh_token)
            except ValueError:
                # Refresh token also invalid/expired
                refresh_payload = None
            else:
                if refresh_payload.get("type") == "refresh":
                    user_id = refresh_payload.get("sub")
                    if user_id:
                        # We need org_id and role for the new access token.
                        # Read from the expired access token if available, or
                        # use defaults that will be corrected on next /me call.
                        org_id = None
                        role = "member"
                        if access_token:
                            try:
                                # Decode without verification to get claims
                                from jose import jwt as jose_jwt

                                expired_payload = jose_jwt.decode(
                                    access_token,
                                    settings.SECRET_KEY,
                                    algorithms=[settings.JWT_ALGORITHM],
                                    options={"verify_exp": False},
                                )
                                org_id = expired_payload.get("org")
                                role = expired_payload.get("role", "member")
                            except Exception:
                                pass

                        # Resolve org_id: if not available from expired token,
                        # look up the user's default org from DB
                        if not org_id:
                            try:
                                from app.database import get_db_context
                                from app.models.users import User

                                async with get_db_context() as _db:
                                    _row = await _db.execute(
                                        select(User.default_organization_id).where(
                                            User.id == UUID(user_id)
                                        )
                                    )
                                    _default_org = _row.scalar_one_or_none()
                                    if _default_org:
                                        org_id = str(_default_org)
                            except Exception:
                                pass

                        if not org_id:
                            # No org context at all — deny rather than using user_id as fake org
                            return self._unauthenticated_response(request)

                        # Create new access token
                        new_access_token = create_access_token(
                            UUID(user_id),
                            UUID(org_id),
                            role,
                        )

                        # Set user context
                        new_payload = verify_token(new_access_token)
                        self._set_request_state(request, new_payload)

                        # Process the request
                        response = await call_next(request)

                        # Set the new access token cookie on the response
                        response.set_cookie(
                            key="snapper_access_token",
                            value=new_access_token,
                            httponly=True,
                            secure=not settings.DEBUG,
                            samesite="lax",
                            path="/",
                            max_age=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                        )
                        return response

        # No valid authentication found
        return self._unauthenticated_response(request)

    def _is_exempt(self, path: str) -> bool:
        """Check if the path is exempt from authentication."""
        if path in self.EXEMPT_PATHS:
            return True

        if path in self.EXEMPT_AUTH_PATHS:
            return True

        for prefix in self.EXEMPT_PREFIXES:
            if path.startswith(prefix):
                return True

        return False

    def _set_request_state(self, request: Request, payload: dict) -> None:
        """Set user context on request.state from JWT payload."""
        request.state.user_id = payload.get("sub")
        request.state.org_id = payload.get("org")
        request.state.user_role = payload.get("role")
        request.state.is_meta_admin = payload.get("meta", False)
        request.state.impersonating_user_id = payload.get("imp")

    def _unauthenticated_response(self, request: Request) -> Response:
        """Return appropriate response for unauthenticated requests."""
        accept = request.headers.get("accept", "")

        # HTML requests get redirected to login
        if "text/html" in accept and not request.url.path.startswith("/api/"):
            return RedirectResponse(url="/login", status_code=302)

        # API/JSON requests get 401
        return JSONResponse(
            status_code=401,
            content={"detail": "Authentication required"},
        )
