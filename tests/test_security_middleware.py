"""Tests for security middleware."""

import pytest
from unittest.mock import MagicMock, patch
from uuid import uuid4

from httpx import AsyncClient
from starlette.requests import Request
from starlette.responses import Response

from app.middleware.security import SecurityMiddleware


class TestOriginValidation:
    """Tests for origin header validation."""

    @pytest.mark.asyncio
    async def test_allowed_origin_passes(self, client: AsyncClient):
        """Valid origin from ALLOWED_ORIGINS passes validation."""
        # http://testserver is in ALLOWED_ORIGINS in conftest
        response = await client.get(
            "/api/v1/agents/",
            headers={"Origin": "http://testserver"},
        )
        # Should not be blocked by origin validation (may be 200 or 404)
        assert response.status_code != 403 or "Origin" not in response.json().get("detail", "")

    @pytest.mark.asyncio
    async def test_disallowed_origin_blocked(self, client: AsyncClient):
        """Origin not in ALLOWED_ORIGINS is blocked with 403."""
        with patch("app.middleware.security.settings") as mock_settings:
            mock_settings.VALIDATE_WEBSOCKET_ORIGIN = True
            mock_settings.allowed_origins_list = ["http://testserver"]
            mock_settings.allowed_hosts_list = ["testserver", "localhost"]
            mock_settings.REQUIRE_LOCALHOST_ONLY = False

            middleware = SecurityMiddleware(app=MagicMock())
            mock_request = MagicMock(spec=Request)
            mock_request.headers = {"origin": "http://evil.com", "host": "testserver"}

            error = middleware._validate_origin(mock_request)
            assert error is not None
            assert "not allowed" in error

    @pytest.mark.asyncio
    async def test_no_origin_header_passes(self, client: AsyncClient):
        """Requests without Origin header pass (same-origin)."""
        # Make a request without Origin header
        response = await client.get("/health")
        assert response.status_code == 200


class TestHostValidation:
    """Tests for host header validation."""

    @pytest.mark.asyncio
    async def test_allowed_host_passes(self, client: AsyncClient):
        """Valid host from ALLOWED_HOSTS passes validation."""
        # testserver is in ALLOWED_HOSTS in conftest
        response = await client.get("/health")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_disallowed_host_blocked(self):
        """Host not in ALLOWED_HOSTS returns error."""
        with patch("app.middleware.security.settings") as mock_settings:
            mock_settings.allowed_hosts_list = ["testserver", "localhost"]

            middleware = SecurityMiddleware(app=MagicMock())
            mock_request = MagicMock(spec=Request)
            mock_request.headers = {"host": "evil.com:8080"}

            error = middleware._validate_host(mock_request)
            assert error is not None
            assert "not allowed" in error

    @pytest.mark.asyncio
    async def test_missing_host_blocked(self):
        """Missing Host header returns error."""
        middleware = SecurityMiddleware(app=MagicMock())
        mock_request = MagicMock(spec=Request)
        mock_request.headers.get.return_value = None

        error = middleware._validate_host(mock_request)
        assert error is not None
        assert "Missing Host header" in error


class TestLocalhostRestriction:
    """Tests for localhost-only restriction."""

    @pytest.mark.asyncio
    async def test_localhost_allowed(self):
        """127.0.0.1 passes localhost validation when enabled."""
        with patch("app.middleware.security.settings") as mock_settings:
            mock_settings.REQUIRE_LOCALHOST_ONLY = True

            middleware = SecurityMiddleware(app=MagicMock())
            mock_request = MagicMock(spec=Request)
            mock_request.client.host = "127.0.0.1"

            error = middleware._validate_localhost(mock_request)
            assert error is None

    @pytest.mark.asyncio
    async def test_remote_ip_blocked(self):
        """Remote IP is blocked when localhost_only is enabled."""
        with patch("app.middleware.security.settings") as mock_settings:
            mock_settings.REQUIRE_LOCALHOST_ONLY = True

            middleware = SecurityMiddleware(app=MagicMock())
            mock_request = MagicMock(spec=Request)
            mock_request.client.host = "192.168.1.100"

            error = middleware._validate_localhost(mock_request)
            assert error is not None
            assert "localhost only" in error


class TestSecurityHeaders:
    """Tests for security headers."""

    @pytest.mark.asyncio
    async def test_csp_header_present(self, client: AsyncClient):
        """Content-Security-Policy header is set on responses."""
        response = await client.get("/health")

        assert "Content-Security-Policy" in response.headers
        csp = response.headers["Content-Security-Policy"]
        assert "default-src 'self'" in csp

    @pytest.mark.asyncio
    async def test_exempt_paths_get_headers(self, client: AsyncClient):
        """/health endpoint gets X-Request-ID header."""
        response = await client.get("/health")

        assert "X-Request-ID" in response.headers
        # Verify it's a valid UUID format (36 chars with dashes)
        request_id = response.headers["X-Request-ID"]
        assert len(request_id) == 36
