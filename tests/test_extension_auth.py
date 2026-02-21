"""Tests for browser extension authentication endpoints."""

import pytest
from uuid import uuid4
from unittest.mock import AsyncMock, patch, MagicMock

from app.models.users import User


class TestExtensionLogin:
    """Tests for POST /api/v1/auth/extension/login."""

    @pytest.mark.asyncio
    async def test_extension_login_success(self, async_client, db_session):
        """Successful extension login returns tokens in body."""
        # Create a test user with hashed password
        from app.services.auth import get_password_hash
        user = User(
            id=uuid4(),
            email="ext-test@example.com",
            username="ext-test",
            hashed_password=get_password_hash("testpass123"),
            is_active=True,
        )
        db_session.add(user)
        await db_session.commit()

        # Create org membership
        from app.models.organizations import Organization, OrganizationMembership, OrgRole
        org = Organization(id=uuid4(), name="Test Org", slug="test-org")
        db_session.add(org)
        await db_session.commit()

        membership = OrganizationMembership(
            user_id=user.id,
            organization_id=org.id,
            role=OrgRole.ADMIN,
        )
        db_session.add(membership)
        user.default_organization_id = org.id
        await db_session.commit()

        response = await async_client.post(
            "/api/v1/auth/extension/login",
            json={"email": "ext-test@example.com", "password": "testpass123"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["user"]["email"] == "ext-test@example.com"
        assert data["user"]["role"] == "admin"
        assert data["expires_in"] > 0
        assert data["organization"]["name"] == "Test Org"

    @pytest.mark.asyncio
    async def test_extension_login_bad_credentials(self, async_client):
        """Extension login with bad credentials returns 401."""
        response = await async_client.post(
            "/api/v1/auth/extension/login",
            json={"email": "noone@example.com", "password": "wrong"},
        )

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_extension_login_mfa_blocked(self, async_client, db_session):
        """Extension login for MFA-enabled user returns 403."""
        from app.services.auth import get_password_hash
        user = User(
            id=uuid4(),
            email="mfa-test@example.com",
            username="mfa-test",
            hashed_password=get_password_hash("testpass123"),
            is_active=True,
            totp_enabled=True,
            totp_secret="dummy_secret",
        )
        db_session.add(user)
        await db_session.commit()

        response = await async_client.post(
            "/api/v1/auth/extension/login",
            json={"email": "mfa-test@example.com", "password": "testpass123"},
        )

        assert response.status_code == 403
        assert "MFA" in response.json()["detail"]


class TestExtensionRefresh:
    """Tests for POST /api/v1/auth/extension/refresh."""

    @pytest.mark.asyncio
    async def test_extension_refresh_success(self, async_client, db_session):
        """Valid refresh token returns new access token."""
        from app.services.auth import create_refresh_token, get_password_hash
        user = User(
            id=uuid4(),
            email="refresh-test@example.com",
            username="refresh-test",
            hashed_password=get_password_hash("testpass123"),
            is_active=True,
        )
        db_session.add(user)
        await db_session.commit()

        # Create org membership for token generation
        from app.models.organizations import Organization, OrganizationMembership, OrgRole
        org = Organization(id=uuid4(), name="Refresh Org", slug="refresh-org")
        db_session.add(org)
        await db_session.commit()

        membership = OrganizationMembership(
            user_id=user.id,
            organization_id=org.id,
            role=OrgRole.MEMBER,
        )
        db_session.add(membership)
        user.default_organization_id = org.id
        await db_session.commit()

        refresh_token = create_refresh_token(user.id)

        response = await async_client.post(
            "/api/v1/auth/extension/refresh",
            json={"refresh_token": refresh_token},
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["expires_in"] > 0

    @pytest.mark.asyncio
    async def test_extension_refresh_invalid_token(self, async_client):
        """Invalid refresh token returns 401."""
        response = await async_client.post(
            "/api/v1/auth/extension/refresh",
            json={"refresh_token": "invalid.token.here"},
        )

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_extension_refresh_access_token_rejected(self, async_client, db_session):
        """Using an access token (not refresh) returns 401."""
        from app.services.auth import create_access_token
        token = create_access_token(uuid4(), uuid4(), "admin")

        response = await async_client.post(
            "/api/v1/auth/extension/refresh",
            json={"refresh_token": token},
        )

        assert response.status_code == 401
        assert "Invalid token type" in response.json()["detail"]


class TestExtensionAuthMiddleware:
    """Test that extension auth paths are exempt from auth middleware."""

    @pytest.mark.asyncio
    async def test_extension_login_no_session_required(self, async_client):
        """Extension login doesn't require existing session cookies."""
        response = await async_client.post(
            "/api/v1/auth/extension/login",
            json={"email": "test@test.com", "password": "wrong"},
        )
        # Should get 401 (bad credentials), not 302 (redirect to login)
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_extension_refresh_no_session_required(self, async_client):
        """Extension refresh doesn't require existing session cookies."""
        response = await async_client.post(
            "/api/v1/auth/extension/refresh",
            json={"refresh_token": "invalid"},
        )
        assert response.status_code == 401
