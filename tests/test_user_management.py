"""
Tests for user management API endpoints:
- Admin unlock
- Password change
- Profile update
- Org-level policy settings
- Active sessions management
"""

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.organizations import Organization, OrganizationMembership, OrgRole, Plan, Team
from app.models.users import User
from app.services.auth import create_access_token, create_user, hash_password


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _enable_auth_middleware(monkeypatch):
    """Override SELF_HOSTED=false so the auth middleware enforces auth."""
    monkeypatch.setenv("SELF_HOSTED", "false")
    from app.config import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest_asyncio.fixture
async def seed_plans(db_session: AsyncSession):
    """Seed the plans table with a free tier."""
    plan = Plan(
        id="free",
        name="Free",
        max_agents=10,
        max_rules=50,
        max_vault_entries=10,
        max_team_members=5,
        max_teams=3,
        price_monthly_cents=0,
        price_yearly_cents=0,
        features={},
    )
    db_session.add(plan)
    await db_session.flush()
    return plan


@pytest_asyncio.fixture
async def admin_user(db_session: AsyncSession, seed_plans):
    """Create an admin user with their own org."""
    user = await create_user(db_session, "admin@example.com", "admin_user", "AdminPass1!")
    user.role = "admin"
    await db_session.flush()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def regular_user(db_session: AsyncSession, seed_plans, admin_user):
    """Create a regular user and add them to the admin's org for cross-org tests."""
    user = await create_user(db_session, "user@example.com", "regular_user", "UserPass1!")
    # Add regular_user to admin's org so admin can manage them
    membership = OrganizationMembership(
        id=uuid4(),
        user_id=user.id,
        organization_id=admin_user.default_organization_id,
        role=OrgRole.MEMBER,
    )
    db_session.add(membership)
    await db_session.flush()
    await db_session.refresh(user)
    return user


def _auth_cookie(user: User, role: str = "owner") -> dict:
    """Build auth cookie dict for a user."""
    token = create_access_token(user.id, user.default_organization_id, role)
    return {"snapper_access_token": token}


# ---------------------------------------------------------------------------
# Admin Unlock
# ---------------------------------------------------------------------------


class TestAdminUnlock:
    """Tests for POST /api/v1/auth/admin/unlock/{user_id}."""

    async def test_unlock_locked_account(self, client: AsyncClient, admin_user: User, regular_user: User, db_session):
        """Admin can unlock a locked account."""
        # Lock the regular user
        regular_user.failed_login_attempts = 5
        regular_user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=30)
        await db_session.flush()

        resp = await client.post(
            f"/api/v1/auth/admin/unlock/{regular_user.id}",
            cookies=_auth_cookie(admin_user, "admin"),
        )
        assert resp.status_code == 200
        assert resp.json()["message"] == "Account unlocked"

        # Verify the user is unlocked
        await db_session.refresh(regular_user)
        assert regular_user.failed_login_attempts == 0
        assert regular_user.locked_until is None

    async def test_unlock_not_locked_account(self, client: AsyncClient, admin_user: User, regular_user: User):
        """Unlocking a non-locked account returns informational message."""
        resp = await client.post(
            f"/api/v1/auth/admin/unlock/{regular_user.id}",
            cookies=_auth_cookie(admin_user, "admin"),
        )
        assert resp.status_code == 200
        assert "not locked" in resp.json()["message"]

    async def test_unlock_requires_admin(self, client: AsyncClient, regular_user: User, admin_user: User):
        """Non-admin users cannot unlock accounts."""
        resp = await client.post(
            f"/api/v1/auth/admin/unlock/{admin_user.id}",
            cookies=_auth_cookie(regular_user, "viewer"),
        )
        assert resp.status_code == 403

    async def test_unlock_nonexistent_user(self, client: AsyncClient, admin_user: User):
        """Unlocking a nonexistent user returns 404."""
        fake_id = uuid4()
        resp = await client.post(
            f"/api/v1/auth/admin/unlock/{fake_id}",
            cookies=_auth_cookie(admin_user, "admin"),
        )
        assert resp.status_code == 404

    async def test_unlock_unauthenticated(self, client: AsyncClient, regular_user: User):
        """Unauthenticated requests are rejected."""
        resp = await client.post(f"/api/v1/auth/admin/unlock/{regular_user.id}")
        assert resp.status_code in (401, 302)


# ---------------------------------------------------------------------------
# Password Change
# ---------------------------------------------------------------------------


class TestPasswordChange:
    """Tests for POST /api/v1/auth/change-password."""

    async def test_change_password_success(self, client: AsyncClient, regular_user: User):
        """Logged-in user can change their password."""
        resp = await client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "UserPass1!",
                "new_password": "NewPassword2!",
                "password_confirm": "NewPassword2!",
            },
            cookies=_auth_cookie(regular_user),
        )
        assert resp.status_code == 200
        assert resp.json()["message"] == "Password changed successfully"

    async def test_change_password_wrong_current(self, client: AsyncClient, regular_user: User):
        """Wrong current password is rejected."""
        resp = await client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "WrongPassword!",
                "new_password": "NewPassword2!",
                "password_confirm": "NewPassword2!",
            },
            cookies=_auth_cookie(regular_user),
        )
        assert resp.status_code == 400
        assert "incorrect" in resp.json()["detail"].lower()

    async def test_change_password_same_as_current(self, client: AsyncClient, regular_user: User):
        """New password can't be the same as current."""
        resp = await client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "UserPass1!",
                "new_password": "UserPass1!",
                "password_confirm": "UserPass1!",
            },
            cookies=_auth_cookie(regular_user),
        )
        assert resp.status_code == 400
        assert "different" in resp.json()["detail"].lower()

    async def test_change_password_mismatch(self, client: AsyncClient, regular_user: User):
        """Mismatched password confirmation is rejected."""
        resp = await client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "UserPass1!",
                "new_password": "NewPassword2!",
                "password_confirm": "DifferentPassword!",
            },
            cookies=_auth_cookie(regular_user),
        )
        assert resp.status_code == 422  # Pydantic validation

    async def test_change_password_too_short(self, client: AsyncClient, regular_user: User):
        """Short password is rejected."""
        resp = await client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "UserPass1!",
                "new_password": "short",
                "password_confirm": "short",
            },
            cookies=_auth_cookie(regular_user),
        )
        assert resp.status_code == 422

    async def test_change_password_unauthenticated(self, client: AsyncClient):
        """Unauthenticated requests are rejected."""
        resp = await client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "pass",
                "new_password": "NewPassword2!",
                "password_confirm": "NewPassword2!",
            },
        )
        assert resp.status_code in (401, 302)


# ---------------------------------------------------------------------------
# Profile Update
# ---------------------------------------------------------------------------


class TestProfileUpdate:
    """Tests for PATCH /api/v1/auth/me."""

    async def test_update_full_name(self, client: AsyncClient, regular_user: User):
        """User can update their full name."""
        resp = await client.patch(
            "/api/v1/auth/me",
            json={"full_name": "John Doe"},
            cookies=_auth_cookie(regular_user),
        )
        assert resp.status_code == 200
        assert resp.json()["full_name"] == "John Doe"

    async def test_update_username(self, client: AsyncClient, regular_user: User):
        """User can update their username."""
        resp = await client.patch(
            "/api/v1/auth/me",
            json={"username": "new_username"},
            cookies=_auth_cookie(regular_user),
        )
        assert resp.status_code == 200
        assert resp.json()["username"] == "new_username"

    async def test_update_username_taken(self, client: AsyncClient, regular_user: User, admin_user: User):
        """Cannot update to an already-taken username."""
        resp = await client.patch(
            "/api/v1/auth/me",
            json={"username": "admin_user"},
            cookies=_auth_cookie(regular_user),
        )
        assert resp.status_code == 409

    async def test_update_no_fields(self, client: AsyncClient, regular_user: User):
        """Empty update is rejected."""
        resp = await client.patch(
            "/api/v1/auth/me",
            json={},
            cookies=_auth_cookie(regular_user),
        )
        assert resp.status_code == 400

    async def test_update_username_too_short(self, client: AsyncClient, regular_user: User):
        """Short username is rejected."""
        resp = await client.patch(
            "/api/v1/auth/me",
            json={"username": "ab"},
            cookies=_auth_cookie(regular_user),
        )
        assert resp.status_code == 422

    async def test_update_unauthenticated(self, client: AsyncClient):
        """Unauthenticated requests are rejected."""
        resp = await client.patch(
            "/api/v1/auth/me",
            json={"full_name": "Test"},
        )
        assert resp.status_code in (401, 302)


# ---------------------------------------------------------------------------
# Org-Level Policy Settings
# ---------------------------------------------------------------------------


class TestOrgPolicySettings:
    """Tests for GET/PATCH /api/v1/organizations/{org_id}/settings/policy."""

    async def test_get_default_settings(self, client: AsyncClient, admin_user: User):
        """Get default org policy settings."""
        org_id = str(admin_user.default_organization_id)
        resp = await client.get(
            f"/api/v1/organizations/{org_id}/settings/policy",
            cookies=_auth_cookie(admin_user),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["audit_retention_days"] == 90
        assert data["require_mfa"] is False
        assert data["max_login_attempts"] == 5
        assert data["lockout_duration_minutes"] == 30
        assert data["session_timeout_minutes"] == 30

    async def test_update_settings(self, client: AsyncClient, admin_user: User):
        """Admin can update org policy settings."""
        org_id = str(admin_user.default_organization_id)
        resp = await client.patch(
            f"/api/v1/organizations/{org_id}/settings/policy",
            json={
                "audit_retention_days": 365,
                "require_mfa": True,
                "max_login_attempts": 10,
            },
            cookies=_auth_cookie(admin_user, "admin"),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["audit_retention_days"] == 365
        assert data["require_mfa"] is True
        assert data["max_login_attempts"] == 10
        # Unchanged values should remain defaults
        assert data["lockout_duration_minutes"] == 30
        assert data["session_timeout_minutes"] == 30

    async def test_update_settings_persists(self, client: AsyncClient, admin_user: User):
        """Updated settings persist on re-read."""
        org_id = str(admin_user.default_organization_id)
        await client.patch(
            f"/api/v1/organizations/{org_id}/settings/policy",
            json={"audit_retention_days": 180},
            cookies=_auth_cookie(admin_user, "admin"),
        )
        resp = await client.get(
            f"/api/v1/organizations/{org_id}/settings/policy",
            cookies=_auth_cookie(admin_user),
        )
        assert resp.status_code == 200
        assert resp.json()["audit_retention_days"] == 180

    async def test_update_settings_validation(self, client: AsyncClient, admin_user: User):
        """Invalid settings values are rejected."""
        org_id = str(admin_user.default_organization_id)
        # Too low retention
        resp = await client.patch(
            f"/api/v1/organizations/{org_id}/settings/policy",
            json={"audit_retention_days": 3},
            cookies=_auth_cookie(admin_user, "admin"),
        )
        assert resp.status_code == 422

    async def test_update_settings_requires_admin(self, client: AsyncClient, regular_user: User):
        """Non-admin users cannot update org settings."""
        org_id = str(regular_user.default_organization_id)
        resp = await client.patch(
            f"/api/v1/organizations/{org_id}/settings/policy",
            json={"require_mfa": True},
            cookies=_auth_cookie(regular_user, "viewer"),
        )
        assert resp.status_code == 403

    async def test_update_empty_settings(self, client: AsyncClient, admin_user: User):
        """Empty settings update is rejected."""
        org_id = str(admin_user.default_organization_id)
        resp = await client.patch(
            f"/api/v1/organizations/{org_id}/settings/policy",
            json={},
            cookies=_auth_cookie(admin_user, "admin"),
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Session Management
# ---------------------------------------------------------------------------


class TestSessionManagement:
    """Tests for GET /api/v1/auth/sessions and DELETE /api/v1/auth/sessions/{id}."""

    async def test_list_sessions_empty(self, client: AsyncClient, regular_user: User):
        """List sessions returns empty list when no sessions are stored."""
        resp = await client.get(
            "/api/v1/auth/sessions",
            cookies=_auth_cookie(regular_user),
        )
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    async def test_session_created_on_login(self, client: AsyncClient, regular_user: User, redis):
        """Login creates a session record in Redis."""
        # Login via the API
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "user@example.com", "password": "UserPass1!"},
        )
        assert resp.status_code == 200

        # Use the cookies from login to list sessions
        cookies = dict(resp.cookies)
        resp2 = await client.get("/api/v1/auth/sessions", cookies=cookies)
        assert resp2.status_code == 200
        sessions = resp2.json()
        assert len(sessions) >= 1
        # At least one session should be marked as current
        assert any(s["is_current"] for s in sessions)

    async def test_revoke_nonexistent_session(self, client: AsyncClient, regular_user: User):
        """Revoking a nonexistent session returns 404."""
        resp = await client.delete(
            "/api/v1/auth/sessions/nonexistent-session-id",
            cookies=_auth_cookie(regular_user),
        )
        assert resp.status_code == 404

    async def test_sessions_unauthenticated(self, client: AsyncClient):
        """Unauthenticated requests are rejected."""
        resp = await client.get("/api/v1/auth/sessions")
        assert resp.status_code in (401, 302)
