"""
Tests for authentication service and auth router endpoints.

Covers password hashing, JWT tokens, user creation, login/register flows,
password reset, refresh tokens, and org switching.
"""

import os
import time
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.organizations import (
    Organization,
    OrganizationMembership,
    OrgRole,
    Plan,
    Team,
)
from app.models.agents import Agent, AgentStatus, TrustLevel
from app.models.users import User
from app.services.auth import (
    authenticate_user,
    complete_password_reset,
    create_access_token,
    create_refresh_token,
    create_user,
    hash_password,
    initiate_password_reset,
    verify_password,
    verify_token,
)


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
    """Seed the plans table with a free tier required by create_user."""
    plan = Plan(
        id="free",
        name="Free",
        max_agents=1,
        max_rules=10,
        max_vault_entries=5,
        max_team_members=1,
        max_teams=1,
        price_monthly_cents=0,
        price_yearly_cents=0,
        features={
            "slack_integration": False,
            "oauth_login": False,
            "sso": False,
            "audit_export": False,
        },
    )
    db_session.add(plan)
    await db_session.commit()
    return plan


@pytest_asyncio.fixture
async def registered_user(db_session: AsyncSession, seed_plans):
    """Create a user via the auth service (includes org, team, membership)."""
    user = await create_user(
        db_session, "alice@example.com", "alice", "StrongPass1!"
    )
    await db_session.commit()
    return user


# ---------------------------------------------------------------------------
# 1. Password hashing and verification
# ---------------------------------------------------------------------------


class TestPasswordHashing:
    def test_hash_password_returns_bcrypt_string(self):
        hashed = hash_password("mysecretpassword")
        assert hashed.startswith("$2")
        assert len(hashed) > 50

    def test_verify_password_correct(self):
        hashed = hash_password("correct-horse-battery-staple")
        assert verify_password("correct-horse-battery-staple", hashed) is True

    def test_verify_password_incorrect(self):
        hashed = hash_password("correct-horse-battery-staple")
        assert verify_password("wrong-password", hashed) is False

    def test_hash_password_unique_salts(self):
        h1 = hash_password("same-password")
        h2 = hash_password("same-password")
        assert h1 != h2  # bcrypt uses unique salts


# ---------------------------------------------------------------------------
# 2. JWT token creation and verification
# ---------------------------------------------------------------------------


class TestJWTTokens:
    def test_create_and_verify_access_token(self):
        user_id = uuid4()
        org_id = uuid4()
        token = create_access_token(user_id, org_id, "owner")
        payload = verify_token(token)

        assert payload["sub"] == str(user_id)
        assert payload["org"] == str(org_id)
        assert payload["role"] == "owner"
        assert payload["type"] == "access"

    def test_create_and_verify_refresh_token(self):
        user_id = uuid4()
        token = create_refresh_token(user_id)
        payload = verify_token(token)

        assert payload["sub"] == str(user_id)
        assert payload["type"] == "refresh"
        assert "org" not in payload

    def test_verify_token_invalid_string(self):
        with pytest.raises(ValueError, match="Invalid token"):
            verify_token("not-a-real-token")

    def test_verify_token_tampered(self):
        token = create_access_token(uuid4(), uuid4(), "member")
        tampered = token[:-5] + "XXXXX"
        with pytest.raises(ValueError):
            verify_token(tampered)

    def test_access_token_contains_expiry(self):
        token = create_access_token(uuid4(), uuid4(), "admin")
        payload = verify_token(token)
        assert "exp" in payload


# ---------------------------------------------------------------------------
# 3. Token expiry detection
# ---------------------------------------------------------------------------


class TestTokenExpiry:
    def test_expired_access_token(self):
        """Manually craft an expired token and verify it raises."""
        from jose import jwt as jose_jwt
        from app.config import get_settings

        settings = get_settings()
        payload = {
            "sub": str(uuid4()),
            "org": str(uuid4()),
            "role": "member",
            "exp": datetime.now(timezone.utc) - timedelta(seconds=10),
            "type": "access",
        }
        expired_token = jose_jwt.encode(
            payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM
        )
        with pytest.raises(ValueError, match="expired"):
            verify_token(expired_token)


# ---------------------------------------------------------------------------
# 4. User creation (auto org/team/membership)
# ---------------------------------------------------------------------------


class TestUserCreation:
    @pytest.mark.asyncio
    async def test_create_user_basic(self, db_session, seed_plans):
        user = await create_user(
            db_session, "bob@example.com", "bob", "SecurePass1!"
        )
        await db_session.commit()

        assert isinstance(user.id, UUID)
        assert user.email == "bob@example.com"
        assert user.username == "bob"
        assert user.is_active is True
        assert user.default_organization_id is not None

    @pytest.mark.asyncio
    async def test_create_user_creates_organization(self, db_session, seed_plans):
        user = await create_user(
            db_session, "carol@example.com", "carol", "SecurePass1!"
        )
        await db_session.commit()

        from sqlalchemy import select

        org_result = await db_session.execute(
            select(Organization).where(
                Organization.id == user.default_organization_id
            )
        )
        org = org_result.scalar_one()
        assert org.name == "carol's Organization"
        assert org.plan_id == "free"
        assert org.is_active is True

    @pytest.mark.asyncio
    async def test_create_user_creates_team(self, db_session, seed_plans):
        user = await create_user(
            db_session, "dan@example.com", "dan", "SecurePass1!"
        )
        await db_session.commit()

        from sqlalchemy import select

        team_result = await db_session.execute(
            select(Team).where(
                Team.organization_id == user.default_organization_id
            )
        )
        team = team_result.scalar_one()
        assert team.name == "Default"
        assert team.is_default is True

    @pytest.mark.asyncio
    async def test_create_user_creates_membership(self, db_session, seed_plans):
        user = await create_user(
            db_session, "eve@example.com", "eve", "SecurePass1!"
        )
        await db_session.commit()

        from sqlalchemy import select

        mem_result = await db_session.execute(
            select(OrganizationMembership).where(
                OrganizationMembership.user_id == user.id
            )
        )
        membership = mem_result.scalar_one()
        assert membership.role == OrgRole.OWNER
        assert membership.organization_id == user.default_organization_id


# ---------------------------------------------------------------------------
# 5. User authentication
# ---------------------------------------------------------------------------


class TestAuthentication:
    @pytest.mark.asyncio
    async def test_authenticate_valid_credentials(
        self, db_session, registered_user
    ):
        user = await authenticate_user(
            db_session, "alice@example.com", "StrongPass1!"
        )
        assert user.id == registered_user.id
        assert user.last_login_at is not None

    @pytest.mark.asyncio
    async def test_authenticate_wrong_password(
        self, db_session, registered_user
    ):
        with pytest.raises(ValueError, match="Invalid email or password"):
            await authenticate_user(
                db_session, "alice@example.com", "WrongPassword!"
            )

    @pytest.mark.asyncio
    async def test_authenticate_nonexistent_email(
        self, db_session, registered_user
    ):
        with pytest.raises(ValueError, match="Invalid email or password"):
            await authenticate_user(
                db_session, "nobody@example.com", "Whatever1!"
            )


# ---------------------------------------------------------------------------
# 6. Password reset flow
# ---------------------------------------------------------------------------


class TestPasswordReset:
    @pytest.mark.asyncio
    async def test_initiate_password_reset_existing_user(
        self, db_session, registered_user
    ):
        token = await initiate_password_reset(db_session, "alice@example.com")
        await db_session.commit()
        assert token is not None
        assert len(token) > 20

    @pytest.mark.asyncio
    async def test_initiate_password_reset_nonexistent_user(
        self, db_session, seed_plans
    ):
        token = await initiate_password_reset(
            db_session, "nobody@example.com"
        )
        assert token is None

    @pytest.mark.asyncio
    async def test_complete_password_reset(self, db_session, registered_user):
        token = await initiate_password_reset(db_session, "alice@example.com")
        await db_session.commit()

        success = await complete_password_reset(
            db_session, token, "BrandNewPass1!"
        )
        await db_session.commit()
        assert success is True

        # Verify new password works
        user = await authenticate_user(
            db_session, "alice@example.com", "BrandNewPass1!"
        )
        assert user.id == registered_user.id

    @pytest.mark.asyncio
    async def test_complete_password_reset_invalid_token(
        self, db_session, seed_plans
    ):
        success = await complete_password_reset(
            db_session, "fake-token-value", "Whatever1!"
        )
        assert success is False


# ---------------------------------------------------------------------------
# 7. Register endpoint
# ---------------------------------------------------------------------------


class TestRegisterEndpoint:
    @pytest.mark.asyncio
    async def test_register_success(self, client, seed_plans):
        resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "username": "newuser",
                "password": "SecurePass1!",
                "password_confirm": "SecurePass1!",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == "newuser@example.com"
        assert data["username"] == "newuser"
        assert data["is_active"] is True
        assert data["default_organization_id"] is not None

        # Cookies should be set
        assert "snapper_access_token" in resp.cookies
        assert "snapper_refresh_token" in resp.cookies

    @pytest.mark.asyncio
    async def test_register_duplicate_email(self, client, seed_plans):
        # First registration
        await client.post(
            "/api/v1/auth/register",
            json={
                "email": "dup@example.com",
                "username": "dup_first",
                "password": "SecurePass1!",
                "password_confirm": "SecurePass1!",
            },
        )
        # Second registration with same email
        resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "dup@example.com",
                "username": "dup_second",
                "password": "SecurePass1!",
                "password_confirm": "SecurePass1!",
            },
        )
        assert resp.status_code == 409
        assert "email" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_register_duplicate_username(self, client, seed_plans):
        await client.post(
            "/api/v1/auth/register",
            json={
                "email": "first@example.com",
                "username": "samename",
                "password": "SecurePass1!",
                "password_confirm": "SecurePass1!",
            },
        )
        resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "second@example.com",
                "username": "samename",
                "password": "SecurePass1!",
                "password_confirm": "SecurePass1!",
            },
        )
        assert resp.status_code == 409
        assert "username" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_register_password_mismatch(self, client, seed_plans):
        resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "mismatch@example.com",
                "username": "mismatch",
                "password": "SecurePass1!",
                "password_confirm": "DifferentPass1!",
            },
        )
        assert resp.status_code == 422  # Pydantic validation error

    @pytest.mark.asyncio
    async def test_register_short_password(self, client, seed_plans):
        resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "short@example.com",
                "username": "shortpw",
                "password": "abc",
                "password_confirm": "abc",
            },
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 8. Login endpoint
# ---------------------------------------------------------------------------


class TestLoginEndpoint:
    @pytest.mark.asyncio
    async def test_login_success(self, client, seed_plans):
        # Register first
        await client.post(
            "/api/v1/auth/register",
            json={
                "email": "logintest@example.com",
                "username": "logintest",
                "password": "SecurePass1!",
                "password_confirm": "SecurePass1!",
            },
        )
        # Login
        resp = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "logintest@example.com",
                "password": "SecurePass1!",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == "logintest@example.com"
        assert "snapper_access_token" in resp.cookies
        assert "snapper_refresh_token" in resp.cookies

    @pytest.mark.asyncio
    async def test_login_wrong_password(self, client, seed_plans):
        await client.post(
            "/api/v1/auth/register",
            json={
                "email": "wrongpw@example.com",
                "username": "wrongpw",
                "password": "SecurePass1!",
                "password_confirm": "SecurePass1!",
            },
        )
        resp = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "wrongpw@example.com",
                "password": "TotallyWrong!",
            },
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_login_nonexistent_user(self, client, seed_plans):
        resp = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "ghost@example.com",
                "password": "Whatever1!",
            },
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 9. Logout endpoint
# ---------------------------------------------------------------------------


class TestLogoutEndpoint:
    @pytest.mark.asyncio
    async def test_logout_clears_cookies(self, client, seed_plans):
        # Register (sets cookies)
        reg_resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "logout@example.com",
                "username": "logoutuser",
                "password": "SecurePass1!",
                "password_confirm": "SecurePass1!",
            },
        )
        assert "snapper_access_token" in reg_resp.cookies

        # Logout
        logout_resp = await client.post("/api/v1/auth/logout")
        assert logout_resp.status_code == 200
        assert logout_resp.json()["message"] == "Logged out"

        # The Set-Cookie headers should delete the cookies (max-age=0 or empty value)
        cookie_headers = logout_resp.headers.get_list("set-cookie")
        cookie_text = " ".join(cookie_headers)
        assert "snapper_access_token" in cookie_text
        assert "snapper_refresh_token" in cookie_text


# ---------------------------------------------------------------------------
# 10. /me endpoint
# ---------------------------------------------------------------------------


class TestMeEndpoint:
    @pytest.mark.asyncio
    async def test_me_authenticated(self, client, seed_plans):
        # Register to get cookies
        reg_resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "metest@example.com",
                "username": "metest",
                "password": "SecurePass1!",
                "password_confirm": "SecurePass1!",
            },
        )
        # Extract cookies and set them on the client
        access_token = reg_resp.cookies.get("snapper_access_token")
        refresh_token = reg_resp.cookies.get("snapper_refresh_token")
        client.cookies.set("snapper_access_token", access_token)
        client.cookies.set("snapper_refresh_token", refresh_token)

        resp = await client.get("/api/v1/auth/me")
        assert resp.status_code == 200
        data = resp.json()
        assert data["user"]["email"] == "metest@example.com"
        assert isinstance(data["organizations"], list)
        assert len(data["organizations"]) >= 1
        assert data["organizations"][0]["role"] == "owner"

    @pytest.mark.asyncio
    async def test_me_unauthenticated(self, client, seed_plans):
        """Without auth cookies, /me returns 401."""
        resp = await client.get(
            "/api/v1/auth/me",
            headers={"accept": "application/json"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 11. Refresh token flow
# ---------------------------------------------------------------------------


class TestRefreshFlow:
    @pytest.mark.asyncio
    async def test_refresh_with_valid_refresh_token(self, client, seed_plans):
        # Register
        reg_resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "refresh@example.com",
                "username": "refreshuser",
                "password": "SecurePass1!",
                "password_confirm": "SecurePass1!",
            },
        )
        refresh_token = reg_resp.cookies.get("snapper_refresh_token")
        client.cookies.set("snapper_refresh_token", refresh_token)

        resp = await client.post("/api/v1/auth/refresh")
        assert resp.status_code == 200
        assert "access_token" in resp.json()
        assert "snapper_access_token" in resp.cookies

    @pytest.mark.asyncio
    async def test_refresh_without_cookie(self, client, seed_plans):
        resp = await client.post("/api/v1/auth/refresh")
        assert resp.status_code == 401
        assert "refresh token" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_refresh_with_invalid_token(self, client, seed_plans):
        client.cookies.set("snapper_refresh_token", "garbage-token-value")
        resp = await client.post("/api/v1/auth/refresh")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 12. Switch org
# ---------------------------------------------------------------------------


class TestSwitchOrg:
    @pytest.mark.asyncio
    async def test_switch_org_success(self, client, db_session, seed_plans):
        """User can switch to an org they belong to."""
        # Register user A (auto creates org A)
        reg_resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "switcher@example.com",
                "username": "switcher",
                "password": "SecurePass1!",
                "password_confirm": "SecurePass1!",
            },
        )
        user_data = reg_resp.json()
        user_id = UUID(user_data["id"])
        org_a_id = UUID(user_data["default_organization_id"])

        # Create a second org and add membership directly in DB
        org_b = Organization(
            id=uuid4(),
            name="Second Org",
            slug="second-org",
            plan_id="free",
            is_active=True,
        )
        db_session.add(org_b)
        await db_session.flush()

        membership = OrganizationMembership(
            id=uuid4(),
            user_id=user_id,
            organization_id=org_b.id,
            role=OrgRole.MEMBER,
            accepted_at=datetime.now(timezone.utc),
        )
        db_session.add(membership)
        await db_session.commit()

        # Set auth cookies
        access_token = reg_resp.cookies.get("snapper_access_token")
        refresh_token = reg_resp.cookies.get("snapper_refresh_token")
        client.cookies.set("snapper_access_token", access_token)
        client.cookies.set("snapper_refresh_token", refresh_token)

        # Switch to org B
        resp = await client.post(
            "/api/v1/auth/switch-org",
            json={"organization_id": str(org_b.id)},
        )
        assert resp.status_code == 200
        assert resp.json()["organization_id"] == str(org_b.id)
        assert "snapper_access_token" in resp.cookies

    @pytest.mark.asyncio
    async def test_switch_org_not_member(self, client, db_session, seed_plans):
        """User cannot switch to an org they do not belong to."""
        reg_resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "notmember@example.com",
                "username": "notmember",
                "password": "SecurePass1!",
                "password_confirm": "SecurePass1!",
            },
        )
        access_token = reg_resp.cookies.get("snapper_access_token")
        refresh_token = reg_resp.cookies.get("snapper_refresh_token")
        client.cookies.set("snapper_access_token", access_token)
        client.cookies.set("snapper_refresh_token", refresh_token)

        random_org_id = uuid4()
        resp = await client.post(
            "/api/v1/auth/switch-org",
            json={"organization_id": str(random_org_id)},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_switch_org_unauthenticated(self, client, seed_plans):
        resp = await client.post(
            "/api/v1/auth/switch-org",
            json={"organization_id": str(uuid4())},
            headers={"accept": "application/json"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 13. Forgot / reset password endpoints
# ---------------------------------------------------------------------------


class TestPasswordResetEndpoints:
    @pytest.mark.asyncio
    async def test_forgot_password_existing_email(self, client, seed_plans):
        # Register first
        await client.post(
            "/api/v1/auth/register",
            json={
                "email": "forgot@example.com",
                "username": "forgotuser",
                "password": "SecurePass1!",
                "password_confirm": "SecurePass1!",
            },
        )
        resp = await client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "forgot@example.com"},
        )
        assert resp.status_code == 200
        # Always returns same message to prevent email enumeration
        assert "reset link" in resp.json()["message"].lower()

    @pytest.mark.asyncio
    async def test_forgot_password_nonexistent_email(self, client, seed_plans):
        resp = await client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "ghost@example.com"},
        )
        # Same 200 response to prevent email enumeration
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_reset_password_invalid_token(self, client, seed_plans):
        resp = await client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": "bogus-token",
                "new_password": "NewSecure1!",
                "password_confirm": "NewSecure1!",
            },
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_full_reset_flow_via_endpoints(
        self, client, db_session, seed_plans
    ):
        """Register, initiate reset via service, then complete via endpoint."""
        await client.post(
            "/api/v1/auth/register",
            json={
                "email": "fullreset@example.com",
                "username": "fullreset",
                "password": "OldPass123!",
                "password_confirm": "OldPass123!",
            },
        )
        # Get reset token via service (simulates email link)
        token = await initiate_password_reset(db_session, "fullreset@example.com")
        await db_session.commit()
        assert token is not None

        # Complete via endpoint
        resp = await client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": token,
                "new_password": "NewPass456!",
                "password_confirm": "NewPass456!",
            },
        )
        assert resp.status_code == 200

        # Verify login with new password
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "fullreset@example.com",
                "password": "NewPass456!",
            },
        )
        assert login_resp.status_code == 200


# ---------------------------------------------------------------------------
# 14. Auth middleware behavior
# ---------------------------------------------------------------------------


class TestAuthMiddlewareBehavior:
    @pytest.mark.asyncio
    async def test_exempt_path_login_accessible(self, client, seed_plans):
        """GET /login should be accessible without auth."""
        resp = await client.get(
            "/login",
            headers={"accept": "text/html"},
            follow_redirects=False,
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_exempt_prefix_evaluate_accessible(self, client, seed_plans):
        """POST /api/v1/rules/evaluate should be exempt from auth."""
        resp = await client.post(
            "/api/v1/rules/evaluate",
            json={
                "agent_id": "test-agent",
                "tool_name": "test_tool",
                "tool_input": "echo hello",
            },
        )
        # Should NOT be 401 — it's an exempt path
        assert resp.status_code != 401

    @pytest.mark.asyncio
    async def test_protected_html_redirects_to_login(self, client, db_session, seed_plans):
        """GET / without auth + Accept: text/html should redirect to /login."""
        # Create an agent so the onboarding middleware doesn't redirect to /wizard
        agent = Agent(
            id=uuid4(),
            name="dummy-agent-for-redirect-test",
            external_id="dummy-redirect",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
        )
        db_session.add(agent)
        await db_session.commit()

        resp = await client.get(
            "/",
            headers={"accept": "text/html"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "/login" in resp.headers.get("location", "")

    @pytest.mark.asyncio
    async def test_protected_api_returns_401(self, client, seed_plans):
        """GET /api/v1/agents without auth should return 401 JSON."""
        resp = await client.get(
            "/api/v1/agents",
            headers={"accept": "application/json"},
        )
        assert resp.status_code == 401
        assert "detail" in resp.json()

    @pytest.mark.asyncio
    async def test_auto_refresh_expired_access(self, client, seed_plans):
        """Expired access token + valid refresh token should auto-rotate."""
        from datetime import datetime, timedelta, timezone
        from jose import jwt as jose_jwt
        from app.config import get_settings

        # Register to get valid tokens
        reg_resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "autorefresh@example.com",
                "username": "autorefresh",
                "password": "SecurePass1!",
                "password_confirm": "SecurePass1!",
            },
        )
        refresh_token = reg_resp.cookies.get("snapper_refresh_token")

        # Create an expired access token
        settings = get_settings()
        expired_payload = {
            "sub": reg_resp.json()["id"],
            "org": reg_resp.json()["default_organization_id"],
            "role": "owner",
            "exp": datetime.now(timezone.utc) - timedelta(seconds=10),
            "type": "access",
        }
        expired_access = jose_jwt.encode(
            expired_payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM
        )

        client.cookies.set("snapper_access_token", expired_access)
        client.cookies.set("snapper_refresh_token", refresh_token)

        # The middleware should auto-refresh and return 200
        resp = await client.get("/api/v1/auth/me")
        assert resp.status_code == 200
        assert resp.json()["user"]["email"] == "autorefresh@example.com"

    @pytest.mark.asyncio
    async def test_both_tokens_invalid(self, client, seed_plans):
        """Garbage cookies should return 401."""
        client.cookies.set("snapper_access_token", "garbage-token")
        client.cookies.set("snapper_refresh_token", "also-garbage")

        resp = await client.get(
            "/api/v1/auth/me",
            headers={"accept": "application/json"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 15. Cookie security attributes
# ---------------------------------------------------------------------------


class TestCookieSecurityAttributes:
    @pytest.mark.asyncio
    async def test_register_sets_httponly_cookies(self, client, seed_plans):
        """Registration response cookies should be httponly."""
        resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "cookietest@example.com",
                "username": "cookietest",
                "password": "SecurePass1!",
                "password_confirm": "SecurePass1!",
            },
        )
        assert resp.status_code == 200
        cookie_headers = resp.headers.get_list("set-cookie")
        cookie_text = " ".join(cookie_headers).lower()
        assert "httponly" in cookie_text

    @pytest.mark.asyncio
    async def test_login_cookies_samesite_lax(self, client, seed_plans):
        """Login response cookies should have samesite=lax."""
        await client.post(
            "/api/v1/auth/register",
            json={
                "email": "samesite@example.com",
                "username": "samesite",
                "password": "SecurePass1!",
                "password_confirm": "SecurePass1!",
            },
        )
        resp = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "samesite@example.com",
                "password": "SecurePass1!",
            },
        )
        assert resp.status_code == 200
        cookie_headers = resp.headers.get_list("set-cookie")
        cookie_text = " ".join(cookie_headers).lower()
        assert "samesite=lax" in cookie_text

    @pytest.mark.asyncio
    async def test_login_cookies_path_root(self, client, seed_plans):
        """Login response cookies should have path=/."""
        await client.post(
            "/api/v1/auth/register",
            json={
                "email": "pathtest@example.com",
                "username": "pathtest",
                "password": "SecurePass1!",
                "password_confirm": "SecurePass1!",
            },
        )
        resp = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "pathtest@example.com",
                "password": "SecurePass1!",
            },
        )
        cookie_headers = resp.headers.get_list("set-cookie")
        cookie_text = " ".join(cookie_headers).lower()
        assert "path=/" in cookie_text


# ---------------------------------------------------------------------------
# 16. Forgot password + email integration
# ---------------------------------------------------------------------------


class TestForgotPasswordEmailIntegration:
    @pytest.mark.asyncio
    async def test_forgot_password_calls_email_service(
        self, client, seed_plans, monkeypatch
    ):
        """Forgot password should call send_password_reset for existing users."""
        # Register
        await client.post(
            "/api/v1/auth/register",
            json={
                "email": "emailcall@example.com",
                "username": "emailcall",
                "password": "SecurePass1!",
                "password_confirm": "SecurePass1!",
            },
        )

        called_with = {}

        def mock_send(to, token, base_url=""):
            called_with["to"] = to
            called_with["token"] = token
            return False  # SMTP not configured

        monkeypatch.setattr("app.services.email.send_password_reset", mock_send)

        resp = await client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "emailcall@example.com"},
        )
        assert resp.status_code == 200
        assert called_with.get("to") == "emailcall@example.com"

    @pytest.mark.asyncio
    async def test_forgot_password_works_without_smtp(self, client, seed_plans):
        """Forgot password returns 200 even without SMTP configured."""
        await client.post(
            "/api/v1/auth/register",
            json={
                "email": "nosmtp@example.com",
                "username": "nosmtp",
                "password": "SecurePass1!",
                "password_confirm": "SecurePass1!",
            },
        )
        resp = await client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "nosmtp@example.com"},
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_nonexistent_email_skips_email(
        self, client, seed_plans, monkeypatch
    ):
        """Forgot password for nonexistent email should not call email service."""
        called = {"count": 0}

        def mock_send(to, token, base_url=""):
            called["count"] += 1
            return False

        monkeypatch.setattr("app.services.email.send_password_reset", mock_send)

        resp = await client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "nonexistent@example.com"},
        )
        assert resp.status_code == 200
        assert called["count"] == 0
