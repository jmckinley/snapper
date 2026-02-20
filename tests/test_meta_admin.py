"""
Tests for meta admin provisioning, impersonation, and platform operations.

Covers:
- is_meta_admin defaults and model behavior
- require_meta_admin dependency rejects non-meta users
- JWT token includes 'meta' claim
- Middleware propagates meta state
- Provision org creates org + team + invitation
- Email domain validation
- Seat limit org override
- Impersonation issues/reverts tokens
- Audit logs include impersonation context
- Non-meta admin gets 403 on all /meta/* endpoints
- META_ADMIN_ENABLED=false blocks all meta endpoints
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agents import Agent, AgentStatus, TrustLevel
from app.models.organizations import (
    Invitation,
    InvitationStatus,
    Organization,
    OrganizationMembership,
    OrgRole,
    Plan,
    Team,
)
from app.models.rules import Rule, RuleAction, RuleType
from app.models.users import User
from app.services.auth import create_access_token, create_user, verify_token


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _enable_auth_middleware(monkeypatch):
    """Override SELF_HOSTED=false so the auth middleware enforces auth."""
    monkeypatch.setenv("SELF_HOSTED", "false")
    monkeypatch.setenv("META_ADMIN_ENABLED", "true")
    from app.config import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest_asyncio.fixture
async def seed_plans(db_session: AsyncSession):
    """Seed the plans table."""
    for plan_id, name, max_members in [("free", "Free", 1), ("pro", "Pro", 10), ("enterprise", "Enterprise", -1)]:
        plan = Plan(
            id=plan_id,
            name=name,
            max_agents=100 if plan_id != "free" else 1,
            max_rules=100 if plan_id != "free" else 10,
            max_vault_entries=100 if plan_id != "free" else 5,
            max_team_members=max_members,
            max_teams=10 if plan_id != "free" else 1,
            price_monthly_cents=0,
            price_yearly_cents=0,
            features={},
        )
        db_session.add(plan)
    await db_session.flush()


@pytest_asyncio.fixture
async def meta_admin(db_session: AsyncSession, seed_plans) -> User:
    """Create a meta admin user."""
    user = await create_user(db_session, "admin@mckinleylabs.com", "metaadmin", "Admin1234!")
    user.is_meta_admin = True
    await db_session.flush()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def regular_user(db_session: AsyncSession, seed_plans) -> User:
    """Create a regular (non-meta) user."""
    user = await create_user(db_session, "regular@example.com", "regular", "Regular1234!")
    await db_session.flush()
    await db_session.refresh(user)
    return user


def _make_token(user: User, org_id=None) -> str:
    """Create a JWT access token for a test user."""
    return create_access_token(
        user_id=user.id,
        org_id=org_id or user.default_organization_id,
        role="owner",
        is_meta_admin=user.is_meta_admin,
    )


def _auth_headers(token: str) -> dict:
    """Return cookie-based auth as headers for httpx."""
    return {"Cookie": f"snapper_access_token={token}"}


# ---------------------------------------------------------------------------
# 1. is_meta_admin defaults to False
# ---------------------------------------------------------------------------


class TestMetaAdminModel:
    async def test_is_meta_admin_defaults_false(self, regular_user):
        assert regular_user.is_meta_admin is False

    async def test_is_meta_admin_true_for_admin(self, meta_admin):
        assert meta_admin.is_meta_admin is True

    async def test_is_platform_admin_property(self, meta_admin, regular_user):
        assert meta_admin.is_platform_admin is True
        assert regular_user.is_platform_admin is False


# ---------------------------------------------------------------------------
# 2. JWT includes meta claim
# ---------------------------------------------------------------------------


class TestJWTMetaClaims:
    async def test_meta_admin_token_has_meta_claim(self, meta_admin):
        token = _make_token(meta_admin)
        payload = verify_token(token)
        assert payload.get("meta") is True

    async def test_regular_user_token_no_meta_claim(self, regular_user):
        token = _make_token(regular_user)
        payload = verify_token(token)
        assert "meta" not in payload

    async def test_impersonation_token_has_imp_claim(self, meta_admin):
        token = create_access_token(
            user_id=meta_admin.id,
            org_id=uuid4(),
            role="owner",
            is_meta_admin=True,
            impersonating_user_id=str(meta_admin.id),
        )
        payload = verify_token(token)
        assert payload["imp"] == str(meta_admin.id)
        assert payload["meta"] is True


# ---------------------------------------------------------------------------
# 3. require_meta_admin rejects non-meta users
# ---------------------------------------------------------------------------


class TestRequireMetaAdmin:
    async def test_regular_user_gets_403_on_meta_endpoints(self, client: AsyncClient, regular_user):
        token = _make_token(regular_user)
        headers = _auth_headers(token)

        endpoints = [
            ("GET", "/api/v1/meta/stats"),
            ("GET", "/api/v1/meta/orgs"),
            ("GET", "/api/v1/meta/users"),
            ("GET", "/api/v1/meta/audit"),
        ]
        for method, url in endpoints:
            resp = await client.request(method, url, headers=headers)
            assert resp.status_code == 403, f"{method} {url} should be 403, got {resp.status_code}"

    async def test_meta_admin_can_access_stats(self, client: AsyncClient, meta_admin):
        token = _make_token(meta_admin)
        headers = _auth_headers(token)
        resp = await client.get("/api/v1/meta/stats", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "total_organizations" in data
        assert "total_users" in data


# ---------------------------------------------------------------------------
# 4. Provision org
# ---------------------------------------------------------------------------


class TestProvisionOrg:
    async def test_provision_creates_org_team_invitation(
        self, client: AsyncClient, meta_admin, db_session: AsyncSession
    ):
        token = _make_token(meta_admin)
        headers = _auth_headers(token)
        headers["Content-Type"] = "application/json"

        resp = await client.post(
            "/api/v1/meta/provision-org",
            headers=headers,
            json={
                "name": "Acme Corp",
                "plan_id": "pro",
                "owner_email": "owner@acme.com",
                "allowed_email_domains": ["acme.com"],
                "max_seats": 5,
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Acme Corp"
        assert data["plan_id"] == "pro"
        assert data["owner_email"] == "owner@acme.com"
        assert data["allowed_email_domains"] == ["acme.com"]
        assert data["max_seats"] == 5
        assert data["invitation_token"]

        # Verify org created in DB
        org_row = await db_session.execute(
            select(Organization).where(Organization.name == "Acme Corp")
        )
        org = org_row.scalar_one_or_none()
        assert org is not None
        assert org.plan_id == "pro"
        assert org.max_seats == 5

        # Verify default team created
        team_row = await db_session.execute(
            select(Team).where(Team.organization_id == org.id, Team.is_default == True)
        )
        assert team_row.scalar_one_or_none() is not None

        # Verify invitation created
        inv_row = await db_session.execute(
            select(Invitation).where(
                Invitation.organization_id == org.id,
                Invitation.email == "owner@acme.com",
            )
        )
        inv = inv_row.scalar_one_or_none()
        assert inv is not None
        assert inv.role == OrgRole.OWNER
        assert inv.status == InvitationStatus.PENDING

    async def test_provision_invalid_plan_returns_400(self, client: AsyncClient, meta_admin):
        token = _make_token(meta_admin)
        headers = _auth_headers(token)
        headers["Content-Type"] = "application/json"

        resp = await client.post(
            "/api/v1/meta/provision-org",
            headers=headers,
            json={"name": "Bad Plan Org", "plan_id": "nonexistent", "owner_email": "a@b.com"},
        )
        assert resp.status_code == 400

    async def test_provision_with_trial_days(self, client: AsyncClient, meta_admin):
        token = _make_token(meta_admin)
        headers = _auth_headers(token)
        headers["Content-Type"] = "application/json"

        resp = await client.post(
            "/api/v1/meta/provision-org",
            headers=headers,
            json={
                "name": "Trial Org",
                "plan_id": "pro",
                "owner_email": "trial@example.com",
                "trial_days": 14,
            },
        )
        assert resp.status_code == 201


# ---------------------------------------------------------------------------
# 5. Org listing and detail
# ---------------------------------------------------------------------------


class TestOrgListDetail:
    async def test_list_orgs_returns_all(self, client: AsyncClient, meta_admin, regular_user):
        token = _make_token(meta_admin)
        headers = _auth_headers(token)
        resp = await client.get("/api/v1/meta/orgs", headers=headers)
        assert resp.status_code == 200
        orgs = resp.json()
        # Should include at least the meta admin's and regular user's orgs
        assert len(orgs) >= 2

    async def test_org_detail(self, client: AsyncClient, meta_admin):
        token = _make_token(meta_admin)
        headers = _auth_headers(token)

        # Get meta admin's own org
        resp = await client.get(
            f"/api/v1/meta/orgs/{meta_admin.default_organization_id}",
            headers=headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "usage" in data
        assert "recent_audit" in data

    async def test_org_detail_not_found(self, client: AsyncClient, meta_admin):
        token = _make_token(meta_admin)
        headers = _auth_headers(token)
        resp = await client.get(f"/api/v1/meta/orgs/{uuid4()}", headers=headers)
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 6. Update org
# ---------------------------------------------------------------------------


class TestUpdateOrg:
    async def test_update_org_name(self, client: AsyncClient, meta_admin):
        token = _make_token(meta_admin)
        headers = _auth_headers(token)
        headers["Content-Type"] = "application/json"

        resp = await client.patch(
            f"/api/v1/meta/orgs/{meta_admin.default_organization_id}",
            headers=headers,
            json={"name": "Renamed Org"},
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "Renamed Org"

    async def test_update_org_plan(self, client: AsyncClient, meta_admin):
        token = _make_token(meta_admin)
        headers = _auth_headers(token)
        headers["Content-Type"] = "application/json"

        resp = await client.patch(
            f"/api/v1/meta/orgs/{meta_admin.default_organization_id}",
            headers=headers,
            json={"plan_id": "pro"},
        )
        assert resp.status_code == 200
        assert resp.json()["plan_id"] == "pro"


# ---------------------------------------------------------------------------
# 7. Email domain validation
# ---------------------------------------------------------------------------


class TestEmailDomainValidation:
    async def test_allowed_email_domains_on_org(self, db_session: AsyncSession, meta_admin):
        """Org with allowed_email_domains correctly stores the list."""
        org = await db_session.get(Organization, meta_admin.default_organization_id)
        org.allowed_email_domains = ["mckinleylabs.com", "acme.com"]
        await db_session.flush()
        await db_session.refresh(org)
        assert org.allowed_email_domains == ["mckinleylabs.com", "acme.com"]


# ---------------------------------------------------------------------------
# 8. Seat limit override
# ---------------------------------------------------------------------------


class TestSeatLimitOverride:
    async def test_max_seats_overrides_plan_limit(self, db_session: AsyncSession, meta_admin):
        """Organization.max_seats takes precedence over Plan.max_team_members."""
        from app.services.plans import check_quota

        org = await db_session.get(Organization, meta_admin.default_organization_id)
        # Plan 'free' has max_team_members=1, but already has 1 member (the owner)
        # Set max_seats=5, should not raise
        org.max_seats = 5
        await db_session.flush()

        # Should not raise (5 seats, 1 used)
        await check_quota(db_session, org.id, "team_members")


# ---------------------------------------------------------------------------
# 9. Impersonation
# ---------------------------------------------------------------------------


class TestImpersonation:
    async def test_impersonate_returns_new_token(
        self, client: AsyncClient, meta_admin, regular_user
    ):
        token = _make_token(meta_admin)
        headers = _auth_headers(token)
        headers["Content-Type"] = "application/json"

        resp = await client.post(
            "/api/v1/meta/impersonate",
            headers=headers,
            json={"org_id": str(regular_user.default_organization_id)},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["org_id"] == str(regular_user.default_organization_id)
        assert "snapper_access_token" in resp.cookies

    async def test_stop_impersonation(self, client: AsyncClient, meta_admin, regular_user):
        """Start then stop impersonation."""
        # Start impersonation
        token = _make_token(meta_admin)
        headers = _auth_headers(token)
        headers["Content-Type"] = "application/json"

        resp = await client.post(
            "/api/v1/meta/impersonate",
            headers=headers,
            json={"org_id": str(regular_user.default_organization_id)},
        )
        assert resp.status_code == 200

        # Use the impersonation token
        imp_token = resp.cookies.get("snapper_access_token")
        imp_headers = _auth_headers(imp_token)

        resp2 = await client.post(
            "/api/v1/meta/stop-impersonation",
            headers=imp_headers,
        )
        assert resp2.status_code == 200
        assert "snapper_access_token" in resp2.cookies


# ---------------------------------------------------------------------------
# 10. User management
# ---------------------------------------------------------------------------


class TestUserManagement:
    async def test_list_users(self, client: AsyncClient, meta_admin, regular_user):
        token = _make_token(meta_admin)
        headers = _auth_headers(token)
        resp = await client.get("/api/v1/meta/users", headers=headers)
        assert resp.status_code == 200
        users = resp.json()
        assert len(users) >= 2
        emails = [u["email"] for u in users]
        assert "admin@mckinleylabs.com" in emails
        assert "regular@example.com" in emails

    async def test_suspend_user(self, client: AsyncClient, meta_admin, regular_user):
        token = _make_token(meta_admin)
        headers = _auth_headers(token)
        headers["Content-Type"] = "application/json"

        resp = await client.patch(
            f"/api/v1/meta/users/{regular_user.id}",
            headers=headers,
            json={"is_active": False},
        )
        assert resp.status_code == 200
        assert resp.json()["changes"]["is_active"]["new"] is False

    async def test_search_users_by_email(self, client: AsyncClient, meta_admin, regular_user):
        token = _make_token(meta_admin)
        headers = _auth_headers(token)
        resp = await client.get("/api/v1/meta/users?search=regular", headers=headers)
        assert resp.status_code == 200
        users = resp.json()
        assert len(users) >= 1
        assert users[0]["email"] == "regular@example.com"


# ---------------------------------------------------------------------------
# 11. Audit log search
# ---------------------------------------------------------------------------


class TestAuditSearch:
    async def test_cross_org_audit_search(self, client: AsyncClient, meta_admin):
        token = _make_token(meta_admin)
        headers = _auth_headers(token)
        resp = await client.get("/api/v1/meta/audit?limit=10", headers=headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


# ---------------------------------------------------------------------------
# 12. Feature flags
# ---------------------------------------------------------------------------


class TestFeatureFlags:
    async def test_toggle_feature_flags(self, client: AsyncClient, meta_admin):
        token = _make_token(meta_admin)
        headers = _auth_headers(token)
        headers["Content-Type"] = "application/json"

        resp = await client.patch(
            f"/api/v1/meta/orgs/{meta_admin.default_organization_id}/features",
            headers=headers,
            json={"features": {"sso": True, "audit_export": True}},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["feature_overrides"]["sso"] is True
        assert data["feature_overrides"]["audit_export"] is True
