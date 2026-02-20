"""
@module test_billing
@description Tests for the billing router (app/routers/billing.py) and the
Stripe billing service (app/services/stripe_billing.py).
"""

from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.organizations import Organization, Plan


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
    """Seed the standard plans required by the billing router."""
    plans = [
        Plan(
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
        ),
        Plan(
            id="pro",
            name="Pro",
            max_agents=10,
            max_rules=100,
            max_vault_entries=50,
            max_team_members=5,
            max_teams=3,
            price_monthly_cents=2900,
            price_yearly_cents=29000,
            features={
                "slack_integration": True,
                "oauth_login": True,
                "sso": False,
                "audit_export": True,
            },
        ),
        Plan(
            id="enterprise",
            name="Enterprise",
            max_agents=-1,
            max_rules=-1,
            max_vault_entries=-1,
            max_team_members=-1,
            max_teams=-1,
            price_monthly_cents=0,
            price_yearly_cents=0,
            features={
                "slack_integration": True,
                "oauth_login": True,
                "sso": True,
                "audit_export": True,
            },
        ),
    ]
    for p in plans:
        db_session.add(p)
    await db_session.commit()
    return plans


async def _register_user(client: AsyncClient, suffix: str = "") -> AsyncClient:
    """
    Register a new user via the auth API and return the same client
    (which now carries the authentication cookies set by the response).
    """
    unique = uuid4().hex[:8]
    resp = await client.post(
        "/api/v1/auth/register",
        json={
            "email": f"billing-test-{unique}{suffix}@example.com",
            "username": f"billingtest{unique}{suffix}",
            "password": "StrongPass123!",
            "password_confirm": "StrongPass123!",
        },
    )
    assert resp.status_code == 200, f"Registration failed: {resp.text}"
    # Cookies are automatically captured by the AsyncClient
    return client


# ---------------------------------------------------------------------------
# Tests -- GET /api/v1/billing/plan
# ---------------------------------------------------------------------------


class TestGetPlan:
    """Tests for the GET /billing/plan endpoint."""

    @pytest.mark.asyncio
    async def test_get_plan_authenticated(self, client: AsyncClient, seed_plans):
        """An authenticated user receives their plan details and usage."""
        client = await _register_user(client)

        resp = await client.get("/api/v1/billing/plan")
        assert resp.status_code == 200

        data = resp.json()
        assert "plan" in data
        assert "usage" in data
        assert data["plan"]["id"] == "free"
        assert data["plan"]["name"] == "Free"
        assert data["plan"]["limits"]["agents"] == 1
        assert data["plan"]["limits"]["rules"] == 10
        assert data["usage"]["agents"]["used"] >= 0
        assert data["usage"]["rules"]["used"] >= 0

    @pytest.mark.asyncio
    async def test_get_plan_includes_features(self, client: AsyncClient, seed_plans):
        """The plan response includes the features dict."""
        client = await _register_user(client)

        resp = await client.get("/api/v1/billing/plan")
        assert resp.status_code == 200

        features = resp.json()["plan"]["features"]
        assert "slack_integration" in features
        assert features["slack_integration"] is False  # free plan

    @pytest.mark.asyncio
    async def test_get_plan_unauthenticated(self, client: AsyncClient, seed_plans):
        """GET /billing/plan returns 401 when no auth cookies are present."""
        resp = await client.get("/api/v1/billing/plan")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_get_plan_includes_subscription_status(self, client: AsyncClient, seed_plans):
        """The plan response includes subscription_status and period_end fields."""
        client = await _register_user(client)

        resp = await client.get("/api/v1/billing/plan")
        data = resp.json()

        # A freshly registered org won't have Stripe subscription info
        assert "subscription_status" in data
        assert "plan_period_end" in data


# ---------------------------------------------------------------------------
# Tests -- POST /api/v1/billing/checkout
# ---------------------------------------------------------------------------


class TestCheckout:
    """Tests for the POST /billing/checkout endpoint."""

    @pytest.mark.asyncio
    async def test_checkout_returns_503_no_stripe(self, client: AsyncClient, seed_plans):
        """POST /billing/checkout returns 503 when Stripe is not configured."""
        client = await _register_user(client)

        resp = await client.post(
            "/api/v1/billing/checkout",
            json={"plan_id": "pro", "interval": "monthly"},
        )
        # Without STRIPE_SECRET_KEY, the service returns None => 503
        assert resp.status_code == 503
        assert "Stripe" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_checkout_unauthenticated(self, client: AsyncClient, seed_plans):
        """POST /billing/checkout returns 401 when not authenticated."""
        resp = await client.post(
            "/api/v1/billing/checkout",
            json={"plan_id": "pro", "interval": "monthly"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Tests -- POST /api/v1/billing/portal
# ---------------------------------------------------------------------------


class TestPortal:
    """Tests for the POST /billing/portal endpoint."""

    @pytest.mark.asyncio
    async def test_portal_unauthenticated(self, client: AsyncClient, seed_plans):
        """POST /billing/portal returns 401 when not authenticated."""
        resp = await client.post("/api/v1/billing/portal")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_portal_no_stripe_customer(self, client: AsyncClient, seed_plans):
        """POST /billing/portal returns 404 when org has no Stripe customer."""
        client = await _register_user(client)

        resp = await client.post("/api/v1/billing/portal")
        # No stripe_customer_id on the org => service returns None => 404
        assert resp.status_code == 404
        assert "Stripe customer" in resp.json()["detail"] or "Subscribe" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Tests -- POST /api/v1/billing/webhook
# ---------------------------------------------------------------------------


class TestWebhook:
    """Tests for the POST /billing/webhook endpoint."""

    @pytest.mark.asyncio
    async def test_webhook_accepts_post(self, client: AsyncClient, seed_plans):
        """The webhook endpoint accepts POST requests (no auth required)."""
        resp = await client.post(
            "/api/v1/billing/webhook",
            content=b'{"type": "test"}',
            headers={"Content-Type": "application/json"},
        )
        # Without a Stripe-Signature header it should return 400
        assert resp.status_code == 400
        assert "Stripe-Signature" in resp.json()["detail"] or "Missing" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_webhook_with_invalid_signature(self, client: AsyncClient, seed_plans):
        """The webhook endpoint rejects requests with an invalid Stripe signature."""
        resp = await client.post(
            "/api/v1/billing/webhook",
            content=b'{"type": "checkout.session.completed"}',
            headers={
                "Content-Type": "application/json",
                "Stripe-Signature": "t=12345,v1=invalid_signature",
            },
        )
        # Should fail during signature verification or Stripe config check
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Tests -- Stripe billing service
# ---------------------------------------------------------------------------


class TestStripeBillingService:
    """Tests for app/services/stripe_billing.py."""

    def test_get_stripe_returns_none_when_not_installed(self, monkeypatch):
        """get_stripe returns None when the stripe package is not importable."""
        import builtins
        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "stripe":
                raise ImportError("No module named 'stripe'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)

        from app.services.stripe_billing import get_stripe
        result = get_stripe()
        assert result is None

    def test_get_stripe_returns_module_when_available(self):
        """get_stripe returns the stripe module (or None) without crashing."""
        from app.services.stripe_billing import get_stripe

        result = get_stripe()
        # Result is either the stripe module or None (if not installed)
        # Either way, the function should not raise
        assert result is None or hasattr(result, "api_key")

    @pytest.mark.asyncio
    async def test_create_checkout_session_returns_none_no_stripe(self, db_session, seed_plans):
        """create_checkout_session returns None when Stripe is not configured."""
        from app.services.stripe_billing import create_checkout_session

        org = Organization(
            id=uuid4(),
            name="Billing Test Org",
            slug=f"billing-test-{uuid4().hex[:8]}",
            plan_id="free",
            is_active=True,
        )
        db_session.add(org)
        await db_session.flush()

        result = await create_checkout_session(
            db=db_session,
            org_id=org.id,
            plan_id="pro",
            interval="monthly",
        )
        # STRIPE_SECRET_KEY is not set in test env => returns None
        assert result is None

    @pytest.mark.asyncio
    async def test_create_portal_session_returns_none_no_stripe(self, db_session, seed_plans):
        """create_portal_session returns None when Stripe is not configured."""
        from app.services.stripe_billing import create_portal_session

        org = Organization(
            id=uuid4(),
            name="Portal Test Org",
            slug=f"portal-test-{uuid4().hex[:8]}",
            plan_id="free",
            is_active=True,
        )
        db_session.add(org)
        await db_session.flush()

        result = await create_portal_session(db=db_session, org_id=org.id)
        assert result is None

    @pytest.mark.asyncio
    async def test_handle_webhook_raises_without_stripe_config(self, db_session):
        """handle_webhook raises ValueError when Stripe is not configured."""
        from app.services.stripe_billing import handle_webhook

        with pytest.raises(ValueError, match="Stripe not configured"):
            await handle_webhook(
                db=db_session,
                payload=b'{"type": "test"}',
                signature="t=12345,v1=fake",
            )

    @pytest.mark.asyncio
    async def test_sync_subscription_noop_without_stripe(self, db_session, seed_plans):
        """sync_subscription_status is a no-op when Stripe is not configured."""
        from app.services.stripe_billing import sync_subscription_status

        org = Organization(
            id=uuid4(),
            name="Sync Test Org",
            slug=f"sync-test-{uuid4().hex[:8]}",
            plan_id="free",
            is_active=True,
        )
        db_session.add(org)
        await db_session.flush()

        # Should complete without raising
        await sync_subscription_status(db=db_session, org_id=org.id)


# ---------------------------------------------------------------------------
# Tests -- Webhook event handler functions
# ---------------------------------------------------------------------------


class TestWebhookEventHandlers:
    """Tests for internal webhook handler functions in stripe_billing.py."""

    @pytest.mark.asyncio
    async def test_checkout_completed_missing_org_noop(self, db_session, seed_plans):
        """handle_checkout_completed with missing org metadata should not crash."""
        from app.services.stripe_billing import _handle_checkout_completed

        event = {
            "metadata": {},
            "customer": "cus_fake",
            "subscription": "sub_fake",
        }
        # Should not raise even with missing org_id
        await _handle_checkout_completed(db_session, event)

    @pytest.mark.asyncio
    async def test_checkout_completed_bad_org_noop(self, db_session, seed_plans):
        """handle_checkout_completed with nonexistent org should not crash."""
        from app.services.stripe_billing import _handle_checkout_completed

        event = {
            "metadata": {"org_id": str(uuid4()), "plan_id": "pro"},
            "customer": "cus_fake",
            "subscription": "sub_fake",
        }
        # Should complete without raising — org not found is logged and returned
        await _handle_checkout_completed(db_session, event)

    @pytest.mark.asyncio
    async def test_subscription_deleted_no_customer_noop(self, db_session, seed_plans):
        """Subscription deleted with unknown customer should not crash."""
        from app.services.stripe_billing import _handle_subscription_deleted

        event = {"customer": "cus_nonexistent"}
        await _handle_subscription_deleted(db_session, event)

    @pytest.mark.asyncio
    async def test_payment_failed_no_customer_noop(self, db_session, seed_plans):
        """Payment failed with unknown customer should not crash."""
        from app.services.stripe_billing import _handle_payment_failed

        event = {
            "customer": "cus_nonexistent",
            "id": "in_fake",
        }
        await _handle_payment_failed(db_session, event)


# ---------------------------------------------------------------------------
# Tests -- Sync subscription noop variants
# ---------------------------------------------------------------------------


class TestSyncSubscriptionStatus:
    @pytest.mark.asyncio
    async def test_sync_noop_without_stripe(self, db_session, seed_plans):
        """sync_subscription_status is a no-op when Stripe is not configured."""
        from app.services.stripe_billing import sync_subscription_status

        org = Organization(
            id=uuid4(),
            name="Sync Noop Org",
            slug=f"sync-noop-{uuid4().hex[:8]}",
            plan_id="free",
            is_active=True,
        )
        db_session.add(org)
        await db_session.flush()
        await sync_subscription_status(db=db_session, org_id=org.id)

    @pytest.mark.asyncio
    async def test_sync_noop_without_subscription_id(self, db_session, seed_plans):
        """sync_subscription_status is a no-op when org has no subscription_id."""
        from app.services.stripe_billing import sync_subscription_status

        org = Organization(
            id=uuid4(),
            name="No Sub Org",
            slug=f"no-sub-{uuid4().hex[:8]}",
            plan_id="free",
            is_active=True,
            stripe_subscription_id=None,
        )
        db_session.add(org)
        await db_session.flush()
        await sync_subscription_status(db=db_session, org_id=org.id)
