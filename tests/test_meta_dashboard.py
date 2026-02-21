"""
Tests for the meta admin platform dashboard endpoints.

Covers:
- GET /meta/dashboard returns correct DashboardResponse schema
- Non-meta-admin gets 403
- hourly_evals contains 24 buckets
- org_usage sorted by evals_24h descending
- agent_types groups correctly
- funnel counts match test data
- GET /meta/dashboard/perf returns PerformanceStats schema
- Perf endpoint handles missing Prometheus gracefully
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agents import Agent, AgentStatus, TrustLevel
from app.models.audit_logs import AuditAction, AuditLog, AuditSeverity
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
from app.models.threat_events import ThreatEvent, ThreatSeverity, ThreatStatus
from app.models.users import User
from app.services.auth import create_access_token, create_user


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _enable_auth(monkeypatch):
    monkeypatch.setenv("SELF_HOSTED", "false")
    monkeypatch.setenv("META_ADMIN_ENABLED", "true")
    from app.config import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest_asyncio.fixture
async def seed_plans(db_session: AsyncSession):
    for plan_id, name in [("free", "Free"), ("pro", "Pro"), ("enterprise", "Enterprise")]:
        plan = Plan(
            id=plan_id,
            name=name,
            max_agents=100 if plan_id != "free" else 1,
            max_rules=100 if plan_id != "free" else 10,
            max_vault_entries=100 if plan_id != "free" else 5,
            max_team_members=10 if plan_id != "free" else 1,
            max_teams=10 if plan_id != "free" else 1,
            price_monthly_cents=0,
            price_yearly_cents=0,
            features={},
        )
        db_session.add(plan)
    await db_session.flush()


@pytest_asyncio.fixture
async def meta_admin(db_session: AsyncSession, seed_plans) -> User:
    user = await create_user(db_session, "dash-admin@mckinleylabs.com", "dashadmin", "Admin1234!")
    user.is_meta_admin = True
    await db_session.flush()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def regular_user(db_session: AsyncSession, seed_plans) -> User:
    user = await create_user(db_session, "dash-regular@example.com", "dashregular", "Regular1234!")
    await db_session.flush()
    await db_session.refresh(user)
    return user


def _make_token(user: User, org_id=None) -> str:
    return create_access_token(
        user_id=user.id,
        org_id=org_id or user.default_organization_id,
        role="owner",
        is_meta_admin=user.is_meta_admin,
    )


def _auth_headers(token: str) -> dict:
    return {"Cookie": f"snapper_access_token={token}"}


@pytest_asyncio.fixture
async def seeded_data(db_session: AsyncSession, meta_admin, seed_plans):
    """Seed orgs, agents, rules, audit logs, threats for dashboard tests."""
    now = datetime.now(timezone.utc)

    # Create two orgs
    org1 = Organization(
        id=uuid4(), name="Org Alpha", slug="org-alpha", plan_id="pro", is_active=True,
    )
    org2 = Organization(
        id=uuid4(), name="Org Beta", slug="org-beta", plan_id="free", is_active=True,
    )
    db_session.add_all([org1, org2])
    await db_session.flush()

    # Teams
    for org in [org1, org2]:
        db_session.add(Team(id=uuid4(), organization_id=org.id, name="General", slug="general", is_default=True))

    # Agents with different types
    agents = []
    for name, atype, org in [
        ("Agent CC", "claude-code", org1),
        ("Agent OC", "openclaw", org1),
        ("Agent Cursor", "cursor", org2),
        ("Agent Unknown", None, org2),
    ]:
        a = Agent(
            id=uuid4(), name=name, external_id=f"ext-{uuid4().hex[:8]}",
            status=AgentStatus.ACTIVE, trust_level=TrustLevel.STANDARD,
            organization_id=org.id, agent_type=atype,
            allowed_origins=[], require_localhost_only=False,
        )
        db_session.add(a)
        agents.append(a)
    await db_session.flush()

    # Rules
    for org in [org1, org2]:
        db_session.add(Rule(
            id=uuid4(), name=f"Rule for {org.name}", agent_id=agents[0].id,
            rule_type=RuleType.RATE_LIMIT, action=RuleAction.DENY, priority=10,
            parameters={"max_requests": 100, "window_seconds": 60},
            is_active=True, organization_id=org.id,
        ))

    # Audit logs (evaluations in the last 24h)
    # Org1: 5 allowed, 2 denied, 1 pending
    for action, count in [
        (AuditAction.REQUEST_ALLOWED, 5),
        (AuditAction.REQUEST_DENIED, 2),
        (AuditAction.REQUEST_PENDING_APPROVAL, 1),
    ]:
        for i in range(count):
            db_session.add(AuditLog(
                id=uuid4(), action=action, severity=AuditSeverity.INFO,
                message=f"Eval {action.value}", organization_id=org1.id,
                created_at=now - timedelta(hours=i + 1),
            ))

    # Org2: 3 allowed, 1 denied
    for action, count in [
        (AuditAction.REQUEST_ALLOWED, 3),
        (AuditAction.REQUEST_DENIED, 1),
    ]:
        for i in range(count):
            db_session.add(AuditLog(
                id=uuid4(), action=action, severity=AuditSeverity.INFO,
                message=f"Eval {action.value}", organization_id=org2.id,
                created_at=now - timedelta(hours=i + 1),
            ))

    # Threat events
    db_session.add(ThreatEvent(
        id=uuid4(), agent_id=agents[0].id, organization_id=org1.id,
        threat_type="data_exfiltration", severity="high",
        threat_score=85.0, status=ThreatStatus.ACTIVE,
        description="Test active threat", signals=[], details={},
    ))

    # Invitation (for funnel)
    db_session.add(Invitation(
        id=uuid4(), organization_id=org1.id, email="invited@test.com",
        role=OrgRole.MEMBER, token=f"tok-{uuid4().hex[:16]}",
        invited_by=meta_admin.id, status=InvitationStatus.PENDING,
        expires_at=now + timedelta(days=14),
        created_at=now - timedelta(days=5),
    ))
    db_session.add(Invitation(
        id=uuid4(), organization_id=org2.id, email="accepted@test.com",
        role=OrgRole.MEMBER, token=f"tok-{uuid4().hex[:16]}",
        invited_by=meta_admin.id, status=InvitationStatus.ACCEPTED,
        expires_at=now + timedelta(days=14),
        created_at=now - timedelta(days=3),
    ))

    await db_session.flush()
    return {"org1": org1, "org2": org2, "agents": agents}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestDashboardAuth:
    async def test_non_meta_admin_gets_403(self, client: AsyncClient, regular_user):
        token = _make_token(regular_user)
        resp = await client.get("/api/v1/meta/dashboard", headers=_auth_headers(token))
        assert resp.status_code == 403

    async def test_perf_non_meta_admin_gets_403(self, client: AsyncClient, regular_user):
        token = _make_token(regular_user)
        resp = await client.get("/api/v1/meta/dashboard/perf", headers=_auth_headers(token))
        assert resp.status_code == 403


class TestDashboardResponse:
    async def test_returns_valid_schema(self, client: AsyncClient, meta_admin, seeded_data):
        token = _make_token(meta_admin)
        resp = await client.get("/api/v1/meta/dashboard", headers=_auth_headers(token))
        assert resp.status_code == 200
        data = resp.json()

        # Verify top-level fields exist
        assert "total_orgs" in data
        assert "active_orgs" in data
        assert "total_users" in data
        assert "total_agents" in data
        assert "total_rules" in data
        assert "evals_24h" in data
        assert "denied_24h" in data
        assert "active_threats" in data
        assert "hourly_evals" in data
        assert "org_usage" in data
        assert "agent_types" in data
        assert "funnel" in data
        assert "generated_at" in data

    async def test_hourly_evals_has_24_buckets(self, client: AsyncClient, meta_admin, seeded_data):
        token = _make_token(meta_admin)
        resp = await client.get("/api/v1/meta/dashboard", headers=_auth_headers(token))
        data = resp.json()
        assert len(data["hourly_evals"]) == 24
        for bucket in data["hourly_evals"]:
            assert "hour" in bucket
            assert "allowed" in bucket
            assert "denied" in bucket
            assert "pending" in bucket

    async def test_evals_counts_correct(self, client: AsyncClient, meta_admin, seeded_data):
        token = _make_token(meta_admin)
        resp = await client.get("/api/v1/meta/dashboard", headers=_auth_headers(token))
        data = resp.json()
        # Org1: 5+2+1=8, Org2: 3+1=4, total=12
        assert data["evals_24h"] == 12
        # Denied: org1=2, org2=1, total=3
        assert data["denied_24h"] == 3

    async def test_active_threats_counted(self, client: AsyncClient, meta_admin, seeded_data):
        token = _make_token(meta_admin)
        resp = await client.get("/api/v1/meta/dashboard", headers=_auth_headers(token))
        data = resp.json()
        assert data["active_threats"] == 1

    async def test_org_usage_sorted_by_evals_desc(self, client: AsyncClient, meta_admin, seeded_data):
        token = _make_token(meta_admin)
        resp = await client.get("/api/v1/meta/dashboard", headers=_auth_headers(token))
        data = resp.json()
        usage = data["org_usage"]
        # Filter to our test orgs
        test_orgs = [o for o in usage if o["org_name"] in ("Org Alpha", "Org Beta")]
        assert len(test_orgs) >= 2
        # Org Alpha should come first (8 evals > 4 evals)
        alpha = next(o for o in test_orgs if o["org_name"] == "Org Alpha")
        beta = next(o for o in test_orgs if o["org_name"] == "Org Beta")
        assert alpha["evals_24h"] >= beta["evals_24h"]

    async def test_agent_types_grouped(self, client: AsyncClient, meta_admin, seeded_data):
        token = _make_token(meta_admin)
        resp = await client.get("/api/v1/meta/dashboard", headers=_auth_headers(token))
        data = resp.json()
        types = {t["agent_type"]: t["count"] for t in data["agent_types"]}
        assert types.get("claude-code", 0) >= 1
        assert types.get("openclaw", 0) >= 1
        assert types.get("cursor", 0) >= 1
        assert types.get("unknown", 0) >= 1

    async def test_funnel_counts(self, client: AsyncClient, meta_admin, seeded_data):
        token = _make_token(meta_admin)
        resp = await client.get("/api/v1/meta/dashboard", headers=_auth_headers(token))
        data = resp.json()
        funnel = data["funnel"]
        assert funnel["invitations_sent_30d"] >= 2  # We created 2 invitations
        assert funnel["invitations_accepted_30d"] >= 1  # 1 accepted
        assert funnel["registrations_30d"] >= 1  # At least the meta admin user

    async def test_total_counts(self, client: AsyncClient, meta_admin, seeded_data):
        token = _make_token(meta_admin)
        resp = await client.get("/api/v1/meta/dashboard", headers=_auth_headers(token))
        data = resp.json()
        assert data["total_agents"] >= 4
        assert data["total_rules"] >= 2
        assert data["total_orgs"] >= 2


class TestPerformanceEndpoint:
    async def test_returns_valid_schema(self, client: AsyncClient, meta_admin):
        token = _make_token(meta_admin)
        resp = await client.get("/api/v1/meta/dashboard/perf", headers=_auth_headers(token))
        assert resp.status_code == 200
        data = resp.json()
        assert "avg_request_latency_ms" in data
        assert "p95_request_latency_ms" in data
        assert "avg_eval_latency_ms" in data
        assert "p95_eval_latency_ms" in data
        assert "requests_per_minute" in data
        assert "evals_per_minute" in data
        assert "error_rate_pct" in data

    async def test_handles_no_data_gracefully(self, client: AsyncClient, meta_admin):
        """Perf endpoint returns zeros when there's no Prometheus data."""
        token = _make_token(meta_admin)
        resp = await client.get("/api/v1/meta/dashboard/perf", headers=_auth_headers(token))
        assert resp.status_code == 200
        data = resp.json()
        # All values should be numeric (not null or error)
        for key, val in data.items():
            assert isinstance(val, (int, float)), f"{key} should be numeric, got {type(val)}"

    async def test_perf_returns_prometheus_disabled(self, client: AsyncClient, meta_admin, monkeypatch):
        """When Prometheus is unavailable, returns all zeros."""
        import app.middleware.metrics as metrics_mod
        original = metrics_mod.PROMETHEUS_AVAILABLE
        monkeypatch.setattr(metrics_mod, "PROMETHEUS_AVAILABLE", False)
        try:
            token = _make_token(meta_admin)
            resp = await client.get("/api/v1/meta/dashboard/perf", headers=_auth_headers(token))
            assert resp.status_code == 200
            data = resp.json()
            assert data["avg_request_latency_ms"] == 0.0
            assert data["error_rate_pct"] == 0.0
        finally:
            monkeypatch.setattr(metrics_mod, "PROMETHEUS_AVAILABLE", original)
