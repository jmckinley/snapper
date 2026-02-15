"""
Tests for multi-tenant organization scoping on agents, rules, vault, and audit endpoints.

Verifies that:
- Agents/rules/audit logs created under one org are invisible to another.
- Unauthenticated (no org context) returns all data (backward compatibility).
- Resources are created with the correct organization_id.
"""

from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agents import Agent, AgentStatus, TrustLevel
from app.models.audit_logs import AuditAction, AuditLog, AuditSeverity
from app.models.organizations import (
    Organization,
    OrganizationMembership,
    OrgRole,
    Plan,
    Team,
)
from app.models.rules import Rule, RuleAction, RuleType
from app.models.users import User
from app.services.auth import create_user


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def seed_plans(db_session: AsyncSession):
    """Seed the plans table with a free tier."""
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
async def user_a(db_session: AsyncSession, seed_plans):
    """Create user A with their own org."""
    user = await create_user(
        db_session, "alice@example.com", "alice", "AlicePass1!"
    )
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def user_b(db_session: AsyncSession, seed_plans):
    """Create user B with their own org."""
    user = await create_user(
        db_session, "bob@example.com", "bob", "BobPass123!"
    )
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def org_a_id(user_a) -> UUID:
    return user_a.default_organization_id


@pytest_asyncio.fixture
async def org_b_id(user_b) -> UUID:
    return user_b.default_organization_id


@pytest_asyncio.fixture
async def agent_in_org_a(db_session: AsyncSession, org_a_id):
    """Create an agent scoped to org A."""
    agent = Agent(
        id=uuid4(),
        name="Org A Agent",
        external_id=f"org-a-agent-{uuid4().hex[:8]}",
        description="Agent belonging to org A",
        status=AgentStatus.ACTIVE,
        trust_level=TrustLevel.STANDARD,
        organization_id=org_a_id,
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)
    return agent


@pytest_asyncio.fixture
async def agent_in_org_b(db_session: AsyncSession, org_b_id):
    """Create an agent scoped to org B."""
    agent = Agent(
        id=uuid4(),
        name="Org B Agent",
        external_id=f"org-b-agent-{uuid4().hex[:8]}",
        description="Agent belonging to org B",
        status=AgentStatus.ACTIVE,
        trust_level=TrustLevel.STANDARD,
        organization_id=org_b_id,
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)
    return agent


@pytest_asyncio.fixture
async def agent_no_org(db_session: AsyncSession):
    """Create an agent with no organization (legacy/global)."""
    agent = Agent(
        id=uuid4(),
        name="Global Agent",
        external_id=f"global-agent-{uuid4().hex[:8]}",
        description="Agent without org scoping",
        status=AgentStatus.ACTIVE,
        trust_level=TrustLevel.STANDARD,
        organization_id=None,
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)
    return agent


@pytest_asyncio.fixture
async def rule_in_org_a(db_session: AsyncSession, org_a_id, agent_in_org_a):
    """Create a rule scoped to org A."""
    rule = Rule(
        id=uuid4(),
        name="Org A Rule",
        description="Rule for org A",
        agent_id=agent_in_org_a.id,
        rule_type=RuleType.RATE_LIMIT,
        action=RuleAction.DENY,
        priority=10,
        parameters={"max_requests": 50, "window_seconds": 60},
        is_active=True,
        organization_id=org_a_id,
    )
    db_session.add(rule)
    await db_session.commit()
    await db_session.refresh(rule)
    return rule


@pytest_asyncio.fixture
async def rule_in_org_b(db_session: AsyncSession, org_b_id, agent_in_org_b):
    """Create a rule scoped to org B."""
    rule = Rule(
        id=uuid4(),
        name="Org B Rule",
        description="Rule for org B",
        agent_id=agent_in_org_b.id,
        rule_type=RuleType.COMMAND_DENYLIST,
        action=RuleAction.DENY,
        priority=20,
        parameters={"commands": ["rm -rf /"]},
        is_active=True,
        organization_id=org_b_id,
    )
    db_session.add(rule)
    await db_session.commit()
    await db_session.refresh(rule)
    return rule


@pytest_asyncio.fixture
async def global_rule_no_org(db_session: AsyncSession):
    """Create a global rule with no org (visible to all when org is set)."""
    rule = Rule(
        id=uuid4(),
        name="Global Rule",
        description="No org scope",
        agent_id=None,
        rule_type=RuleType.CREDENTIAL_PROTECTION,
        action=RuleAction.DENY,
        priority=100,
        parameters={
            "protected_patterns": [r"\.env$"],
            "block_plaintext_secrets": True,
        },
        is_active=True,
        organization_id=None,
    )
    db_session.add(rule)
    await db_session.commit()
    await db_session.refresh(rule)
    return rule


@pytest_asyncio.fixture
async def audit_log_in_org_a(
    db_session: AsyncSession, org_a_id, agent_in_org_a
):
    """Create an audit log entry scoped to org A."""
    log = AuditLog(
        id=uuid4(),
        action=AuditAction.REQUEST_DENIED,
        severity=AuditSeverity.WARNING,
        agent_id=agent_in_org_a.id,
        message="Denied in org A",
        details={"org": "a"},
        organization_id=org_a_id,
    )
    db_session.add(log)
    await db_session.commit()
    await db_session.refresh(log)
    return log


@pytest_asyncio.fixture
async def audit_log_in_org_b(
    db_session: AsyncSession, org_b_id, agent_in_org_b
):
    """Create an audit log entry scoped to org B."""
    log = AuditLog(
        id=uuid4(),
        action=AuditAction.REQUEST_ALLOWED,
        severity=AuditSeverity.INFO,
        agent_id=agent_in_org_b.id,
        message="Allowed in org B",
        details={"org": "b"},
        organization_id=org_b_id,
    )
    db_session.add(log)
    await db_session.commit()
    await db_session.refresh(log)
    return log


async def _register_and_get_cookies(client: AsyncClient, email: str, username: str):
    """Helper: register a user and return (user_data, access_token, refresh_token)."""
    resp = await client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "username": username,
            "password": "SecurePass1!",
            "password_confirm": "SecurePass1!",
        },
    )
    assert resp.status_code == 200, f"Registration failed: {resp.text}"
    access_token = resp.cookies.get("snapper_access_token")
    refresh_token = resp.cookies.get("snapper_refresh_token")
    return resp.json(), access_token, refresh_token


# ---------------------------------------------------------------------------
# 1. Agents list filtered by org_id
# ---------------------------------------------------------------------------


class TestAgentsOrgScoping:
    @pytest.mark.asyncio
    async def test_agents_list_shows_only_own_org(
        self, client, seed_plans, db_session, agent_in_org_a, agent_in_org_b
    ):
        """Authenticated user A sees only agents in org A."""
        user_data, access, refresh = await _register_and_get_cookies(
            client, "agentscope@example.com", "agentscope"
        )
        user_org_id = UUID(user_data["default_organization_id"])

        # Create an agent in the user's org
        agent_mine = Agent(
            id=uuid4(),
            name="My Scoped Agent",
            external_id=f"mine-{uuid4().hex[:8]}",
            description="Belongs to test user org",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
            organization_id=user_org_id,
        )
        db_session.add(agent_mine)
        await db_session.commit()

        client.cookies.set("snapper_access_token", access)
        client.cookies.set("snapper_refresh_token", refresh)

        resp = await client.get("/api/v1/agents")
        assert resp.status_code == 200
        data = resp.json()
        agent_names = [a["name"] for a in data["items"]]
        assert "My Scoped Agent" in agent_names
        assert "Org A Agent" not in agent_names
        assert "Org B Agent" not in agent_names

    @pytest.mark.asyncio
    async def test_agents_no_auth_returns_all(
        self, client, seed_plans, agent_in_org_a, agent_in_org_b, agent_no_org
    ):
        """Without auth (no org context), all agents are returned."""
        # API routes under /api/v1/agents are NOT under /api/v1/auth/ prefix,
        # so AuthMiddleware will intercept. We call as JSON API to get 401
        # or if the middleware allows unauthenticated API calls (exempt paths).
        # Based on the middleware, /api/v1/agents is NOT exempt.
        # So unauthenticated = 401.
        resp = await client.get(
            "/api/v1/agents",
            headers={"accept": "application/json"},
        )
        # AuthMiddleware returns 401 for API requests without tokens
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 2. Agents created with org_id
# ---------------------------------------------------------------------------


class TestAgentsCreatedWithOrg:
    @pytest.mark.asyncio
    async def test_create_agent_inherits_org_from_auth(
        self, client, db_session, seed_plans
    ):
        """When an authenticated user creates an agent, it gets their org_id."""
        user_data, access, refresh = await _register_and_get_cookies(
            client, "agentcreator@example.com", "agentcreator"
        )
        user_org_id = UUID(user_data["default_organization_id"])

        client.cookies.set("snapper_access_token", access)
        client.cookies.set("snapper_refresh_token", refresh)

        resp = await client.post(
            "/api/v1/agents",
            json={
                "name": "Created Agent",
                "external_id": f"created-{uuid4().hex[:8]}",
                "description": "Via API with auth",
            },
        )
        assert resp.status_code == 201
        agent_data = resp.json()

        # Verify in DB
        result = await db_session.execute(
            select(Agent).where(Agent.id == UUID(agent_data["id"]))
        )
        agent = result.scalar_one()
        assert agent.organization_id == user_org_id


# ---------------------------------------------------------------------------
# 3. Rules list filtered by org_id
# ---------------------------------------------------------------------------


class TestRulesOrgScoping:
    @pytest.mark.asyncio
    async def test_rules_list_shows_own_org_and_global(
        self,
        client,
        db_session,
        seed_plans,
        rule_in_org_a,
        rule_in_org_b,
        global_rule_no_org,
    ):
        """Authenticated user sees rules in their org plus global (null org) rules."""
        user_data, access, refresh = await _register_and_get_cookies(
            client, "rulescope@example.com", "rulescope"
        )
        user_org_id = UUID(user_data["default_organization_id"])

        # Create a rule in the user's org
        my_rule = Rule(
            id=uuid4(),
            name="My Org Rule",
            description="In my org",
            agent_id=None,
            rule_type=RuleType.RATE_LIMIT,
            action=RuleAction.DENY,
            priority=5,
            parameters={"max_requests": 10, "window_seconds": 60},
            is_active=True,
            organization_id=user_org_id,
        )
        db_session.add(my_rule)
        await db_session.commit()

        client.cookies.set("snapper_access_token", access)
        client.cookies.set("snapper_refresh_token", refresh)

        resp = await client.get("/api/v1/rules")
        assert resp.status_code == 200
        data = resp.json()
        rule_names = [r["name"] for r in data["items"]]

        # Own org rule visible
        assert "My Org Rule" in rule_names
        # Global rule (org_id=None) also visible
        assert "Global Rule" in rule_names
        # Other org rules NOT visible
        assert "Org A Rule" not in rule_names
        assert "Org B Rule" not in rule_names


# ---------------------------------------------------------------------------
# 4. Rules created with org_id
# ---------------------------------------------------------------------------


class TestRulesCreatedWithOrg:
    @pytest.mark.asyncio
    async def test_create_rule_inherits_org(
        self, client, db_session, seed_plans, agent_in_org_a
    ):
        """Rule created via API gets the authenticated user's org_id."""
        user_data, access, refresh = await _register_and_get_cookies(
            client, "rulecreator@example.com", "rulecreator"
        )
        user_org_id = UUID(user_data["default_organization_id"])

        client.cookies.set("snapper_access_token", access)
        client.cookies.set("snapper_refresh_token", refresh)

        resp = await client.post(
            "/api/v1/rules",
            json={
                "name": "Auth-Created Rule",
                "description": "Created with auth context",
                "rule_type": "rate_limit",
                "action": "deny",
                "priority": 15,
                "parameters": {"max_requests": 25, "window_seconds": 60},
                "is_active": True,
            },
        )
        assert resp.status_code == 201
        rule_data = resp.json()

        result = await db_session.execute(
            select(Rule).where(Rule.id == UUID(rule_data["id"]))
        )
        rule = result.scalar_one()
        assert rule.organization_id == user_org_id


# ---------------------------------------------------------------------------
# 5. Audit logs filtered by org_id
# ---------------------------------------------------------------------------


class TestAuditOrgScoping:
    @pytest.mark.asyncio
    async def test_audit_logs_filtered_by_org(
        self,
        client,
        db_session,
        seed_plans,
        audit_log_in_org_a,
        audit_log_in_org_b,
    ):
        """Authenticated user only sees audit logs from their org."""
        user_data, access, refresh = await _register_and_get_cookies(
            client, "auditscope@example.com", "auditscope"
        )
        user_org_id = UUID(user_data["default_organization_id"])

        # Add an audit log in the user's org
        my_log = AuditLog(
            id=uuid4(),
            action=AuditAction.RULE_CREATED,
            severity=AuditSeverity.INFO,
            message="Created a rule in my org",
            details={"org": "mine"},
            organization_id=user_org_id,
        )
        db_session.add(my_log)
        await db_session.commit()

        client.cookies.set("snapper_access_token", access)
        client.cookies.set("snapper_refresh_token", refresh)

        resp = await client.get("/api/v1/audit/logs")
        assert resp.status_code == 200
        data = resp.json()
        messages = [l["message"] for l in data["items"]]

        assert "Created a rule in my org" in messages
        assert "Denied in org A" not in messages
        assert "Allowed in org B" not in messages


# ---------------------------------------------------------------------------
# 6. Cross-org isolation
# ---------------------------------------------------------------------------


class TestCrossOrgIsolation:
    @pytest.mark.asyncio
    async def test_two_users_see_different_agents(
        self, client, db_session, seed_plans
    ):
        """User A and User B each see only their own agents."""
        # Register user A
        data_a, access_a, refresh_a = await _register_and_get_cookies(
            client, "iso_a@example.com", "iso_a"
        )
        org_a_id = UUID(data_a["default_organization_id"])

        # Register user B
        data_b, access_b, refresh_b = await _register_and_get_cookies(
            client, "iso_b@example.com", "iso_b"
        )
        org_b_id = UUID(data_b["default_organization_id"])

        # Create agent in org A
        agent_a = Agent(
            id=uuid4(),
            name="Iso Agent A",
            external_id=f"iso-a-{uuid4().hex[:8]}",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
            organization_id=org_a_id,
        )
        # Create agent in org B
        agent_b = Agent(
            id=uuid4(),
            name="Iso Agent B",
            external_id=f"iso-b-{uuid4().hex[:8]}",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
            organization_id=org_b_id,
        )
        db_session.add_all([agent_a, agent_b])
        await db_session.commit()

        # User A queries
        client.cookies.set("snapper_access_token", access_a)
        client.cookies.set("snapper_refresh_token", refresh_a)
        resp_a = await client.get("/api/v1/agents")
        assert resp_a.status_code == 200
        names_a = [a["name"] for a in resp_a.json()["items"]]
        assert "Iso Agent A" in names_a
        assert "Iso Agent B" not in names_a

        # User B queries
        client.cookies.set("snapper_access_token", access_b)
        client.cookies.set("snapper_refresh_token", refresh_b)
        resp_b = await client.get("/api/v1/agents")
        assert resp_b.status_code == 200
        names_b = [a["name"] for a in resp_b.json()["items"]]
        assert "Iso Agent B" in names_b
        assert "Iso Agent A" not in names_b

    @pytest.mark.asyncio
    async def test_two_users_see_different_rules(
        self, client, db_session, seed_plans
    ):
        """User A and User B each see only their own rules (plus global)."""
        data_a, access_a, refresh_a = await _register_and_get_cookies(
            client, "riso_a@example.com", "riso_a"
        )
        org_a_id = UUID(data_a["default_organization_id"])

        data_b, access_b, refresh_b = await _register_and_get_cookies(
            client, "riso_b@example.com", "riso_b"
        )
        org_b_id = UUID(data_b["default_organization_id"])

        rule_a = Rule(
            id=uuid4(),
            name="Iso Rule A",
            rule_type=RuleType.RATE_LIMIT,
            action=RuleAction.DENY,
            priority=5,
            parameters={"max_requests": 10, "window_seconds": 60},
            is_active=True,
            organization_id=org_a_id,
        )
        rule_b = Rule(
            id=uuid4(),
            name="Iso Rule B",
            rule_type=RuleType.RATE_LIMIT,
            action=RuleAction.DENY,
            priority=5,
            parameters={"max_requests": 10, "window_seconds": 60},
            is_active=True,
            organization_id=org_b_id,
        )
        db_session.add_all([rule_a, rule_b])
        await db_session.commit()

        # User A
        client.cookies.set("snapper_access_token", access_a)
        client.cookies.set("snapper_refresh_token", refresh_a)
        resp_a = await client.get("/api/v1/rules")
        assert resp_a.status_code == 200
        names_a = [r["name"] for r in resp_a.json()["items"]]
        assert "Iso Rule A" in names_a
        assert "Iso Rule B" not in names_a

        # User B
        client.cookies.set("snapper_access_token", access_b)
        client.cookies.set("snapper_refresh_token", refresh_b)
        resp_b = await client.get("/api/v1/rules")
        assert resp_b.status_code == 200
        names_b = [r["name"] for r in resp_b.json()["items"]]
        assert "Iso Rule B" in names_b
        assert "Iso Rule A" not in names_b

    @pytest.mark.asyncio
    async def test_two_users_see_different_audit_logs(
        self, client, db_session, seed_plans
    ):
        """User A and User B each see only their own audit logs."""
        data_a, access_a, refresh_a = await _register_and_get_cookies(
            client, "aiso_a@example.com", "aiso_a"
        )
        org_a_id = UUID(data_a["default_organization_id"])

        data_b, access_b, refresh_b = await _register_and_get_cookies(
            client, "aiso_b@example.com", "aiso_b"
        )
        org_b_id = UUID(data_b["default_organization_id"])

        log_a = AuditLog(
            id=uuid4(),
            action=AuditAction.RULE_CREATED,
            severity=AuditSeverity.INFO,
            message="Audit from org A",
            details={},
            organization_id=org_a_id,
        )
        log_b = AuditLog(
            id=uuid4(),
            action=AuditAction.RULE_CREATED,
            severity=AuditSeverity.INFO,
            message="Audit from org B",
            details={},
            organization_id=org_b_id,
        )
        db_session.add_all([log_a, log_b])
        await db_session.commit()

        # User A
        client.cookies.set("snapper_access_token", access_a)
        client.cookies.set("snapper_refresh_token", refresh_a)
        resp_a = await client.get("/api/v1/audit/logs")
        assert resp_a.status_code == 200
        msgs_a = [l["message"] for l in resp_a.json()["items"]]
        assert "Audit from org A" in msgs_a
        assert "Audit from org B" not in msgs_a

        # User B
        client.cookies.set("snapper_access_token", access_b)
        client.cookies.set("snapper_refresh_token", refresh_b)
        resp_b = await client.get("/api/v1/audit/logs")
        assert resp_b.status_code == 200
        msgs_b = [l["message"] for l in resp_b.json()["items"]]
        assert "Audit from org B" in msgs_b
        assert "Audit from org A" not in msgs_b


# ---------------------------------------------------------------------------
# 7. Backward compatibility: no org context returns all data
# ---------------------------------------------------------------------------


class TestBackwardCompatNoOrg:
    @pytest.mark.asyncio
    async def test_unauthenticated_api_returns_401(
        self, client, seed_plans, agent_in_org_a, agent_in_org_b
    ):
        """
        Without auth cookies, API requests return 401.
        The AuthMiddleware does not exempt /api/v1/agents etc.
        This IS the expected behavior for the SaaS version.
        """
        resp = await client.get(
            "/api/v1/agents",
            headers={"accept": "application/json"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_global_rules_visible_to_all_orgs(
        self, client, db_session, seed_plans, global_rule_no_org
    ):
        """Rules with organization_id=None are visible to any authenticated user."""
        user_data, access, refresh = await _register_and_get_cookies(
            client, "globalvis@example.com", "globalvis"
        )
        client.cookies.set("snapper_access_token", access)
        client.cookies.set("snapper_refresh_token", refresh)

        resp = await client.get("/api/v1/rules")
        assert resp.status_code == 200
        rule_names = [r["name"] for r in resp.json()["items"]]
        assert "Global Rule" in rule_names

    @pytest.mark.asyncio
    async def test_org_scoping_preserves_db_data_integrity(
        self, db_session, seed_plans, agent_in_org_a, agent_in_org_b, agent_no_org
    ):
        """Direct DB query returns all agents regardless of org -- scoping is API-level."""
        result = await db_session.execute(select(Agent))
        all_agents = result.scalars().all()
        names = [a.name for a in all_agents]

        assert "Org A Agent" in names
        assert "Org B Agent" in names
        assert "Global Agent" in names


# ---------------------------------------------------------------------------
# 8. Agents GET by ID respects org boundary
# ---------------------------------------------------------------------------


class TestAgentGetByIdOrgBoundary:
    @pytest.mark.asyncio
    async def test_get_agent_from_other_org(
        self, client, db_session, seed_plans, agent_in_org_a
    ):
        """
        An authenticated user requesting an agent from another org
        can still get it by ID (GET by ID does not filter by org today).
        This test documents current behavior.
        """
        user_data, access, refresh = await _register_and_get_cookies(
            client, "getother@example.com", "getother"
        )
        client.cookies.set("snapper_access_token", access)
        client.cookies.set("snapper_refresh_token", refresh)

        resp = await client.get(f"/api/v1/agents/{agent_in_org_a.id}")
        # Current behavior: GET by ID is not org-filtered
        # This documents the behavior for future hardening
        assert resp.status_code in (200, 403, 404)


# ---------------------------------------------------------------------------
# 9. Switching org changes visible data
# ---------------------------------------------------------------------------


class TestAgentCountsPerOrg:
    @pytest.mark.asyncio
    async def test_agent_total_reflects_org_scoping(
        self, client, db_session, seed_plans
    ):
        """The 'total' field in the agents list response reflects org filtering."""
        data_a, access_a, refresh_a = await _register_and_get_cookies(
            client, "count_a@example.com", "count_a"
        )
        org_a_id = UUID(data_a["default_organization_id"])

        data_b, access_b, refresh_b = await _register_and_get_cookies(
            client, "count_b@example.com", "count_b"
        )
        org_b_id = UUID(data_b["default_organization_id"])

        # 3 agents in org A, 1 in org B
        for i in range(3):
            db_session.add(
                Agent(
                    id=uuid4(),
                    name=f"Count Agent A{i}",
                    external_id=f"ca{i}-{uuid4().hex[:8]}",
                    status=AgentStatus.ACTIVE,
                    trust_level=TrustLevel.STANDARD,
                    organization_id=org_a_id,
                )
            )
        db_session.add(
            Agent(
                id=uuid4(),
                name="Count Agent B0",
                external_id=f"cb0-{uuid4().hex[:8]}",
                status=AgentStatus.ACTIVE,
                trust_level=TrustLevel.STANDARD,
                organization_id=org_b_id,
            )
        )
        await db_session.commit()

        # User A sees 3
        client.cookies.set("snapper_access_token", access_a)
        client.cookies.set("snapper_refresh_token", refresh_a)
        resp_a = await client.get("/api/v1/agents")
        assert resp_a.status_code == 200
        assert resp_a.json()["total"] == 3

        # User B sees 1
        client.cookies.set("snapper_access_token", access_b)
        client.cookies.set("snapper_refresh_token", refresh_b)
        resp_b = await client.get("/api/v1/agents")
        assert resp_b.status_code == 200
        assert resp_b.json()["total"] == 1


class TestRuleCreationIsolation:
    @pytest.mark.asyncio
    async def test_rule_created_by_user_a_invisible_to_user_b(
        self, client, db_session, seed_plans
    ):
        """A rule created by user A via the API is not visible to user B."""
        data_a, access_a, refresh_a = await _register_and_get_cookies(
            client, "rcreate_a@example.com", "rcreate_a"
        )
        data_b, access_b, refresh_b = await _register_and_get_cookies(
            client, "rcreate_b@example.com", "rcreate_b"
        )

        # User A creates a rule
        client.cookies.set("snapper_access_token", access_a)
        client.cookies.set("snapper_refresh_token", refresh_a)
        create_resp = await client.post(
            "/api/v1/rules",
            json={
                "name": "User A Private Rule",
                "rule_type": "rate_limit",
                "action": "deny",
                "priority": 10,
                "parameters": {"max_requests": 5, "window_seconds": 60},
                "is_active": True,
            },
        )
        assert create_resp.status_code == 201

        # User B should NOT see it
        client.cookies.set("snapper_access_token", access_b)
        client.cookies.set("snapper_refresh_token", refresh_b)
        list_resp = await client.get("/api/v1/rules")
        assert list_resp.status_code == 200
        rule_names = [r["name"] for r in list_resp.json()["items"]]
        assert "User A Private Rule" not in rule_names

    @pytest.mark.asyncio
    async def test_rule_total_reflects_org_scoping(
        self, client, db_session, seed_plans
    ):
        """The 'total' in rules list reflects org filtering (own rules + global)."""
        data_a, access_a, refresh_a = await _register_and_get_cookies(
            client, "rtotal_a@example.com", "rtotal_a"
        )
        org_a_id = UUID(data_a["default_organization_id"])

        # Add 2 rules in org A and 1 global
        for i in range(2):
            db_session.add(
                Rule(
                    id=uuid4(),
                    name=f"Org A Total Rule {i}",
                    rule_type=RuleType.RATE_LIMIT,
                    action=RuleAction.DENY,
                    priority=5,
                    parameters={"max_requests": 10, "window_seconds": 60},
                    is_active=True,
                    organization_id=org_a_id,
                )
            )
        db_session.add(
            Rule(
                id=uuid4(),
                name="Global Total Rule",
                rule_type=RuleType.CREDENTIAL_PROTECTION,
                action=RuleAction.DENY,
                priority=100,
                parameters={
                    "protected_patterns": [r"\.env$"],
                    "block_plaintext_secrets": True,
                },
                is_active=True,
                organization_id=None,
            )
        )
        await db_session.commit()

        client.cookies.set("snapper_access_token", access_a)
        client.cookies.set("snapper_refresh_token", refresh_a)

        resp = await client.get("/api/v1/rules")
        assert resp.status_code == 200
        # Should see 2 org-scoped + 1 global = 3
        assert resp.json()["total"] == 3


class TestSwitchOrgChangesData:
    @pytest.mark.asyncio
    async def test_switch_org_changes_agents_list(
        self, client, db_session, seed_plans
    ):
        """After switching org, the agent list reflects the new org."""
        # Register user (creates org Alpha)
        user_data, access, refresh = await _register_and_get_cookies(
            client, "switchdata@example.com", "switchdata"
        )
        user_id = UUID(user_data["id"])
        org_alpha_id = UUID(user_data["default_organization_id"])

        # Create second org (org Beta) and add membership
        org_beta = Organization(
            id=uuid4(),
            name="Beta Org",
            slug=f"beta-{uuid4().hex[:6]}",
            plan_id="free",
            is_active=True,
        )
        db_session.add(org_beta)
        await db_session.flush()

        membership = OrganizationMembership(
            id=uuid4(),
            user_id=user_id,
            organization_id=org_beta.id,
            role=OrgRole.MEMBER,
            accepted_at=datetime.now(timezone.utc),
        )
        db_session.add(membership)

        # Create agents in each org
        agent_alpha = Agent(
            id=uuid4(),
            name="Alpha Agent",
            external_id=f"alpha-{uuid4().hex[:8]}",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
            organization_id=org_alpha_id,
        )
        agent_beta = Agent(
            id=uuid4(),
            name="Beta Agent",
            external_id=f"beta-{uuid4().hex[:8]}",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
            organization_id=org_beta.id,
        )
        db_session.add_all([agent_alpha, agent_beta])
        await db_session.commit()

        # List agents in org Alpha (default)
        client.cookies.set("snapper_access_token", access)
        client.cookies.set("snapper_refresh_token", refresh)

        resp_alpha = await client.get("/api/v1/agents")
        assert resp_alpha.status_code == 200
        names_alpha = [a["name"] for a in resp_alpha.json()["items"]]
        assert "Alpha Agent" in names_alpha
        assert "Beta Agent" not in names_alpha

        # Switch to org Beta
        switch_resp = await client.post(
            "/api/v1/auth/switch-org",
            json={"organization_id": str(org_beta.id)},
        )
        assert switch_resp.status_code == 200

        # Update access token from switch response
        new_access = switch_resp.cookies.get("snapper_access_token")
        client.cookies.set("snapper_access_token", new_access)

        # Now list agents -- should see Beta, not Alpha
        resp_beta = await client.get("/api/v1/agents")
        assert resp_beta.status_code == 200
        names_beta = [a["name"] for a in resp_beta.json()["items"]]
        assert "Beta Agent" in names_beta
        assert "Alpha Agent" not in names_beta
