"""Tests for approval automation API — bot-in-the-middle.

Covers: /decide with org-scoped auth, rate caps, anomaly detection,
reason field, 410/409 status codes, audit trail with decision_source,
and full BITL (Bot-In-The-Loop) integration flows.
"""

import asyncio
import json
import pytest
import pytest_asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agents import Agent, AgentStatus, TrustLevel
from app.models.organizations import Organization, Plan
from app.models.rules import Rule, RuleType, RuleAction
from app.routers.approvals import (
    APPROVAL_PREFIX,
    ApprovalRequest,
    create_approval_request,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def seed_plans(db_session: AsyncSession):
    """Seed the plans reference table required by Organization FK."""
    from sqlalchemy import select
    result = await db_session.execute(select(Plan).where(Plan.id == "free"))
    if result.scalar_one_or_none():
        return  # Already seeded
    plans = [
        Plan(id="free", name="Free", max_agents=3, max_rules=10, max_vault_entries=5,
             max_team_members=1, max_teams=1, price_monthly_cents=0, price_yearly_cents=0,
             features={}),
        Plan(id="pro", name="Pro", max_agents=25, max_rules=100, max_vault_entries=50,
             max_team_members=10, max_teams=5, price_monthly_cents=2900, price_yearly_cents=29000,
             features={"slack_integration": True}),
    ]
    for p in plans:
        db_session.add(p)
    await db_session.flush()


@pytest_asyncio.fixture
async def org(db_session: AsyncSession, seed_plans):
    """Create a test organization."""
    org = Organization(
        id=uuid4(),
        name="Bot Test Org",
        slug=f"bot-test-{uuid4().hex[:8]}",
        plan_id="free",
        is_active=True,
        settings={},
    )
    db_session.add(org)
    await db_session.flush()
    return org


@pytest_asyncio.fixture
async def bot_agent(db_session: AsyncSession, org: Organization):
    """Agent acting as the automation bot (has API key, same org)."""
    agent = Agent(
        id=uuid4(),
        name="Approval Bot",
        external_id=f"bot-{uuid4().hex[:8]}",
        description="Automation bot for approvals",
        status=AgentStatus.ACTIVE,
        trust_level=TrustLevel.STANDARD,
        api_key=f"snp_bot_{uuid4().hex[:16]}",
        organization_id=org.id,
    )
    db_session.add(agent)
    await db_session.flush()
    await db_session.refresh(agent)
    return agent


@pytest_asyncio.fixture
async def target_agent(db_session: AsyncSession, org: Organization):
    """Agent whose action requires approval (same org)."""
    agent = Agent(
        id=uuid4(),
        name="Worker Agent",
        external_id=f"worker-{uuid4().hex[:8]}",
        description="Agent doing work",
        status=AgentStatus.ACTIVE,
        trust_level=TrustLevel.STANDARD,
        api_key=f"snp_wrk_{uuid4().hex[:16]}",
        organization_id=org.id,
    )
    db_session.add(agent)
    await db_session.flush()
    await db_session.refresh(agent)
    return agent


@pytest_asyncio.fixture
async def other_org_agent(db_session: AsyncSession, seed_plans):
    """Agent from a different org."""
    other_org = Organization(
        id=uuid4(),
        name="Other Org",
        slug=f"other-{uuid4().hex[:8]}",
        plan_id="free",
        is_active=True,
    )
    db_session.add(other_org)
    await db_session.flush()

    agent = Agent(
        id=uuid4(),
        name="Outsider Bot",
        external_id=f"outsider-{uuid4().hex[:8]}",
        description="Bot from another org",
        status=AgentStatus.ACTIVE,
        trust_level=TrustLevel.STANDARD,
        api_key=f"snp_out_{uuid4().hex[:16]}",
        organization_id=other_org.id,
    )
    db_session.add(agent)
    await db_session.flush()
    await db_session.refresh(agent)
    return agent


@pytest_asyncio.fixture
async def pending_approval(redis, target_agent, org):
    """Create a pending approval request in Redis."""
    approval_id = await create_approval_request(
        redis=redis,
        agent_id=str(target_agent.id),
        agent_name=target_agent.name,
        request_type="command",
        rule_id="rule-123",
        rule_name="Test Rule",
        command="rm -rf /tmp/test",
        organization_id=str(org.id),
    )
    return approval_id


@pytest_asyncio.fixture
async def approval_rule(db_session: AsyncSession, target_agent: Agent):
    """Create a human_in_loop rule requiring approval for destructive commands."""
    rule = Rule(
        id=uuid4(),
        name="Approve destructive commands",
        description="Require approval for rm, drop, delete",
        agent_id=target_agent.id,
        rule_type=RuleType.HUMAN_IN_LOOP,
        action=RuleAction.REQUIRE_APPROVAL,
        priority=50,
        parameters={"patterns": [r"^(rm|drop|delete|truncate)\b"]},
        is_active=True,
    )
    db_session.add(rule)
    await db_session.flush()
    return rule


@pytest_asyncio.fixture
async def denylist_rule(db_session: AsyncSession, target_agent: Agent):
    """Create a denylist rule blocking mkfs commands."""
    rule = Rule(
        id=uuid4(),
        name="Block mkfs",
        description="Deny mkfs commands outright",
        agent_id=target_agent.id,
        rule_type=RuleType.COMMAND_DENYLIST,
        action=RuleAction.DENY,
        priority=100,
        parameters={"patterns": [r"^mkfs\b"]},
        is_active=True,
    )
    db_session.add(rule)
    await db_session.flush()
    return rule


# ---------------------------------------------------------------------------
# Tests: /decide with bot auth
# ---------------------------------------------------------------------------


class TestBearerAuth:
    """Tests for Authorization: Bearer header support."""

    @pytest.mark.asyncio
    async def test_bearer_auth_header(self, client, bot_agent, pending_approval):
        """Bot using Authorization: Bearer snp_xxx should work like X-API-Key."""
        response = await client.post(
            f"/api/v1/approvals/{pending_approval}/decide",
            json={"decision": "approve", "reason": "Bearer auth test"},
            headers={"Authorization": f"Bearer {bot_agent.api_key}"},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "approved"


class TestSuspendedAgent:
    """Tests for suspended agent rejection."""

    @pytest.mark.asyncio
    async def test_suspended_agent_blocked(self, client, db_session, bot_agent, pending_approval):
        """Suspended agent gets 403 Forbidden on /decide."""
        bot_agent.status = AgentStatus.SUSPENDED
        await db_session.flush()

        response = await client.post(
            f"/api/v1/approvals/{pending_approval}/decide",
            json={"decision": "approve"},
            headers={"X-API-Key": bot_agent.api_key},
        )
        assert response.status_code == 403
        assert "suspended" in response.json()["detail"].lower()


class TestAnomalyDetectionThreshold:
    """Tests for rapid auto-approval anomaly detection."""

    @pytest.mark.asyncio
    async def test_anomaly_detection_fires(self, client, redis, bot_agent, target_agent, org):
        """Exceeding the anomaly threshold logs a warning (doesn't block, just alerts)."""
        from app.routers.approvals import ANOMALY_THRESHOLD

        # Seed the sorted set with entries exceeding threshold
        import time
        key = f"auto_approve_window:{bot_agent.id}"
        now = time.time()
        for i in range(ANOMALY_THRESHOLD + 5):
            await redis.zadd(key, {str(now - i): now - i})
        await redis.expire(key, 700)

        # Create and approve — should succeed but log anomaly
        approval_id = await create_approval_request(
            redis=redis,
            agent_id=str(target_agent.id),
            agent_name=target_agent.name,
            request_type="command",
            rule_id="rule-anom",
            rule_name="Anomaly Test",
            command="ls",
            organization_id=str(org.id),
        )

        response = await client.post(
            f"/api/v1/approvals/{approval_id}/decide",
            json={"decision": "approve"},
            headers={"X-API-Key": bot_agent.api_key},
        )
        # Anomaly detection logs a warning but doesn't block — decision should succeed
        assert response.status_code == 200


class TestRateCapOrgOverride:
    """Tests for per-org max_auto_approvals_per_hour override."""

    @pytest.mark.asyncio
    async def test_rate_cap_with_org_override(self, client, redis, db_session, bot_agent, target_agent, org):
        """Per-org override of max_auto_approvals_per_hour is respected."""
        # Set org override to 5
        org.settings = {"max_auto_approvals_per_hour": 5}
        await db_session.flush()

        # Simulate counter at 6 (over the override cap of 5)
        key = f"auto_approve_hourly:{org.id}"
        await redis.set(key, "6", expire=3600)

        approval_id = await create_approval_request(
            redis=redis,
            agent_id=str(target_agent.id),
            agent_name=target_agent.name,
            request_type="command",
            rule_id="rule-cap",
            rule_name="Cap Test",
            command="echo hello",
            organization_id=str(org.id),
        )

        response = await client.post(
            f"/api/v1/approvals/{approval_id}/decide",
            json={"decision": "approve"},
            headers={"X-API-Key": bot_agent.api_key},
        )
        assert response.status_code == 429


class TestNoAuthDevMode:
    """Tests for backward compat when REQUIRE_API_KEY=false."""

    @pytest.mark.asyncio
    async def test_decide_no_auth_dev_mode(self, client, pending_approval):
        """When REQUIRE_API_KEY=false, decisions work without auth (dev mode)."""
        response = await client.post(
            f"/api/v1/approvals/{pending_approval}/decide",
            json={"decision": "approve"},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "approved"


class TestBotDecideAuth:
    """Tests for org-scoped API key auth on /decide."""

    @pytest.mark.asyncio
    async def test_bot_can_approve_same_org(self, client, bot_agent, pending_approval):
        """Bot with API key in same org can approve."""
        response = await client.post(
            f"/api/v1/approvals/{pending_approval}/decide",
            json={"decision": "approve", "reason": "Matches safe pattern"},
            headers={"X-API-Key": bot_agent.api_key},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "approved"
        assert f"bot:{bot_agent.name}" in data["reason"]

    @pytest.mark.asyncio
    async def test_bot_can_deny_same_org(self, client, bot_agent, pending_approval):
        """Bot with API key in same org can deny."""
        response = await client.post(
            f"/api/v1/approvals/{pending_approval}/decide",
            json={"decision": "deny", "reason": "Destructive command"},
            headers={"X-API-Key": bot_agent.api_key},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "denied"

    @pytest.mark.asyncio
    async def test_other_org_bot_blocked(self, client, other_org_agent, pending_approval):
        """Bot from different org cannot decide on this approval."""
        response = await client.post(
            f"/api/v1/approvals/{pending_approval}/decide",
            json={"decision": "approve"},
            headers={"X-API-Key": other_org_agent.api_key},
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_invalid_api_key_rejected(self, client, pending_approval):
        """Invalid API key returns 401."""
        response = await client.post(
            f"/api/v1/approvals/{pending_approval}/decide",
            json={"decision": "approve"},
            headers={"X-API-Key": "snp_invalid_key_12345"},
        )
        assert response.status_code == 401


class TestDecideStatusCodes:
    """Tests for correct HTTP status codes on /decide."""

    @pytest.mark.asyncio
    async def test_expired_returns_410(self, client, redis, target_agent, org):
        """Expired/missing approval returns 410 Gone."""
        response = await client.post(
            "/api/v1/approvals/nonexistent-id/decide",
            json={"decision": "approve"},
        )
        assert response.status_code == 410

    @pytest.mark.asyncio
    async def test_already_decided_returns_409(self, client, bot_agent, pending_approval):
        """Double-deciding returns 409 Conflict."""
        resp1 = await client.post(
            f"/api/v1/approvals/{pending_approval}/decide",
            json={"decision": "approve"},
            headers={"X-API-Key": bot_agent.api_key},
        )
        assert resp1.status_code == 200

        resp2 = await client.post(
            f"/api/v1/approvals/{pending_approval}/decide",
            json={"decision": "deny"},
            headers={"X-API-Key": bot_agent.api_key},
        )
        assert resp2.status_code == 409


class TestDecideReasonField:
    """Tests for the reason field in decisions."""

    @pytest.mark.asyncio
    async def test_reason_stored_in_response(self, client, bot_agent, pending_approval):
        """Bot-provided reason is accepted."""
        response = await client.post(
            f"/api/v1/approvals/{pending_approval}/decide",
            json={
                "decision": "deny",
                "reason": "Command matches rm pattern, blocking for safety",
            },
            headers={"X-API-Key": bot_agent.api_key},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "denied"

    @pytest.mark.asyncio
    async def test_reason_optional(self, client, bot_agent, pending_approval):
        """Reason is optional — decisions work without it."""
        response = await client.post(
            f"/api/v1/approvals/{pending_approval}/decide",
            json={"decision": "approve"},
            headers={"X-API-Key": bot_agent.api_key},
        )
        assert response.status_code == 200


class TestDecideAuditTrail:
    """Tests for audit trail enrichment on /decide."""

    @pytest.mark.asyncio
    async def test_automation_decision_source_logged(self, client, bot_agent, pending_approval):
        """Bot decisions should be logged with decision_source=automation."""
        with patch("app.database.async_session_factory") as mock_factory:
            mock_db = AsyncMock()
            mock_factory.return_value.__aenter__ = AsyncMock(return_value=mock_db)
            mock_factory.return_value.__aexit__ = AsyncMock(return_value=False)

            response = await client.post(
                f"/api/v1/approvals/{pending_approval}/decide",
                json={"decision": "approve", "reason": "Safe pattern"},
                headers={"X-API-Key": bot_agent.api_key},
            )
            assert response.status_code == 200

            if mock_db.add.called:
                audit_log = mock_db.add.call_args[0][0]
                details = audit_log.new_value
                assert details["decision_source"] == "automation"
                assert details["channel"] == "api"
                assert details["automation_agent_name"] == bot_agent.name


class TestDecideRateCap:
    """Tests for per-org hourly automated approval rate cap."""

    @pytest.mark.asyncio
    async def test_rate_cap_enforced(self, client, redis, bot_agent, target_agent, org):
        """Exceeding the hourly cap returns 429."""
        # Simulate counter already over default cap (200)
        key = f"auto_approve_hourly:{org.id}"
        await redis.set(key, "201", expire=3600)

        approval_id = await create_approval_request(
            redis=redis,
            agent_id=str(target_agent.id),
            agent_name=target_agent.name,
            request_type="command",
            rule_id="rule-1",
            rule_name="Test",
            command="ls",
            organization_id=str(org.id),
        )

        response = await client.post(
            f"/api/v1/approvals/{approval_id}/decide",
            json={"decision": "approve"},
            headers={"X-API-Key": bot_agent.api_key},
        )
        assert response.status_code == 429
        assert "Retry-After" in response.headers


class TestPendingOrgFilter:
    """Tests for /pending with org-scoped filtering."""

    @pytest.mark.asyncio
    async def test_pending_filtered_by_org(self, client, bot_agent, pending_approval):
        """Bot sees only its org's pending approvals."""
        response = await client.get(
            "/api/v1/approvals/pending",
            headers={"X-API-Key": bot_agent.api_key},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["count"] >= 1
        for item in data["pending"]:
            if item.get("organization_id"):
                assert item["organization_id"] == str(bot_agent.organization_id)

    @pytest.mark.asyncio
    async def test_other_org_filtered_out(self, client, other_org_agent, pending_approval):
        """Bot from different org doesn't see these approvals."""
        response = await client.get(
            "/api/v1/approvals/pending",
            headers={"X-API-Key": other_org_agent.api_key},
        )
        assert response.status_code == 200
        data = response.json()
        ids = [a["id"] for a in data["pending"]]
        assert pending_approval not in ids


# ---------------------------------------------------------------------------
# Tests: Full BITL (Bot-In-The-Loop) Integration Flow
# ---------------------------------------------------------------------------


class TestBITLFullFlow:
    """End-to-end tests: create rules, generate traffic, bot approves/denies."""

    @pytest.mark.asyncio
    async def test_bitl_approve_flow(
        self, client, db_session, redis, bot_agent, target_agent, org, approval_rule
    ):
        """Full flow: agent sends command → require_approval → bot approves → status shows approved."""
        # Step 1: Agent sends a command that triggers require_approval
        eval_response = await client.post(
            "/api/v1/rules/evaluate",
            json={
                "agent_id": str(target_agent.id),
                "request_type": "command",
                "command": "rm -rf /tmp/build",
            },
            headers={"X-API-Key": target_agent.api_key},
        )
        assert eval_response.status_code == 200
        eval_data = eval_response.json()
        assert eval_data["decision"] == "require_approval"
        assert eval_data["approval_request_id"] is not None
        approval_id = eval_data["approval_request_id"]

        # Step 2: Bot polls /pending and finds the request
        pending_response = await client.get(
            "/api/v1/approvals/pending",
            headers={"X-API-Key": bot_agent.api_key},
        )
        assert pending_response.status_code == 200
        pending_data = pending_response.json()
        pending_ids = [a["id"] for a in pending_data["pending"]]
        assert approval_id in pending_ids

        # Step 3: Bot approves the request
        decide_response = await client.post(
            f"/api/v1/approvals/{approval_id}/decide",
            json={"decision": "approve", "reason": "Read-only cleanup, safe to proceed"},
            headers={"X-API-Key": bot_agent.api_key},
        )
        assert decide_response.status_code == 200
        assert decide_response.json()["status"] == "approved"

        # Step 4: Hook polls /status and sees approved
        status_response = await client.get(
            f"/api/v1/approvals/{approval_id}/status",
        )
        assert status_response.status_code == 200
        assert status_response.json()["status"] == "approved"
        assert "bot:Approval Bot" in status_response.json()["reason"]

    @pytest.mark.asyncio
    async def test_bitl_deny_flow(
        self, client, db_session, redis, bot_agent, target_agent, org, approval_rule
    ):
        """Full flow: agent sends destructive command → bot denies → status shows denied."""
        # Step 1: Trigger require_approval
        eval_response = await client.post(
            "/api/v1/rules/evaluate",
            json={
                "agent_id": str(target_agent.id),
                "request_type": "command",
                "command": "delete /var/data",
            },
            headers={"X-API-Key": target_agent.api_key},
        )
        assert eval_response.status_code == 200
        eval_data = eval_response.json()
        assert eval_data["decision"] == "require_approval"
        approval_id = eval_data["approval_request_id"]

        # Step 2: Bot denies
        decide_response = await client.post(
            f"/api/v1/approvals/{approval_id}/decide",
            json={"decision": "deny", "reason": "Data deletion not authorized"},
            headers={"X-API-Key": bot_agent.api_key},
        )
        assert decide_response.status_code == 200
        assert decide_response.json()["status"] == "denied"

        # Step 3: Verify status
        status_response = await client.get(f"/api/v1/approvals/{approval_id}/status")
        assert status_response.json()["status"] == "denied"

    @pytest.mark.asyncio
    async def test_bitl_deny_rule_blocks_outright(
        self, client, db_session, target_agent, denylist_rule
    ):
        """Denylist rule blocks immediately — no approval request created."""
        eval_response = await client.post(
            "/api/v1/rules/evaluate",
            json={
                "agent_id": str(target_agent.id),
                "request_type": "command",
                "command": "mkfs /dev/sda1",
            },
            headers={"X-API-Key": target_agent.api_key},
        )
        assert eval_response.status_code == 200
        eval_data = eval_response.json()
        assert eval_data["decision"] == "deny"
        assert eval_data["approval_request_id"] is None

    @pytest.mark.asyncio
    async def test_bitl_cross_org_isolation(
        self, client, db_session, redis, bot_agent, target_agent, org,
        other_org_agent, approval_rule,
    ):
        """Bot from another org cannot approve requests from this org."""
        # Create approval via evaluate
        eval_response = await client.post(
            "/api/v1/rules/evaluate",
            json={
                "agent_id": str(target_agent.id),
                "request_type": "command",
                "command": "rm /tmp/old",
            },
            headers={"X-API-Key": target_agent.api_key},
        )
        assert eval_response.status_code == 200
        approval_id = eval_response.json()["approval_request_id"]

        # Other org bot tries to approve → 403
        response = await client.post(
            f"/api/v1/approvals/{approval_id}/decide",
            json={"decision": "approve"},
            headers={"X-API-Key": other_org_agent.api_key},
        )
        assert response.status_code == 403

        # Same org bot succeeds
        response = await client.post(
            f"/api/v1/approvals/{approval_id}/decide",
            json={"decision": "approve"},
            headers={"X-API-Key": bot_agent.api_key},
        )
        assert response.status_code == 200
