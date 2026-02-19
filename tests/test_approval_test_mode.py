"""Tests for approval test mode — sandboxed webhook simulation.

Covers: test webhook delivery, test approval sandboxing,
test decisions not affecting real state, policy dry-run.
"""

import pytest
import pytest_asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agents import Agent, AgentStatus, TrustLevel
from app.models.organizations import Organization, Plan
from app.routers.approvals import (
    APPROVAL_PREFIX,
    TEST_APPROVAL_PREFIX,
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
        return
    plans = [
        Plan(id="free", name="Free", max_agents=3, max_rules=10, max_vault_entries=5,
             max_team_members=1, max_teams=1, price_monthly_cents=0, price_yearly_cents=0,
             features={}),
    ]
    for p in plans:
        db_session.add(p)
    await db_session.flush()


@pytest_asyncio.fixture
async def org(db_session: AsyncSession, seed_plans):
    org = Organization(
        id=uuid4(),
        name="Test Mode Org",
        slug=f"test-mode-{uuid4().hex[:8]}",
        plan_id="free",
        is_active=True,
        settings={
            "webhooks": [
                {
                    "id": str(uuid4()),
                    "url": "https://httpbin.org/post",
                    "secret": "test-secret",
                    "event_filters": [],
                    "active": True,
                    "created_at": "2026-02-18T00:00:00",
                }
            ],
            "approval_policies": [
                {
                    "id": str(uuid4()),
                    "name": "Auto-approve reads",
                    "active": True,
                    "priority": 10,
                    "conditions": {
                        "request_types": ["command"],
                        "command_patterns": [r"^(ls|cat|head)"],
                    },
                    "decision": "approve",
                    "max_auto_per_hour": 100,
                    "created_at": "2026-02-18T00:00:00",
                },
            ],
            "approval_policies_enabled": True,
        },
    )
    db_session.add(org)
    await db_session.flush()
    return org


@pytest_asyncio.fixture
async def agent(db_session: AsyncSession, org: Organization):
    agent = Agent(
        id=uuid4(),
        name="Test Agent",
        external_id=f"test-{uuid4().hex[:8]}",
        description="Agent for test mode",
        status=AgentStatus.ACTIVE,
        trust_level=TrustLevel.STANDARD,
        organization_id=org.id,
        api_key=f"snp_test_{uuid4().hex[:16]}",
    )
    db_session.add(agent)
    await db_session.flush()
    await db_session.refresh(agent)
    return agent


# ---------------------------------------------------------------------------
# Tests: Test decision sandboxing
# ---------------------------------------------------------------------------


class TestDecisionSandboxing:
    """Tests for sandboxed test decisions via /decide."""

    @pytest.mark.asyncio
    async def test_test_decision_accepted(self, client, redis, agent, org):
        """Decisions on test approvals are accepted."""
        test_id = f"test_{uuid4()}"
        now = datetime.utcnow()
        test_approval = ApprovalRequest(
            id=test_id,
            agent_id=str(agent.id),
            agent_name=agent.name,
            request_type="command",
            command="echo test",
            rule_id="test-rule",
            rule_name="Test Rule",
            status="pending",
            created_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=60)).isoformat(),
            organization_id=str(org.id),
        )
        key = f"{TEST_APPROVAL_PREFIX}{test_id.removeprefix('test_')}"
        await redis.set(key, test_approval.model_dump_json(), expire=60)

        response = await client.post(
            f"/api/v1/approvals/{test_id}/decide",
            json={"decision": "approve", "reason": "Test bot approving"},
            headers={"X-API-Key": agent.api_key},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "approved"

    @pytest.mark.asyncio
    async def test_test_decision_does_not_affect_real_approvals(self, client, redis, agent, org):
        """Test decisions don't create real approval records."""
        # Create a real approval
        real_id = await create_approval_request(
            redis=redis,
            agent_id=str(agent.id),
            agent_name=agent.name,
            request_type="command",
            rule_id="rule-1",
            rule_name="Real Rule",
            command="real command",
            organization_id=str(org.id),
        )

        # Create test approval
        test_id = f"test_{uuid4()}"
        now = datetime.utcnow()
        test_approval = ApprovalRequest(
            id=test_id,
            agent_id=str(agent.id),
            agent_name=agent.name,
            request_type="command",
            command="test command",
            rule_id="test-rule",
            rule_name="Test Rule",
            status="pending",
            created_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=60)).isoformat(),
            organization_id=str(org.id),
        )
        key = f"{TEST_APPROVAL_PREFIX}{test_id.removeprefix('test_')}"
        await redis.set(key, test_approval.model_dump_json(), expire=60)

        # Decide on test approval
        await client.post(
            f"/api/v1/approvals/{test_id}/decide",
            json={"decision": "approve"},
            headers={"X-API-Key": agent.api_key},
        )

        # Verify real approval is still pending
        real_key = f"{APPROVAL_PREFIX}{real_id}"
        real_data = await redis.get(real_key)
        assert real_data is not None
        real_approval = ApprovalRequest.model_validate_json(real_data)
        assert real_approval.status == "pending"

    @pytest.mark.asyncio
    async def test_test_decision_skips_rate_cap(self, client, redis, agent, org):
        """Test decisions bypass automated approval rate cap."""
        rate_key = f"auto_approve_hourly:{org.id}"
        await redis.set(rate_key, "9999", expire=3600)

        test_id = f"test_{uuid4()}"
        now = datetime.utcnow()
        test_approval = ApprovalRequest(
            id=test_id,
            agent_id=str(agent.id),
            agent_name=agent.name,
            request_type="command",
            command="test",
            rule_id="test-rule",
            rule_name="Test",
            status="pending",
            created_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=60)).isoformat(),
            organization_id=str(org.id),
        )
        key = f"{TEST_APPROVAL_PREFIX}{test_id.removeprefix('test_')}"
        await redis.set(key, test_approval.model_dump_json(), expire=60)

        response = await client.post(
            f"/api/v1/approvals/{test_id}/decide",
            json={"decision": "approve"},
            headers={"X-API-Key": agent.api_key},
        )
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# Tests: Policy dry-run (unit-level, no auth middleware needed)
# ---------------------------------------------------------------------------


class TestPolicyDryRun:
    """Tests for approval policy dry-run evaluation (service-level)."""

    @pytest.mark.asyncio
    async def test_policy_dry_run_match(self, db_session, org, agent, redis):
        """Dry-run finds matching policy."""
        from app.services.approval_policies import evaluate_approval_policies

        result = await evaluate_approval_policies(
            db=db_session,
            organization_id=str(org.id),
            approval_data={"request_type": "command", "command": "ls -la", "vault_tokens": []},
            agent=agent,
            redis=redis,
        )
        assert result is not None
        assert result.decision == "approve"
        assert result.policy_name == "Auto-approve reads"

    @pytest.mark.asyncio
    async def test_policy_dry_run_no_match(self, db_session, org, agent, redis):
        """Dry-run reports no match for unmatched request."""
        from app.services.approval_policies import evaluate_approval_policies

        result = await evaluate_approval_policies(
            db=db_session,
            organization_id=str(org.id),
            approval_data={"request_type": "command", "command": "rm -rf /", "vault_tokens": []},
            agent=agent,
            redis=redis,
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_policy_dry_run_pii_blocks_approve(self, db_session, org, agent, redis):
        """Dry-run correctly blocks auto-approve when PII present."""
        from app.services.approval_policies import evaluate_approval_policies

        result = await evaluate_approval_policies(
            db=db_session,
            organization_id=str(org.id),
            approval_data={
                "request_type": "command",
                "command": "cat /etc/hosts",
                "vault_tokens": ["{{SNAPPER_VAULT:abc123}}"],
            },
            agent=agent,
            redis=redis,
        )
        assert result is None
