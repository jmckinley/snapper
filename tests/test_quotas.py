"""
@module test_quotas
@description Tests for the plan service (app/services/plans.py) and quota
checker dependency (app/services/quota.py).
"""

import os
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agents import Agent, AgentStatus, TrustLevel
from app.models.organizations import Organization, OrganizationMembership, OrgRole, Plan, Team
from app.models.pii_vault import PIICategory, PIIVaultEntry
from app.models.rules import Rule, RuleAction, RuleType


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def seed_plans(db_session: AsyncSession):
    """Seed the three standard plans: free, pro, enterprise."""
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


@pytest_asyncio.fixture
async def org_with_plan(db_session: AsyncSession, seed_plans):
    """Create an organization on the free plan."""
    org = Organization(
        id=uuid4(),
        name="Test Org",
        slug="test-org",
        plan_id="free",
        is_active=True,
    )
    db_session.add(org)
    await db_session.flush()
    return org


@pytest_asyncio.fixture
async def pro_org(db_session: AsyncSession, seed_plans):
    """Create an organization on the pro plan."""
    org = Organization(
        id=uuid4(),
        name="Pro Org",
        slug="pro-org",
        plan_id="pro",
        is_active=True,
    )
    db_session.add(org)
    await db_session.flush()
    return org


@pytest_asyncio.fixture
async def enterprise_org(db_session: AsyncSession, seed_plans):
    """Create an organization on the enterprise (unlimited) plan."""
    org = Organization(
        id=uuid4(),
        name="Enterprise Org",
        slug="enterprise-org",
        plan_id="enterprise",
        is_active=True,
    )
    db_session.add(org)
    await db_session.flush()
    return org


# ---------------------------------------------------------------------------
# Tests -- get_plan
# ---------------------------------------------------------------------------


class TestGetPlan:
    """Tests for plans.get_plan()."""

    @pytest.mark.asyncio
    async def test_get_plan_by_id(self, db_session, seed_plans):
        """get_plan returns the correct plan when given a valid ID."""
        from app.services.plans import get_plan

        plan = await get_plan(db_session, "free")
        assert plan.id == "free"
        assert plan.name == "Free"
        assert plan.max_agents == 1

    @pytest.mark.asyncio
    async def test_get_plan_pro(self, db_session, seed_plans):
        """get_plan returns the pro plan with correct limits."""
        from app.services.plans import get_plan

        plan = await get_plan(db_session, "pro")
        assert plan.id == "pro"
        assert plan.max_agents == 10
        assert plan.max_rules == 100
        assert plan.price_monthly_cents == 2900

    @pytest.mark.asyncio
    async def test_get_plan_enterprise(self, db_session, seed_plans):
        """get_plan returns the enterprise plan with unlimited (-1) limits."""
        from app.services.plans import get_plan

        plan = await get_plan(db_session, "enterprise")
        assert plan.id == "enterprise"
        assert plan.max_agents == -1
        assert plan.max_rules == -1

    @pytest.mark.asyncio
    async def test_get_plan_not_found(self, db_session, seed_plans):
        """get_plan raises 404 for a nonexistent plan ID."""
        from app.services.plans import get_plan

        with pytest.raises(HTTPException) as exc_info:
            await get_plan(db_session, "nonexistent")
        assert exc_info.value.status_code == 404
        assert "nonexistent" in str(exc_info.value.detail)


# ---------------------------------------------------------------------------
# Tests -- check_quota
# ---------------------------------------------------------------------------


class TestCheckQuota:
    """Tests for plans.check_quota()."""

    @pytest.mark.asyncio
    async def test_check_quota_passes_under_limit(self, db_session, org_with_plan):
        """check_quota does not raise when resource count is below the plan limit."""
        from app.services.plans import check_quota

        # Free plan allows 1 agent, org has 0 agents => should pass
        await check_quota(db_session, org_with_plan.id, "agents")

    @pytest.mark.asyncio
    async def test_check_quota_raises_402_at_limit(self, db_session, org_with_plan):
        """check_quota raises 402 when resource count equals the plan limit."""
        from app.services.plans import check_quota

        # Create 1 agent (free plan limit = 1)
        agent = Agent(
            id=uuid4(),
            name="Quota Agent",
            external_id=f"quota-{uuid4().hex[:8]}",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
            organization_id=org_with_plan.id,
            is_deleted=False,
        )
        db_session.add(agent)
        await db_session.flush()

        with pytest.raises(HTTPException) as exc_info:
            await check_quota(db_session, org_with_plan.id, "agents")
        assert exc_info.value.status_code == 402
        assert exc_info.value.detail["error"] == "quota_exceeded"
        assert exc_info.value.detail["resource"] == "agents"
        assert exc_info.value.detail["used"] == 1
        assert exc_info.value.detail["limit"] == 1

    @pytest.mark.asyncio
    async def test_check_quota_raises_402_over_limit_rules(self, db_session, org_with_plan):
        """check_quota raises 402 when rule count exceeds the plan limit."""
        from app.services.plans import check_quota

        # Free plan allows 10 rules -- create exactly 10
        for i in range(10):
            rule = Rule(
                id=uuid4(),
                name=f"Rule {i}",
                rule_type=RuleType.COMMAND_ALLOWLIST,
                action=RuleAction.ALLOW,
                priority=10,
                parameters={"commands": [f"cmd-{i}"]},
                is_active=True,
                is_deleted=False,
                organization_id=org_with_plan.id,
            )
            db_session.add(rule)
        await db_session.flush()

        with pytest.raises(HTTPException) as exc_info:
            await check_quota(db_session, org_with_plan.id, "rules")
        assert exc_info.value.status_code == 402
        assert exc_info.value.detail["used"] == 10
        assert exc_info.value.detail["limit"] == 10

    @pytest.mark.asyncio
    async def test_check_quota_vault_entries(self, db_session, org_with_plan):
        """check_quota raises 402 for vault_entries when at limit."""
        from app.services.plans import check_quota

        # Free plan allows 5 vault entries
        for i in range(5):
            entry = PIIVaultEntry(
                id=uuid4(),
                owner_chat_id="test-chat",
                label=f"Entry {i}",
                category=PIICategory.EMAIL,
                vault_token=f"{{{{SNAPPER_VAULT:{uuid4().hex[:32]}}}}}",
                encrypted_value=b"encrypted",
                organization_id=org_with_plan.id,
                is_deleted=False,
            )
            db_session.add(entry)
        await db_session.flush()

        with pytest.raises(HTTPException) as exc_info:
            await check_quota(db_session, org_with_plan.id, "vault_entries")
        assert exc_info.value.status_code == 402
        assert exc_info.value.detail["used"] == 5
        assert exc_info.value.detail["limit"] == 5

    @pytest.mark.asyncio
    async def test_check_quota_skips_unlimited(self, db_session, enterprise_org):
        """check_quota allows through when plan limit is -1 (unlimited)."""
        from app.services.plans import check_quota

        # Enterprise plan has unlimited agents (-1). Create many, should still pass.
        for i in range(20):
            agent = Agent(
                id=uuid4(),
                name=f"Enterprise Agent {i}",
                external_id=f"ent-agent-{uuid4().hex[:8]}",
                status=AgentStatus.ACTIVE,
                trust_level=TrustLevel.STANDARD,
                organization_id=enterprise_org.id,
                is_deleted=False,
            )
            db_session.add(agent)
        await db_session.flush()

        # Should not raise
        await check_quota(db_session, enterprise_org.id, "agents")

    @pytest.mark.asyncio
    async def test_check_quota_skips_self_hosted(self, db_session, org_with_plan, monkeypatch):
        """check_quota returns None (no-op) when SELF_HOSTED=True."""
        monkeypatch.setenv("SELF_HOSTED", "true")
        from app.config import get_settings
        get_settings.cache_clear()

        # Re-import to pick up new settings
        import importlib
        import app.services.plans as plans_mod
        importlib.reload(plans_mod)

        # Create an agent to fill the quota
        agent = Agent(
            id=uuid4(),
            name="Self-hosted Agent",
            external_id=f"sh-{uuid4().hex[:8]}",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
            organization_id=org_with_plan.id,
            is_deleted=False,
        )
        db_session.add(agent)
        await db_session.flush()

        # Even though free plan limit is 1 and we have 1, self-hosted skips the check
        result = await plans_mod.check_quota(db_session, org_with_plan.id, "agents")
        assert result is None

        # Restore original settings
        monkeypatch.delenv("SELF_HOSTED", raising=False)
        get_settings.cache_clear()
        importlib.reload(plans_mod)

    @pytest.mark.asyncio
    async def test_check_quota_org_not_found(self, db_session, seed_plans):
        """check_quota raises 404 when the organization does not exist."""
        from app.services.plans import check_quota

        with pytest.raises(HTTPException) as exc_info:
            await check_quota(db_session, uuid4(), "agents")
        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_check_quota_unknown_resource_type(self, db_session, org_with_plan):
        """check_quota raises ValueError for an unknown resource type."""
        from app.services.plans import check_quota

        with pytest.raises(ValueError, match="Unknown resource type"):
            await check_quota(db_session, org_with_plan.id, "unknown_resource")

    @pytest.mark.asyncio
    async def test_check_quota_team_members(self, db_session, org_with_plan):
        """check_quota raises 402 for team_members when at limit."""
        from app.services.plans import check_quota
        from app.models.users import User

        # Free plan allows 1 team member -- add one membership
        user = User(
            id=uuid4(),
            email="member@test.com",
            username="testmember",
            password_hash="hashed",
        )
        db_session.add(user)
        await db_session.flush()

        membership = OrganizationMembership(
            id=uuid4(),
            user_id=user.id,
            organization_id=org_with_plan.id,
            role=OrgRole.MEMBER,
        )
        db_session.add(membership)
        await db_session.flush()

        with pytest.raises(HTTPException) as exc_info:
            await check_quota(db_session, org_with_plan.id, "team_members")
        assert exc_info.value.status_code == 402
        assert exc_info.value.detail["used"] == 1
        assert exc_info.value.detail["limit"] == 1

    @pytest.mark.asyncio
    async def test_check_quota_teams(self, db_session, org_with_plan):
        """check_quota raises 402 for teams when at limit."""
        from app.services.plans import check_quota

        # Free plan allows 1 team
        team = Team(
            id=uuid4(),
            organization_id=org_with_plan.id,
            name="Default Team",
            slug="default",
            is_default=True,
        )
        db_session.add(team)
        await db_session.flush()

        with pytest.raises(HTTPException) as exc_info:
            await check_quota(db_session, org_with_plan.id, "teams")
        assert exc_info.value.status_code == 402
        assert exc_info.value.detail["used"] == 1
        assert exc_info.value.detail["limit"] == 1

    @pytest.mark.asyncio
    async def test_check_quota_deleted_resources_not_counted(self, db_session, org_with_plan):
        """check_quota does not count soft-deleted agents toward the limit."""
        from app.services.plans import check_quota

        # Create a soft-deleted agent
        agent = Agent(
            id=uuid4(),
            name="Deleted Agent",
            external_id=f"del-{uuid4().hex[:8]}",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
            organization_id=org_with_plan.id,
            is_deleted=True,
        )
        db_session.add(agent)
        await db_session.flush()

        # Free plan limit is 1, but the one agent is deleted => should pass
        await check_quota(db_session, org_with_plan.id, "agents")


# ---------------------------------------------------------------------------
# Tests -- has_feature
# ---------------------------------------------------------------------------


class TestHasFeature:
    """Tests for plans.has_feature()."""

    @pytest.mark.asyncio
    async def test_has_feature_true(self, db_session, pro_org):
        """has_feature returns True for a feature enabled in the plan."""
        from app.services.plans import has_feature

        result = await has_feature(db_session, pro_org.id, "slack_integration")
        assert result is True

    @pytest.mark.asyncio
    async def test_has_feature_false(self, db_session, org_with_plan):
        """has_feature returns False for a feature disabled in the free plan."""
        from app.services.plans import has_feature

        result = await has_feature(db_session, org_with_plan.id, "slack_integration")
        assert result is False

    @pytest.mark.asyncio
    async def test_has_feature_org_override_enables(self, db_session, org_with_plan):
        """has_feature returns True when org feature_overrides override a disabled plan feature."""
        from app.services.plans import has_feature

        # Free plan disables slack_integration, but org override enables it
        org_with_plan.feature_overrides = {"slack_integration": True}
        await db_session.flush()

        result = await has_feature(db_session, org_with_plan.id, "slack_integration")
        assert result is True

    @pytest.mark.asyncio
    async def test_has_feature_org_override_disables(self, db_session, pro_org):
        """has_feature returns False when org override disables an otherwise enabled feature."""
        from app.services.plans import has_feature

        # Pro plan enables audit_export, but org override disables it
        pro_org.feature_overrides = {"audit_export": False}
        await db_session.flush()

        result = await has_feature(db_session, pro_org.id, "audit_export")
        assert result is False

    @pytest.mark.asyncio
    async def test_has_feature_unknown_feature_returns_false(self, db_session, pro_org):
        """has_feature returns False for a feature not defined in the plan."""
        from app.services.plans import has_feature

        result = await has_feature(db_session, pro_org.id, "nonexistent_feature")
        assert result is False

    @pytest.mark.asyncio
    async def test_has_feature_nonexistent_org_returns_false(self, db_session, seed_plans):
        """has_feature returns False when the org ID does not exist."""
        from app.services.plans import has_feature

        result = await has_feature(db_session, uuid4(), "slack_integration")
        assert result is False

    @pytest.mark.asyncio
    async def test_has_feature_sso_enterprise_only(self, db_session, enterprise_org, org_with_plan):
        """SSO feature is only available on enterprise plan."""
        from app.services.plans import has_feature

        assert await has_feature(db_session, enterprise_org.id, "sso") is True
        assert await has_feature(db_session, org_with_plan.id, "sso") is False


# ---------------------------------------------------------------------------
# Tests -- get_usage
# ---------------------------------------------------------------------------


class TestGetUsage:
    """Tests for plans.get_usage()."""

    @pytest.mark.asyncio
    async def test_get_usage_empty_org(self, db_session, org_with_plan):
        """get_usage returns correct zero counts for an org with no resources."""
        from app.services.plans import get_usage

        usage = await get_usage(db_session, org_with_plan.id)

        assert usage["plan_id"] == "free"
        assert usage["plan_name"] == "Free"
        assert usage["agents"]["used"] == 0
        assert usage["agents"]["limit"] == 1
        assert usage["agents"]["is_unlimited"] is False
        assert usage["rules"]["used"] == 0
        assert usage["rules"]["limit"] == 10
        assert usage["vault_entries"]["used"] == 0
        assert usage["vault_entries"]["limit"] == 5
        assert usage["team_members"]["used"] == 0
        assert usage["teams"]["used"] == 0

    @pytest.mark.asyncio
    async def test_get_usage_with_resources(self, db_session, pro_org):
        """get_usage counts agents and rules belonging to the org."""
        from app.services.plans import get_usage

        # Create 3 agents in the pro org
        for i in range(3):
            agent = Agent(
                id=uuid4(),
                name=f"Agent {i}",
                external_id=f"usage-agent-{uuid4().hex[:8]}",
                status=AgentStatus.ACTIVE,
                trust_level=TrustLevel.STANDARD,
                organization_id=pro_org.id,
                is_deleted=False,
            )
            db_session.add(agent)

        # Create 5 rules
        for i in range(5):
            rule = Rule(
                id=uuid4(),
                name=f"Rule {i}",
                rule_type=RuleType.COMMAND_ALLOWLIST,
                action=RuleAction.ALLOW,
                priority=10,
                parameters={"commands": ["ls"]},
                is_active=True,
                is_deleted=False,
                organization_id=pro_org.id,
            )
            db_session.add(rule)
        await db_session.flush()

        usage = await get_usage(db_session, pro_org.id)

        assert usage["plan_id"] == "pro"
        assert usage["agents"]["used"] == 3
        assert usage["agents"]["limit"] == 10
        assert usage["rules"]["used"] == 5
        assert usage["rules"]["limit"] == 100

    @pytest.mark.asyncio
    async def test_get_usage_enterprise_unlimited(self, db_session, enterprise_org):
        """get_usage marks enterprise limits as is_unlimited=True."""
        from app.services.plans import get_usage

        usage = await get_usage(db_session, enterprise_org.id)

        assert usage["agents"]["is_unlimited"] is True
        assert usage["agents"]["limit"] == -1
        assert usage["rules"]["is_unlimited"] is True

    @pytest.mark.asyncio
    async def test_get_usage_merged_features(self, db_session, org_with_plan):
        """get_usage merges plan features with org overrides."""
        from app.services.plans import get_usage

        org_with_plan.feature_overrides = {"custom_feature": True}
        await db_session.flush()

        usage = await get_usage(db_session, org_with_plan.id)

        # Plan features should be present
        assert usage["features"]["slack_integration"] is False
        # Org override should also be present
        assert usage["features"]["custom_feature"] is True

    @pytest.mark.asyncio
    async def test_get_usage_org_not_found(self, db_session, seed_plans):
        """get_usage raises 404 when the organization does not exist."""
        from app.services.plans import get_usage

        with pytest.raises(HTTPException) as exc_info:
            await get_usage(db_session, uuid4())
        assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# Tests -- QuotaChecker dependency
# ---------------------------------------------------------------------------


class TestQuotaChecker:
    """Tests for the QuotaChecker FastAPI dependency class."""

    @pytest.mark.asyncio
    async def test_quota_checker_skips_when_no_org_id(self, db_session):
        """QuotaChecker returns None (no-op) when request.state has no org_id."""
        from unittest.mock import AsyncMock, MagicMock

        from app.services.quota import QuotaChecker

        checker = QuotaChecker("agents")

        request = MagicMock()
        request.state = MagicMock(spec=[])  # Empty state -- no org_id attribute

        # Should complete without error
        result = await checker(request, db_session)
        assert result is None

    @pytest.mark.asyncio
    async def test_quota_checker_skips_self_hosted(self, db_session, monkeypatch):
        """QuotaChecker returns None (no-op) when SELF_HOSTED=True."""
        monkeypatch.setenv("SELF_HOSTED", "true")
        from app.config import get_settings
        get_settings.cache_clear()

        import importlib
        import app.services.quota as quota_mod
        importlib.reload(quota_mod)

        from unittest.mock import MagicMock

        checker = quota_mod.QuotaChecker("agents")
        request = MagicMock()
        request.state.org_id = str(uuid4())

        result = await checker(request, db_session)
        assert result is None

        # Restore
        monkeypatch.delenv("SELF_HOSTED", raising=False)
        get_settings.cache_clear()
        importlib.reload(quota_mod)

    @pytest.mark.asyncio
    async def test_quota_checker_delegates_to_check_quota(self, db_session, org_with_plan):
        """QuotaChecker calls check_quota which raises 402 when over limit."""
        from unittest.mock import MagicMock

        from app.services.quota import QuotaChecker

        # Fill the agent quota (free plan = 1)
        agent = Agent(
            id=uuid4(),
            name="Checker Agent",
            external_id=f"checker-{uuid4().hex[:8]}",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
            organization_id=org_with_plan.id,
            is_deleted=False,
        )
        db_session.add(agent)
        await db_session.flush()

        checker = QuotaChecker("agents")
        request = MagicMock()
        request.state.org_id = str(org_with_plan.id)

        with pytest.raises(HTTPException) as exc_info:
            await checker(request, db_session)
        assert exc_info.value.status_code == 402
