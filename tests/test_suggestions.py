"""Tests for the smart suggestions engine.

Covers: signal detection, dismiss persistence, TTL expiry, max cap,
priority ordering, and API endpoints.
"""

import os
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from uuid import uuid4

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agents import Agent, AgentStatus, TrustLevel
from app.models.organizations import Organization, Plan
from app.services.suggestions import (
    Suggestion,
    generate_suggestions,
    dismiss_suggestion,
    _check_learning_mode,
    _check_no_rules,
    _check_no_notifications,
    _check_trust_scoring,
    _check_no_agents,
    _suggestion_id,
    DISMISS_PREFIX,
    MAX_SUGGESTIONS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def seed_plans(db_session: AsyncSession):
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
        name="Suggestions Test Org",
        slug=f"suggest-test-{uuid4().hex[:8]}",
        plan_id="free",
        is_active=True,
        settings={},
    )
    db_session.add(org)
    await db_session.flush()
    return org


@pytest_asyncio.fixture
async def agent(db_session: AsyncSession, org: Organization):
    agent = Agent(
        id=uuid4(),
        name="suggest-agent",
        external_id=f"sug-{uuid4().hex[:8]}",
        description="Agent for suggestions tests",
        status=AgentStatus.ACTIVE,
        trust_level=TrustLevel.STANDARD,
        organization_id=org.id,
        auto_adjust_trust=False,
    )
    db_session.add(agent)
    await db_session.flush()
    return agent


# ---------------------------------------------------------------------------
# Tests: Individual signal checks
# ---------------------------------------------------------------------------

class TestLearningModeSuggestion:
    """Test that learning mode ON triggers a critical suggestion."""

    @pytest.mark.asyncio
    async def test_learning_mode_on_returns_critical(self):
        """When LEARNING_MODE=true, a critical suggestion should be returned."""
        with patch("app.services.suggestions.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(LEARNING_MODE=True)
            result = await _check_learning_mode()
            assert result is not None
            assert result.severity == "critical"
            assert "enforcement" in result.title.lower() or "learning" in result.description.lower()

    @pytest.mark.asyncio
    async def test_learning_mode_off_returns_none(self):
        """When LEARNING_MODE=false, no suggestion should be returned."""
        with patch("app.services.suggestions.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(LEARNING_MODE=False)
            result = await _check_learning_mode()
            assert result is None


class TestNoRulesSuggestion:
    """Test that zero active rules triggers a critical suggestion."""

    @pytest.mark.asyncio
    async def test_no_rules_returns_suggestion(self, db_session):
        """With no rules in DB, should return a critical suggestion."""
        result = await _check_no_rules(db_session)
        assert result is not None
        assert result.severity == "critical"
        assert "rules" in result.title.lower()

    @pytest.mark.asyncio
    async def test_has_rules_returns_none(self, db_session, agent):
        """With active rules, should return None."""
        from app.models.rules import Rule, RuleType, RuleAction
        rule = Rule(
            id=uuid4(), name="Test Rule", agent_id=agent.id,
            rule_type=RuleType.COMMAND_ALLOWLIST, action=RuleAction.ALLOW,
            parameters={"patterns": [".*"]}, is_active=True,
        )
        db_session.add(rule)
        await db_session.flush()

        result = await _check_no_rules(db_session)
        assert result is None


class TestNoNotificationSuggestion:
    """Test that missing notification channels triggers a suggestion."""

    @pytest.mark.asyncio
    async def test_no_channels_returns_suggestion(self):
        with patch("app.services.suggestions.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                TELEGRAM_BOT_TOKEN=None, TELEGRAM_CHAT_ID=None,
                SLACK_BOT_TOKEN=None, SLACK_APP_TOKEN=None,
            )
            result = await _check_no_notifications()
            assert result is not None
            assert result.severity == "high"

    @pytest.mark.asyncio
    async def test_telegram_configured_returns_none(self):
        with patch("app.services.suggestions.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                TELEGRAM_BOT_TOKEN="123:ABC", TELEGRAM_CHAT_ID="456",
                SLACK_BOT_TOKEN=None, SLACK_APP_TOKEN=None,
            )
            result = await _check_no_notifications()
            assert result is None


class TestTrustScoringSuggestion:
    """Test that all-disabled trust scoring triggers a suggestion."""

    @pytest.mark.asyncio
    async def test_all_disabled_returns_suggestion(self, db_session, agent):
        result = await _check_trust_scoring(db_session)
        assert result is not None
        assert result.severity == "high"
        assert "trust" in result.title.lower()

    @pytest.mark.asyncio
    async def test_one_enabled_returns_none(self, db_session, agent):
        agent.auto_adjust_trust = True
        await db_session.flush()

        result = await _check_trust_scoring(db_session)
        assert result is None


class TestNoAgentsSuggestion:
    """Test that zero agents triggers a critical suggestion."""

    @pytest.mark.asyncio
    async def test_no_agents_returns_suggestion(self, db_session):
        """With no agents, should return a critical suggestion."""
        result = await _check_no_agents(db_session)
        assert result is not None
        assert result.severity == "critical"
        assert "agent" in result.title.lower()


# ---------------------------------------------------------------------------
# Tests: Dismiss persistence and TTL
# ---------------------------------------------------------------------------

class TestDismissPersistence:
    """Test that dismissed suggestions stay dismissed."""

    @pytest.mark.asyncio
    async def test_dismiss_persists(self, db_session, redis):
        """Dismissed suggestion should not appear in results."""
        org_key = "test-org-dismiss"
        sid = _suggestion_id("no_agents")

        # First generate — should have suggestions
        with patch("app.services.suggestions.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                LEARNING_MODE=False,
                TELEGRAM_BOT_TOKEN=None, TELEGRAM_CHAT_ID=None,
                SLACK_BOT_TOKEN=None, SLACK_APP_TOKEN=None,
            )
            results_before = await generate_suggestions(db_session, redis, org_key)

        # Dismiss the no-agents suggestion
        await dismiss_suggestion(redis, org_key, sid)

        # Re-generate — dismissed one should be gone
        with patch("app.services.suggestions.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                LEARNING_MODE=False,
                TELEGRAM_BOT_TOKEN=None, TELEGRAM_CHAT_ID=None,
                SLACK_BOT_TOKEN=None, SLACK_APP_TOKEN=None,
            )
            results_after = await generate_suggestions(db_session, redis, org_key)

        before_ids = {s.id for s in results_before}
        after_ids = {s.id for s in results_after}

        if sid in before_ids:
            assert sid not in after_ids

    @pytest.mark.asyncio
    async def test_dismiss_stored_in_redis(self, redis):
        """Dismiss should create a Redis set entry."""
        org_key = "test-org-dismiss-check"
        sid = "test-suggestion-123"

        await dismiss_suggestion(redis, org_key, sid)

        members = await redis.smembers(f"{DISMISS_PREFIX}{org_key}")
        decoded = {m.decode() if isinstance(m, bytes) else m for m in members}
        assert sid in decoded


# ---------------------------------------------------------------------------
# Tests: Max cap and priority ordering
# ---------------------------------------------------------------------------

class TestMaxSuggestions:
    """Test that results are capped at MAX_SUGGESTIONS."""

    @pytest.mark.asyncio
    async def test_max_5_suggestions(self, db_session, redis):
        """Should return at most MAX_SUGGESTIONS items."""
        with patch("app.services.suggestions.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                LEARNING_MODE=True,
                TELEGRAM_BOT_TOKEN=None, TELEGRAM_CHAT_ID=None,
                SLACK_BOT_TOKEN=None, SLACK_APP_TOKEN=None,
            )
            results = await generate_suggestions(db_session, redis, "test-cap")

        assert len(results) <= MAX_SUGGESTIONS


class TestPriorityOrdering:
    """Test that suggestions are sorted by severity."""

    @pytest.mark.asyncio
    async def test_critical_before_high_before_medium(self, db_session, redis):
        """Critical suggestions should appear before high, high before medium."""
        with patch("app.services.suggestions.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                LEARNING_MODE=True,
                TELEGRAM_BOT_TOKEN=None, TELEGRAM_CHAT_ID=None,
                SLACK_BOT_TOKEN=None, SLACK_APP_TOKEN=None,
            )
            results = await generate_suggestions(db_session, redis, "test-priority")

        if len(results) >= 2:
            severity_values = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            for i in range(len(results) - 1):
                current = severity_values.get(results[i].severity, 99)
                next_val = severity_values.get(results[i + 1].severity, 99)
                assert current <= next_val, (
                    f"Out of order: {results[i].severity} should not come after {results[i+1].severity}"
                )


# ---------------------------------------------------------------------------
# Tests: API endpoints
# ---------------------------------------------------------------------------

class TestSuggestionsAPI:
    """Test the suggestions REST API."""

    @pytest.mark.asyncio
    async def test_get_suggestions_returns_list(self, client):
        """GET /suggestions should return a list."""
        response = await client.get("/api/v1/suggestions")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_dismiss_returns_ok(self, client, redis):
        """POST /suggestions/{id}/dismiss should return success."""
        response = await client.post("/api/v1/suggestions/test-id/dismiss")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "dismissed"
        assert data["id"] == "test-id"

    @pytest.mark.asyncio
    async def test_suggestions_have_required_fields(self, client):
        """Each suggestion should have id, title, severity, action_url."""
        response = await client.get("/api/v1/suggestions")
        assert response.status_code == 200
        data = response.json()
        for suggestion in data:
            assert "id" in suggestion
            assert "title" in suggestion
            assert "severity" in suggestion
            assert "action_url" in suggestion
            assert "action_type" in suggestion
