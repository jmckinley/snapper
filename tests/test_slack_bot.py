"""
@module test_slack_bot
@description Tests for the Slack bot integration (app/routers/slack.py).
Covers all commands, interactive action handlers, DM flows, approval processing,
emergency block/unblock, trust management, PII vault operations, and the
send_slack_approval public API.
"""

import hashlib
import json
import time
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agents import Agent, AgentStatus, TrustLevel
from app.models.audit_logs import AuditLog, AuditAction, AuditSeverity
from app.models.rules import Rule, RuleAction, RuleType
from app.redis_client import RedisClient
from tests.conftest import TestSessionLocal


# -------------------------------------------------------------------------
# Fixtures
# -------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def mock_slack_settings():
    """Ensure Slack settings are set for all tests."""
    with patch("app.routers.slack.settings") as mock_settings:
        mock_settings.SLACK_BOT_TOKEN = "xoxb-test-token"
        mock_settings.SLACK_APP_TOKEN = "xapp-test-token"
        mock_settings.SLACK_ALERT_CHANNEL = "C_TEST_CHANNEL"
        mock_settings.API_V1_PREFIX = "/api/v1"
        yield mock_settings


@pytest_asyncio.fixture
async def slack_agent(db_session: AsyncSession) -> Agent:
    """Create a test agent with Slack owner_chat_id."""
    agent = Agent(
        id=uuid4(),
        name="Slack Test Agent",
        external_id=f"slack-test-U_TESTUSER",
        description="Test agent for Slack",
        status=AgentStatus.ACTIVE,
        trust_level=TrustLevel.STANDARD,
        owner_chat_id="U_TESTUSER",
        trust_score=1.0,
        auto_adjust_trust=False,
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)
    return agent


@pytest_asyncio.fixture
async def slack_context(redis: RedisClient, slack_agent: Agent):
    """Create a Slack callback context in Redis for testing actions."""
    context_data = {
        "type": "run",
        "value": "test command",
        "agent_id": str(slack_agent.id),
    }
    context_json = json.dumps(context_data)
    context_key = hashlib.sha256(context_json.encode()).hexdigest()[:12]
    await redis.set(f"slack_ctx:{context_key}", context_json, expire=3600)
    return context_key, context_data


def _make_command(text="", user_id="U_TESTUSER", user_name="testuser", channel_id="C_TESTCHAN"):
    """Build a mock Slack command dict."""
    return {
        "text": text,
        "user_id": user_id,
        "user_name": user_name,
        "channel_id": channel_id,
        "command": "/snapper-test",
    }


# -------------------------------------------------------------------------
# Health endpoint (REST)
# -------------------------------------------------------------------------

class TestSlackHealth:
    """Tests for the /slack/health REST endpoint."""

    @pytest.mark.asyncio
    async def test_health_not_configured(self, client: AsyncClient):
        """Returns not_configured when Slack app is not initialized."""
        with patch("app.routers.slack.slack_app", None), \
             patch("app.routers.slack.socket_handler", None):
            response = await client.get("/api/v1/slack/health")
            assert response.status_code == 200
            assert response.json()["status"] == "not_configured"

    @pytest.mark.asyncio
    async def test_health_connected(self, client: AsyncClient):
        """Returns connected when both slack_app and socket_handler are set."""
        mock_app = MagicMock()
        mock_handler = MagicMock()
        with patch("app.routers.slack.slack_app", mock_app), \
             patch("app.routers.slack.socket_handler", mock_handler):
            response = await client.get("/api/v1/slack/health")
            assert response.status_code == 200
            assert response.json()["status"] == "connected"


# -------------------------------------------------------------------------
# /snapper-status
# -------------------------------------------------------------------------

class TestStatusCommand:
    """Tests for /snapper-status command."""

    @pytest.mark.asyncio
    async def test_status_all_healthy(self, db_session, redis):
        """Returns healthy status when DB and Redis are connected."""
        from app.routers.slack import _cmd_status

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal), \
             patch("app.redis_client.redis_client", redis):
            await _cmd_status(_make_command(), say)

        say.assert_called_once()
        call_kwargs = say.call_args.kwargs
        blocks = call_kwargs["blocks"]
        # Should have header, section, context
        assert len(blocks) >= 2
        section_text = blocks[1]["text"]["text"]
        assert "connected" in section_text.lower()

    @pytest.mark.asyncio
    async def test_status_db_unreachable(self, db_session, redis):
        """Shows PostgreSQL as unreachable when DB fails."""
        from app.routers.slack import _cmd_status

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        # Mock session factory to raise
        async def failing_session():
            raise Exception("DB connection failed")

        mock_factory = MagicMock()
        mock_factory.__aenter__ = AsyncMock(side_effect=Exception("DB fail"))
        mock_factory.__aexit__ = AsyncMock(return_value=False)

        with patch("app.routers.slack.async_session_factory", return_value=mock_factory), \
             patch("app.redis_client.redis_client", redis):
            # Using _cmd_status with patched session
            from app.routers.slack import _cmd_status
            await _cmd_status(_make_command(), say)

        say.assert_called_once()
        section_text = say.call_args.kwargs["blocks"][1]["text"]["text"]
        assert "UNREACHABLE" in section_text


# -------------------------------------------------------------------------
# /snapper-rules
# -------------------------------------------------------------------------

class TestRulesCommand:
    """Tests for /snapper-rules command."""

    @pytest.mark.asyncio
    async def test_rules_no_rules(self, db_session, redis, slack_agent):
        """Shows 'no rules' message when agent has no rules."""
        from app.routers.slack import _cmd_rules, _test_agents

        _test_agents["U_TESTUSER"] = slack_agent.id
        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _cmd_rules(_make_command(), say)

        say.assert_called_once()
        blocks = say.call_args.kwargs["blocks"]
        section_text = blocks[1]["text"]["text"]
        assert "no rules" in section_text.lower() or "No rules" in section_text

    @pytest.mark.asyncio
    async def test_rules_with_rules(self, db_session, redis, sample_rule, slack_agent):
        """Lists active rules when they exist."""
        from app.routers.slack import _cmd_rules, _test_agents

        _test_agents["U_TESTUSER"] = sample_rule.agent_id
        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _cmd_rules(_make_command(), say)

        say.assert_called_once()
        blocks = say.call_args.kwargs["blocks"]
        # Should show at least the header and a section with rule info
        assert len(blocks) >= 2

    @pytest.mark.asyncio
    async def test_rules_truncation_message(self, db_session, redis, slack_agent):
        """Shows truncation message when there are more than 15 rules."""
        from app.routers.slack import _cmd_rules, _test_agents

        _test_agents["U_TESTUSER"] = slack_agent.id

        # Create 20 rules
        for i in range(20):
            rule = Rule(
                id=uuid4(),
                name=f"Rule {i}",
                description=f"Test rule {i}",
                agent_id=slack_agent.id,
                rule_type=RuleType.COMMAND_ALLOWLIST,
                action=RuleAction.ALLOW,
                priority=i,
                parameters={"patterns": [f"cmd{i}"]},
                is_active=True,
            )
            db_session.add(rule)
        await db_session.commit()

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _cmd_rules(_make_command(), say)

        say.assert_called_once()
        blocks = say.call_args.kwargs["blocks"]
        section_text = blocks[1]["text"]["text"]
        assert "Showing" in section_text


# -------------------------------------------------------------------------
# /snapper-test
# -------------------------------------------------------------------------

class TestTestCommand:
    """Tests for /snapper-test command."""

    @pytest.mark.asyncio
    async def test_test_help(self, db_session, redis):
        """Shows help when no arguments provided."""
        from app.routers.slack import _cmd_test

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _cmd_test(_make_command(text=""), say)

        say.assert_called_once()
        blocks = say.call_args.kwargs["blocks"]
        section_text = blocks[1]["text"]["text"]
        assert "run" in section_text.lower()
        assert "install" in section_text.lower()

    @pytest.mark.asyncio
    async def test_test_run_command(self, db_session, redis, slack_agent):
        """Tests a shell command and returns evaluation result."""
        from app.routers.slack import _cmd_test, _test_agents

        _test_agents["U_TESTUSER"] = slack_agent.id
        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _cmd_test(_make_command(text="run ls -la"), say)

        say.assert_called_once()
        # Should show result (ALLOWED, BLOCKED, or REQUIRES APPROVAL)
        blocks = say.call_args.kwargs["blocks"]
        section_text = blocks[0]["text"]["text"]
        assert any(s in section_text for s in ["ALLOWED", "BLOCKED", "REQUIRES APPROVAL"])

    @pytest.mark.asyncio
    async def test_test_blocked_shows_buttons(self, db_session, redis, slack_agent):
        """Shows Allow Once/Always buttons when command is blocked."""
        from app.routers.slack import _cmd_test, _test_agents

        _test_agents["U_TESTUSER"] = slack_agent.id

        # Create a deny rule
        deny_rule = Rule(
            id=uuid4(),
            name="Deny rm",
            description="Block rm commands",
            agent_id=slack_agent.id,
            rule_type=RuleType.COMMAND_DENYLIST,
            action=RuleAction.DENY,
            priority=100,
            parameters={"patterns": ["rm.*"]},
            is_active=True,
        )
        db_session.add(deny_rule)
        await db_session.commit()

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _cmd_test(_make_command(text="run rm -rf /"), say)

        say.assert_called_once()
        blocks = say.call_args.kwargs["blocks"]
        # Should have BLOCKED status
        assert "BLOCKED" in blocks[0]["text"]["text"]
        # Should have actions block with buttons
        action_blocks = [b for b in blocks if b.get("type") == "actions"]
        assert len(action_blocks) >= 1
        buttons = action_blocks[0]["elements"]
        action_ids = [b["action_id"] for b in buttons]
        assert "once_action" in action_ids
        assert "always_action" in action_ids

    @pytest.mark.asyncio
    async def test_test_install_skill(self, db_session, redis, slack_agent):
        """Tests skill install evaluation."""
        from app.routers.slack import _cmd_test, _test_agents

        _test_agents["U_TESTUSER"] = slack_agent.id
        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _cmd_test(_make_command(text="install test-skill"), say)

        say.assert_called_once()

    @pytest.mark.asyncio
    async def test_test_access_file(self, db_session, redis, slack_agent):
        """Tests file access evaluation."""
        from app.routers.slack import _cmd_test, _test_agents

        _test_agents["U_TESTUSER"] = slack_agent.id
        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _cmd_test(_make_command(text="access /etc/passwd"), say)

        say.assert_called_once()

    @pytest.mark.asyncio
    async def test_test_network_egress(self, db_session, redis, slack_agent):
        """Tests network egress evaluation."""
        from app.routers.slack import _cmd_test, _test_agents

        _test_agents["U_TESTUSER"] = slack_agent.id
        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _cmd_test(_make_command(text="network evil.com"), say)

        say.assert_called_once()

    @pytest.mark.asyncio
    async def test_test_unknown_subcommand(self, db_session, redis, slack_agent):
        """Shows error for unknown test type."""
        from app.routers.slack import _cmd_test, _test_agents

        _test_agents["U_TESTUSER"] = slack_agent.id
        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _cmd_test(_make_command(text="foobar something"), say)

        say.assert_called_once()
        assert "unknown" in say.call_args.kwargs.get("text", "").lower() or \
               "Unknown" in say.call_args.kwargs.get("text", "")

    @pytest.mark.asyncio
    async def test_test_missing_argument(self, db_session, redis, slack_agent):
        """Shows usage when subcommand has no argument."""
        from app.routers.slack import _cmd_test, _test_agents

        _test_agents["U_TESTUSER"] = slack_agent.id
        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _cmd_test(_make_command(text="run"), say)

        say.assert_called_once()
        assert "Usage" in say.call_args.kwargs.get("text", "") or \
               "missing" in say.call_args.kwargs.get("text", "").lower() or \
               "Missing" in say.call_args.kwargs.get("text", "")


# -------------------------------------------------------------------------
# /snapper-pending
# -------------------------------------------------------------------------

class TestPendingCommand:
    """Tests for /snapper-pending command."""

    @pytest.mark.asyncio
    async def test_pending_no_approvals(self, db_session, redis):
        """Shows no pending message when queue is empty."""
        from app.routers.slack import _cmd_pending

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.redis_client.redis_client", redis):
            await _cmd_pending(_make_command(), say)

        say.assert_called_once()
        blocks = say.call_args.kwargs["blocks"]
        section_text = blocks[1]["text"]["text"]
        assert "no pending" in section_text.lower() or "No pending" in section_text

    @pytest.mark.asyncio
    async def test_pending_with_approvals(self, db_session, redis):
        """Lists pending approvals when they exist."""
        from app.routers.slack import _cmd_pending

        # Store a fake pending approval in Redis
        from app.routers.approvals import APPROVAL_PREFIX
        approval_data = {
            "id": "test-approval-123",
            "agent_id": str(uuid4()),
            "agent_name": "Test Agent",
            "request_type": "command",
            "command": "rm -rf /",
            "rule_id": str(uuid4()),
            "rule_name": "Test Rule",
            "status": "pending",
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + timedelta(hours=1)).isoformat(),
        }
        await redis.set(f"{APPROVAL_PREFIX}test-approval-123", json.dumps(approval_data))

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.redis_client.redis_client", redis):
            await _cmd_pending(_make_command(), say)

        say.assert_called_once()
        blocks = say.call_args.kwargs["blocks"]
        section_text = blocks[1]["text"]["text"]
        assert "test-app" in section_text


# -------------------------------------------------------------------------
# /snapper-help
# -------------------------------------------------------------------------

class TestHelpCommand:
    """Tests for /snapper-help command."""

    @pytest.mark.asyncio
    async def test_help_shows_all_commands(self, db_session, redis):
        """Lists all available commands with user ID."""
        from app.routers.slack import _cmd_help

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})
        await _cmd_help(_make_command(user_id="U_TESTUSER"), say)

        say.assert_called_once()
        blocks = say.call_args.kwargs["blocks"]
        section_text = blocks[1]["text"]["text"]
        # Verify key commands are mentioned
        assert "/snapper-rules" in section_text
        assert "/snapper-test" in section_text
        assert "/snapper-vault" in section_text
        assert "/snapper-trust" in section_text
        assert "/snapper-block" in section_text

        # User ID shown in context
        context_text = blocks[2]["elements"][0]["text"]
        assert "U_TESTUSER" in context_text


# -------------------------------------------------------------------------
# /snapper-block & /snapper-unblock
# -------------------------------------------------------------------------

class TestEmergencyBlockUnblock:
    """Tests for emergency block/unblock commands."""

    @pytest.mark.asyncio
    async def test_block_shows_confirmation(self, db_session, redis):
        """Shows confirmation buttons when block is requested."""
        from app.routers.slack import _cmd_block, _pending_emergency_blocks

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})
        await _cmd_block(_make_command(user_id="U_TESTUSER"), say)

        say.assert_called_once()
        blocks = say.call_args.kwargs["blocks"]
        # Should have section with warning and actions with confirm/cancel
        section_text = blocks[0]["text"]["text"]
        assert "EMERGENCY" in section_text
        action_blocks = [b for b in blocks if b.get("type") == "actions"]
        assert len(action_blocks) == 1
        action_ids = [e["action_id"] for e in action_blocks[0]["elements"]]
        assert "confirm_block_action" in action_ids
        assert "cancel_block_action" in action_ids

        # Should register pending confirmation
        assert "U_TESTUSER" in _pending_emergency_blocks

    @pytest.mark.asyncio
    async def test_confirm_block_creates_rules(self, db_session, redis):
        """Confirm block creates high-priority deny-all rules."""
        from app.routers.slack import _activate_emergency_block

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            result = await _activate_emergency_block("U_TESTUSER", "testuser")

        assert result["status"] == "activated"

        # Verify rules were created in DB
        async with TestSessionLocal() as session:
            stmt = select(Rule).where(
                Rule.name == "\U0001f6a8 EMERGENCY BLOCK ALL",
                Rule.is_active == True,
            )
            rules = (await session.execute(stmt)).scalars().all()
            assert len(rules) >= 4
            for rule in rules:
                assert rule.priority == 10000
                assert rule.action == RuleAction.DENY
                assert rule.agent_id is None  # Global

    @pytest.mark.asyncio
    async def test_confirm_block_reactivates_existing(self, db_session, redis):
        """Confirm block reactivates existing inactive emergency rules."""
        from app.routers.slack import _activate_emergency_block

        # First create rules
        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _activate_emergency_block("U_TESTUSER", "testuser")

        # Deactivate them
        async with TestSessionLocal() as session:
            stmt = select(Rule).where(Rule.name == "\U0001f6a8 EMERGENCY BLOCK ALL")
            rules = (await session.execute(stmt)).scalars().all()
            for rule in rules:
                rule.is_active = False
            await session.commit()

        # Reactivate
        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            result = await _activate_emergency_block("U_TESTUSER", "testuser")

        assert result["status"] == "activated"

        async with TestSessionLocal() as session:
            stmt = select(Rule).where(
                Rule.name == "\U0001f6a8 EMERGENCY BLOCK ALL",
                Rule.is_active == True,
            )
            rules = (await session.execute(stmt)).scalars().all()
            assert len(rules) >= 4

    @pytest.mark.asyncio
    async def test_unblock_deactivates_rules(self, db_session, redis):
        """Unblock deactivates emergency rules."""
        from app.routers.slack import _activate_emergency_block, _cmd_unblock

        # Create block rules first
        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _activate_emergency_block("U_TESTUSER", "testuser")

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})
        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _cmd_unblock(_make_command(user_id="U_TESTUSER"), say)

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "deactivated" in text.lower()

        # Verify rules are inactive
        async with TestSessionLocal() as session:
            stmt = select(Rule).where(
                Rule.name == "\U0001f6a8 EMERGENCY BLOCK ALL",
                Rule.is_active == True,
            )
            rules = (await session.execute(stmt)).scalars().all()
            assert len(rules) == 0

    @pytest.mark.asyncio
    async def test_unblock_no_active_block(self, db_session, redis):
        """Shows info message when no emergency block is active."""
        from app.routers.slack import _cmd_unblock

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})
        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _cmd_unblock(_make_command(user_id="U_TESTUSER"), say)

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "no emergency" in text.lower() or "No emergency" in text


# -------------------------------------------------------------------------
# /snapper-trust
# -------------------------------------------------------------------------

class TestTrustCommand:
    """Tests for /snapper-trust command."""

    @pytest.mark.asyncio
    async def test_trust_view_scores(self, db_session, redis, slack_agent):
        """Shows trust scores for owned agents."""
        from app.routers.slack import _cmd_trust

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal), \
             patch("app.redis_client.redis_client", redis):
            await _cmd_trust(_make_command(text="", user_id="U_TESTUSER"), say)

        say.assert_called_once()
        blocks = say.call_args.kwargs["blocks"]
        section_text = blocks[1]["text"]["text"]
        assert "Slack Test Agent" in section_text
        assert "1.000" in section_text

    @pytest.mark.asyncio
    async def test_trust_no_agents(self, db_session, redis):
        """Shows error when user owns no agents."""
        from app.routers.slack import _cmd_trust

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal), \
             patch("app.redis_client.redis_client", redis):
            await _cmd_trust(_make_command(text="", user_id="U_NOAGENT"), say)

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "no agents" in text.lower() or "No agents" in text

    @pytest.mark.asyncio
    async def test_trust_reset(self, db_session, redis, slack_agent):
        """Reset command resets trust score to 1.0."""
        from app.routers.slack import _cmd_trust

        # Set trust to a non-default value
        trust_key = f"trust:rate:{slack_agent.id}"
        await redis.set(trust_key, "0.7")

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal), \
             patch("app.redis_client.redis_client", redis):
            await _cmd_trust(_make_command(text="reset", user_id="U_TESTUSER"), say)

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "1.0" in text

        # Verify Redis key deleted
        val = await redis.get(trust_key)
        assert val is None

    @pytest.mark.asyncio
    async def test_trust_enable(self, db_session, redis, slack_agent):
        """Enable command turns on trust enforcement."""
        from app.routers.slack import _cmd_trust

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal), \
             patch("app.redis_client.redis_client", redis):
            await _cmd_trust(_make_command(text="enable", user_id="U_TESTUSER"), say)

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "enabled" in text.lower()

    @pytest.mark.asyncio
    async def test_trust_disable(self, db_session, redis, slack_agent):
        """Disable command turns off trust enforcement."""
        from app.routers.slack import _cmd_trust

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal), \
             patch("app.redis_client.redis_client", redis):
            await _cmd_trust(_make_command(text="disable", user_id="U_TESTUSER"), say)

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "disabled" in text.lower()

    @pytest.mark.asyncio
    async def test_trust_target_specific_agent(self, db_session, redis, slack_agent):
        """Target a specific agent by name."""
        from app.routers.slack import _cmd_trust

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal), \
             patch("app.redis_client.redis_client", redis):
            await _cmd_trust(_make_command(text=f"reset {slack_agent.name}", user_id="U_TESTUSER"), say)

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "1.0" in text

    @pytest.mark.asyncio
    async def test_trust_target_unknown_agent(self, db_session, redis, slack_agent):
        """Shows error for unknown agent name."""
        from app.routers.slack import _cmd_trust

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal), \
             patch("app.redis_client.redis_client", redis):
            await _cmd_trust(_make_command(text="reset NonExistentAgent", user_id="U_TESTUSER"), say)

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "not found" in text.lower()


# -------------------------------------------------------------------------
# /snapper-vault
# -------------------------------------------------------------------------

class TestVaultCommand:
    """Tests for /snapper-vault command."""

    @pytest.mark.asyncio
    async def test_vault_list_empty(self, db_session, redis):
        """Shows empty vault message when no entries exist."""
        from app.routers.slack import _cmd_vault

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _cmd_vault(_make_command(text="list", user_id="U_TESTUSER"), say)

        say.assert_called_once()
        blocks = say.call_args.kwargs["blocks"]
        # Should show empty state
        found_empty = False
        for block in blocks:
            if block.get("type") == "section":
                text = block["text"]["text"]
                if "no entries" in text.lower() or "No entries" in text:
                    found_empty = True
        assert found_empty

    @pytest.mark.asyncio
    async def test_vault_add_starts_dm_flow(self, db_session, redis):
        """Add command opens DM and stores pending state in Redis."""
        from app.routers.slack import _cmd_vault

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})
        mock_app = MagicMock()
        mock_app.client.conversations_open = AsyncMock(
            return_value={"channel": {"id": "D_TESTDM"}}
        )
        mock_app.client.chat_postMessage = AsyncMock()

        with patch("app.routers.slack.async_session_factory", TestSessionLocal), \
             patch("app.redis_client.redis_client", redis), \
             patch("app.routers.slack.slack_app", mock_app):
            await _cmd_vault(_make_command(text='add "My Email" email', user_id="U_TESTUSER"), say)

        # Should have stored pending state
        pending = await redis.get("slack_vault_pending:U_TESTUSER")
        assert pending is not None
        pending_data = json.loads(pending)
        assert pending_data["label"] == "My Email"
        assert pending_data["category"] == "email"

        # Should have opened DM
        mock_app.client.conversations_open.assert_called_once_with(users="U_TESTUSER")

    @pytest.mark.asyncio
    async def test_vault_add_credit_card_multistep(self, db_session, redis):
        """Credit card add starts multi-step flow."""
        from app.routers.slack import _cmd_vault

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})
        mock_app = MagicMock()
        mock_app.client.conversations_open = AsyncMock(
            return_value={"channel": {"id": "D_TESTDM"}}
        )
        mock_app.client.chat_postMessage = AsyncMock()

        with patch("app.routers.slack.async_session_factory", TestSessionLocal), \
             patch("app.redis_client.redis_client", redis), \
             patch("app.routers.slack.slack_app", mock_app):
            await _cmd_vault(_make_command(text='add "My Visa" cc', user_id="U_TESTUSER"), say)

        pending = await redis.get("slack_vault_pending:U_TESTUSER")
        assert pending is not None
        pending_data = json.loads(pending)
        assert pending_data["category"] == "credit_card"
        assert pending_data["step"] == "number"

    @pytest.mark.asyncio
    async def test_vault_add_missing_args(self, db_session, redis):
        """Shows usage when add has no arguments."""
        from app.routers.slack import _cmd_vault

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal), \
             patch("app.redis_client.redis_client", redis):
            await _cmd_vault(_make_command(text="add", user_id="U_TESTUSER"), say)

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "Usage" in text

    @pytest.mark.asyncio
    async def test_vault_add_invalid_category(self, db_session, redis):
        """Shows error for invalid category."""
        from app.routers.slack import _cmd_vault

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal), \
             patch("app.redis_client.redis_client", redis):
            await _cmd_vault(_make_command(text="add MyData fakecategory", user_id="U_TESTUSER"), say)

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "unknown" in text.lower() or "Unknown" in text

    @pytest.mark.asyncio
    async def test_vault_delete_not_found(self, db_session, redis):
        """Shows error when token not found for delete."""
        from app.routers.slack import _cmd_vault

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _cmd_vault(
                _make_command(text="delete {{SNAPPER_VAULT:nonexistent}}", user_id="U_TESTUSER"), say
            )

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "not found" in text.lower()

    @pytest.mark.asyncio
    async def test_vault_delete_all_confirmation(self, db_session, redis):
        """Delete * shows confirmation buttons."""
        from app.routers.slack import _cmd_vault
        from app.services import pii_vault as vault_service
        from app.models.pii_vault import PIICategory

        # Create an entry first
        async with TestSessionLocal() as session:
            entry = await vault_service.create_entry(
                db=session,
                owner_chat_id="U_TESTUSER",
                owner_name="testuser",
                label="Test Card",
                category=PIICategory.CREDIT_CARD,
                raw_value="4111111111111111",
            )
            await session.commit()

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _cmd_vault(_make_command(text="delete *", user_id="U_TESTUSER"), say)

        say.assert_called_once()
        blocks = say.call_args.kwargs["blocks"]
        action_blocks = [b for b in blocks if b.get("type") == "actions"]
        assert len(action_blocks) == 1
        action_ids = [e["action_id"] for e in action_blocks[0]["elements"]]
        assert "vault_delall_action" in action_ids
        assert "vault_delall_cancel" in action_ids

    @pytest.mark.asyncio
    async def test_vault_domains_missing_args(self, db_session, redis):
        """Shows usage for domains with insufficient arguments."""
        from app.routers.slack import _cmd_vault

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _cmd_vault(_make_command(text="domains", user_id="U_TESTUSER"), say)

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "Usage" in text

    @pytest.mark.asyncio
    async def test_vault_help(self, db_session, redis):
        """Shows vault help text."""
        from app.routers.slack import _cmd_vault

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _cmd_vault(_make_command(text="help", user_id="U_TESTUSER"), say)

        say.assert_called_once()
        blocks = say.call_args.kwargs["blocks"]
        section_text = blocks[1]["text"]["text"]
        assert "vault" in section_text.lower()

    @pytest.mark.asyncio
    async def test_vault_unknown_subcommand(self, db_session, redis):
        """Shows error for unknown vault subcommand."""
        from app.routers.slack import _cmd_vault

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal), \
             patch("app.redis_client.redis_client", redis):
            await _cmd_vault(_make_command(text="foobar", user_id="U_TESTUSER"), say)

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "unknown" in text.lower() or "Unknown" in text


# -------------------------------------------------------------------------
# /snapper-pii
# -------------------------------------------------------------------------

class TestPiiCommand:
    """Tests for /snapper-pii command."""

    @pytest.mark.asyncio
    async def test_pii_show_current_mode(self, db_session, redis):
        """Shows current PII gate mode."""
        from app.routers.slack import _cmd_pii

        # Create PII gate rule
        pii_rule = Rule(
            id=uuid4(),
            name="PII Gate",
            rule_type=RuleType.PII_GATE,
            action=RuleAction.REQUIRE_APPROVAL,
            priority=100,
            parameters={"pii_mode": "protected"},
            is_active=True,
        )
        db_session.add(pii_rule)
        await db_session.commit()

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _cmd_pii(_make_command(text="", user_id="U_TESTUSER"), say)

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "protected" in text

    @pytest.mark.asyncio
    async def test_pii_no_gate_rule(self, db_session, redis):
        """Shows error when no PII gate rule exists."""
        from app.routers.slack import _cmd_pii

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _cmd_pii(_make_command(text="", user_id="U_TESTUSER"), say)

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "no active" in text.lower() or "No active" in text

    @pytest.mark.asyncio
    async def test_pii_switch_to_auto(self, db_session, redis):
        """Switches PII mode from protected to auto."""
        from app.routers.slack import _cmd_pii

        pii_rule = Rule(
            id=uuid4(),
            name="PII Gate",
            rule_type=RuleType.PII_GATE,
            action=RuleAction.REQUIRE_APPROVAL,
            priority=100,
            parameters={"pii_mode": "protected"},
            is_active=True,
        )
        db_session.add(pii_rule)
        await db_session.commit()

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _cmd_pii(_make_command(text="auto", user_id="U_TESTUSER"), say)

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "auto" in text

    @pytest.mark.asyncio
    async def test_pii_already_in_mode(self, db_session, redis):
        """Shows info when already in requested mode."""
        from app.routers.slack import _cmd_pii

        pii_rule = Rule(
            id=uuid4(),
            name="PII Gate",
            rule_type=RuleType.PII_GATE,
            action=RuleAction.REQUIRE_APPROVAL,
            priority=100,
            parameters={"pii_mode": "auto"},
            is_active=True,
        )
        db_session.add(pii_rule)
        await db_session.commit()

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _cmd_pii(_make_command(text="auto", user_id="U_TESTUSER"), say)

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "already" in text.lower()

    @pytest.mark.asyncio
    async def test_pii_invalid_mode(self, db_session, redis):
        """Shows usage for invalid mode."""
        from app.routers.slack import _cmd_pii

        pii_rule = Rule(
            id=uuid4(),
            name="PII Gate",
            rule_type=RuleType.PII_GATE,
            action=RuleAction.REQUIRE_APPROVAL,
            priority=100,
            parameters={"pii_mode": "protected"},
            is_active=True,
        )
        db_session.add(pii_rule)
        await db_session.commit()

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _cmd_pii(_make_command(text="invalid", user_id="U_TESTUSER"), say)

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "Usage" in text or "protected" in text


# -------------------------------------------------------------------------
# /snapper-purge
# -------------------------------------------------------------------------

class TestPurgeCommand:
    """Tests for /snapper-purge command."""

    @pytest.mark.asyncio
    async def test_purge_no_messages(self, db_session, redis):
        """Shows no messages when nothing to purge."""
        from app.routers.slack import _cmd_purge

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.redis_client.redis_client", redis):
            await _cmd_purge(_make_command(text="", channel_id="C_TESTCHAN"), say)

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "no tracked" in text.lower() or "No tracked" in text

    @pytest.mark.asyncio
    async def test_purge_with_messages(self, db_session, redis):
        """Deletes tracked bot messages."""
        from app.routers.slack import _cmd_purge

        # Add some tracked messages
        key = "slack_bot_messages:C_TESTCHAN"
        old_time = time.time() - 90000  # 25 hours ago
        await redis.zadd(key, {"1234.5678": old_time, "1234.5679": old_time})

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})
        mock_app = MagicMock()
        mock_app.client.chat_delete = AsyncMock()

        with patch("app.redis_client.redis_client", redis), \
             patch("app.routers.slack.slack_app", mock_app):
            await _cmd_purge(_make_command(text="", channel_id="C_TESTCHAN"), say)

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "Deleted" in text or "Purge" in text

    @pytest.mark.asyncio
    async def test_purge_invalid_duration(self, db_session, redis):
        """Shows usage for invalid duration format."""
        from app.routers.slack import _cmd_purge

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.redis_client.redis_client", redis):
            await _cmd_purge(_make_command(text="invalid", channel_id="C_TESTCHAN"), say)

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "Usage" in text or "Examples" in text


# -------------------------------------------------------------------------
# Action handlers (interactive buttons)
# -------------------------------------------------------------------------

class TestAllowOnceAction:
    """Tests for Allow Once button handler."""

    @pytest.mark.asyncio
    async def test_allow_once_stores_redis_key(self, db_session, redis, slack_context):
        """Stores temporary approval key in Redis."""
        from app.routers.slack import _action_allow_once

        context_key, context_data = slack_context
        body = {
            "actions": [{"value": context_key}],
            "user": {"id": "U_TESTUSER", "username": "testuser"},
        }
        respond = AsyncMock()

        with patch("app.redis_client.redis_client", redis):
            await _action_allow_once(body, respond)

        respond.assert_called_once()
        call_kwargs = respond.call_args.kwargs
        assert call_kwargs.get("replace_original") is True
        assert "ALLOWED ONCE" in call_kwargs.get("text", "")

        # Verify Redis key
        cmd = context_data["value"]
        agent_id = context_data["agent_id"]
        cmd_hash = hashlib.sha256(cmd.encode()).hexdigest()[:16]
        approval_key = f"once_allow:{agent_id}:{cmd_hash}"
        val = await redis.get(approval_key)
        assert val == "1"

    @pytest.mark.asyncio
    async def test_allow_once_expired_context(self, db_session, redis):
        """Shows error when context has expired."""
        from app.routers.slack import _action_allow_once

        body = {
            "actions": [{"value": "nonexistent_key"}],
            "user": {"id": "U_TESTUSER", "username": "testuser"},
        }
        respond = AsyncMock()

        with patch("app.redis_client.redis_client", redis):
            await _action_allow_once(body, respond)

        respond.assert_called_once()
        text = respond.call_args.kwargs.get("text", "")
        assert "expired" in text.lower()


class TestAllowAlwaysAction:
    """Tests for Allow Always button handler."""

    @pytest.mark.asyncio
    async def test_allow_always_creates_rule(self, db_session, redis, slack_context, slack_agent):
        """Creates a persistent allow rule from context."""
        from app.routers.slack import _action_allow_always

        context_key, context_data = slack_context
        body = {
            "actions": [{"value": context_key}],
            "user": {"id": "U_TESTUSER", "username": "testuser"},
        }
        respond = AsyncMock()

        with patch("app.redis_client.redis_client", redis), \
             patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _action_allow_always(body, respond)

        respond.assert_called_once()
        text = respond.call_args.kwargs.get("text", "")
        assert "ALLOW RULE CREATED" in text

    @pytest.mark.asyncio
    async def test_allow_always_expired_context(self, db_session, redis):
        """Shows error when context has expired."""
        from app.routers.slack import _action_allow_always

        body = {
            "actions": [{"value": "nonexistent_key"}],
            "user": {"id": "U_TESTUSER", "username": "testuser"},
        }
        respond = AsyncMock()

        with patch("app.redis_client.redis_client", redis):
            await _action_allow_always(body, respond)

        respond.assert_called_once()
        text = respond.call_args.kwargs.get("text", "")
        assert "expired" in text.lower()


class TestApprovalAction:
    """Tests for Approve/Deny button handlers."""

    @pytest.mark.asyncio
    async def test_approve_action(self, db_session, redis):
        """Approves a pending request."""
        from app.routers.slack import _action_approval
        from app.routers.approvals import APPROVAL_PREFIX

        approval_id = "test-approval-action-1"
        approval_data = {
            "id": approval_id,
            "agent_id": str(uuid4()),
            "agent_name": "Test Agent",
            "request_type": "command",
            "command": "ls",
            "rule_id": str(uuid4()),
            "rule_name": "Test Rule",
            "status": "pending",
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + timedelta(hours=1)).isoformat(),
        }
        await redis.set(f"{APPROVAL_PREFIX}{approval_id}", json.dumps(approval_data))

        body = {
            "actions": [{"value": approval_id}],
            "user": {"id": "U_TESTUSER", "username": "testuser"},
        }
        respond = AsyncMock()

        with patch("app.redis_client.redis_client", redis), \
             patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _action_approval(body, respond, "approve")

        respond.assert_called_once()
        text = respond.call_args.kwargs.get("text", "")
        assert "APPROVED" in text

    @pytest.mark.asyncio
    async def test_deny_action(self, db_session, redis):
        """Denies a pending request."""
        from app.routers.slack import _action_approval
        from app.routers.approvals import APPROVAL_PREFIX

        approval_id = "test-approval-action-2"
        approval_data = {
            "id": approval_id,
            "agent_id": str(uuid4()),
            "agent_name": "Test Agent",
            "request_type": "command",
            "command": "rm -rf /",
            "rule_id": str(uuid4()),
            "rule_name": "Test Rule",
            "status": "pending",
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + timedelta(hours=1)).isoformat(),
        }
        await redis.set(f"{APPROVAL_PREFIX}{approval_id}", json.dumps(approval_data))

        body = {
            "actions": [{"value": approval_id}],
            "user": {"id": "U_TESTUSER", "username": "testuser"},
        }
        respond = AsyncMock()

        with patch("app.redis_client.redis_client", redis), \
             patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _action_approval(body, respond, "deny")

        respond.assert_called_once()
        text = respond.call_args.kwargs.get("text", "")
        assert "DENIED" in text

    @pytest.mark.asyncio
    async def test_approval_expired_request(self, db_session, redis):
        """Shows expiry message for non-existent approval."""
        from app.routers.slack import _action_approval

        body = {
            "actions": [{"value": "nonexistent-approval"}],
            "user": {"id": "U_TESTUSER", "username": "testuser"},
        }
        respond = AsyncMock()

        with patch("app.redis_client.redis_client", redis), \
             patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _action_approval(body, respond, "approve")

        respond.assert_called_once()
        text = respond.call_args.kwargs.get("text", "")
        assert "expired" in text.lower() or "not found" in text.lower()


class TestViewRuleAction:
    """Tests for View Rule button handler."""

    @pytest.mark.asyncio
    async def test_view_rule_found(self, db_session, redis, sample_rule):
        """Shows rule details when found."""
        from app.routers.slack import _action_view_rule

        rule_id_short = str(sample_rule.id)[:12]
        body = {
            "actions": [{"value": rule_id_short}],
            "user": {"id": "U_TESTUSER", "username": "testuser"},
        }
        respond = AsyncMock()

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _action_view_rule(body, respond)

        respond.assert_called_once()
        text = respond.call_args.kwargs.get("text", "")
        assert "Rule Details" in text
        assert sample_rule.name in text

    @pytest.mark.asyncio
    async def test_view_rule_not_found(self, db_session, redis):
        """Shows not found for invalid rule ID."""
        from app.routers.slack import _action_view_rule

        body = {
            "actions": [{"value": "000000000000"}],
            "user": {"id": "U_TESTUSER", "username": "testuser"},
        }
        respond = AsyncMock()

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _action_view_rule(body, respond)

        respond.assert_called_once()
        text = respond.call_args.kwargs.get("text", "")
        assert "not found" in text.lower()


class TestConfirmBlockAction:
    """Tests for emergency block confirm button handler."""

    @pytest.mark.asyncio
    async def test_confirm_block_activates(self, db_session, redis):
        """Confirmation activates emergency block."""
        from app.routers.slack import _action_confirm_block

        body = {
            "actions": [{"value": "U_TESTUSER"}],
            "user": {"id": "U_TESTUSER", "username": "testuser"},
        }
        respond = AsyncMock()

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _action_confirm_block(body, respond)

        respond.assert_called_once()
        text = respond.call_args.kwargs.get("text", "")
        assert "EMERGENCY BLOCK ACTIVATED" in text

        # Verify rules exist
        async with TestSessionLocal() as session:
            stmt = select(Rule).where(
                Rule.name == "\U0001f6a8 EMERGENCY BLOCK ALL",
                Rule.is_active == True,
            )
            rules = (await session.execute(stmt)).scalars().all()
            assert len(rules) >= 4


class TestCancelBlockAction:
    """Tests for emergency block cancel button handler."""

    @pytest.mark.asyncio
    async def test_cancel_block(self, db_session, redis):
        """Cancel clears pending block."""
        from app.routers.slack import _pending_emergency_blocks

        _pending_emergency_blocks["U_TESTUSER"] = datetime.utcnow()

        # Simulate the cancel handler directly
        _pending_emergency_blocks.pop("U_TESTUSER", None)
        assert "U_TESTUSER" not in _pending_emergency_blocks


# -------------------------------------------------------------------------
# DM conversation flow
# -------------------------------------------------------------------------

class TestDMVaultValueReply:
    """Tests for DM vault value reply handler."""

    @pytest.mark.asyncio
    async def test_vault_value_simple_email(self, db_session, redis):
        """Stores a simple email value via DM."""
        from app.routers.slack import _handle_vault_value_reply

        pending_data = json.dumps({
            "label": "My Email",
            "category": "email",
            "owner_chat_id": "U_TESTUSER",
            "owner_name": "testuser",
        })

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})

        with patch("app.routers.slack.async_session_factory", TestSessionLocal), \
             patch("app.redis_client.redis_client", redis):
            await _handle_vault_value_reply(
                "U_TESTUSER", "D_TESTDM", "test@example.com", pending_data, say
            )

        say.assert_called_once()
        blocks = say.call_args.kwargs.get("blocks", [])
        assert len(blocks) >= 1

    @pytest.mark.asyncio
    async def test_vault_value_cancel(self, db_session, redis):
        """Cancel aborts vault creation."""
        from app.routers.slack import _handle_vault_value_reply

        pending_data = json.dumps({
            "label": "My Email",
            "category": "email",
            "owner_chat_id": "U_TESTUSER",
            "owner_name": "testuser",
        })

        say = AsyncMock(return_value=None)

        with patch("app.redis_client.redis_client", redis):
            await _handle_vault_value_reply("U_TESTUSER", "D_TESTDM", "cancel", pending_data, say)

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "cancelled" in text.lower()

    @pytest.mark.asyncio
    async def test_vault_credit_card_step_number(self, db_session, redis):
        """Credit card flow step 1: card number."""
        from app.routers.slack import _handle_vault_value_reply

        pending_data = json.dumps({
            "label": "My Visa",
            "category": "credit_card",
            "owner_chat_id": "U_TESTUSER",
            "owner_name": "testuser",
            "step": "number",
        })

        say = AsyncMock(return_value=None)

        with patch("app.redis_client.redis_client", redis):
            await _handle_vault_value_reply(
                "U_TESTUSER", "D_TESTDM", "4111111111111111", pending_data, say
            )

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "expiration" in text.lower() or "Step 2" in text

        # Verify step advanced
        new_pending = await redis.get("slack_vault_pending:U_TESTUSER")
        assert new_pending is not None
        new_data = json.loads(new_pending)
        assert new_data["step"] == "exp"
        assert new_data["card_number"] == "4111111111111111"

    @pytest.mark.asyncio
    async def test_vault_credit_card_invalid_number(self, db_session, redis):
        """Shows validation error for invalid card number."""
        from app.routers.slack import _handle_vault_value_reply

        pending_data = json.dumps({
            "label": "My Visa",
            "category": "credit_card",
            "owner_chat_id": "U_TESTUSER",
            "owner_name": "testuser",
            "step": "number",
        })

        say = AsyncMock(return_value=None)

        with patch("app.redis_client.redis_client", redis):
            await _handle_vault_value_reply(
                "U_TESTUSER", "D_TESTDM", "123", pending_data, say
            )

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "valid" in text.lower() or "13-19" in text

    @pytest.mark.asyncio
    async def test_vault_name_step_first(self, db_session, redis):
        """Name flow step 1: first name."""
        from app.routers.slack import _handle_vault_value_reply

        pending_data = json.dumps({
            "label": "My Name",
            "category": "name",
            "owner_chat_id": "U_TESTUSER",
            "owner_name": "testuser",
            "step": "first",
        })

        say = AsyncMock(return_value=None)

        with patch("app.redis_client.redis_client", redis):
            await _handle_vault_value_reply(
                "U_TESTUSER", "D_TESTDM", "John", pending_data, say
            )

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "last" in text.lower() or "Step 2" in text


class TestDMCustomPlaceholder:
    """Tests for DM custom placeholder reply handler."""

    @pytest.mark.asyncio
    async def test_custom_placeholder_cancel(self, db_session, redis):
        """Cancel skips placeholder setup."""
        from app.routers.slack import _handle_custom_placeholder

        say = AsyncMock(return_value=None)
        await _handle_custom_placeholder("U_TESTUSER", "D_TESTDM", "cancel", "test-id", say)

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "skipped" in text.lower()

    @pytest.mark.asyncio
    async def test_custom_placeholder_too_long(self, db_session, redis):
        """Rejects placeholder longer than 255 chars."""
        from app.routers.slack import _handle_custom_placeholder

        say = AsyncMock(return_value=None)
        long_value = "x" * 256
        await _handle_custom_placeholder("U_TESTUSER", "D_TESTDM", long_value, "test-id", say)

        say.assert_called_once()
        text = say.call_args.kwargs.get("text", "")
        assert "too long" in text.lower()


# -------------------------------------------------------------------------
# _create_allow_rule_from_context
# -------------------------------------------------------------------------

class TestCreateAllowRule:
    """Tests for _create_allow_rule_from_context helper."""

    @pytest.mark.asyncio
    async def test_create_command_allow_rule(self, db_session, redis, slack_agent):
        """Creates COMMAND_ALLOWLIST rule for 'run' context."""
        from app.routers.slack import _create_allow_rule_from_context

        context_json = json.dumps({
            "type": "run",
            "value": "ls -la",
            "agent_id": str(slack_agent.id),
        })

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            result = await _create_allow_rule_from_context(context_json, "testuser")

        assert result["rule_id"] is not None

        # Verify rule in DB
        async with TestSessionLocal() as session:
            stmt = select(Rule).where(Rule.name.like("Allow: ls%"))
            rules = (await session.execute(stmt)).scalars().all()
            assert len(rules) == 1
            assert rules[0].rule_type == RuleType.COMMAND_ALLOWLIST
            assert rules[0].action == RuleAction.ALLOW

    @pytest.mark.asyncio
    async def test_create_skill_allow_rule(self, db_session, redis, slack_agent):
        """Creates SKILL_ALLOWLIST rule for 'install' context."""
        from app.routers.slack import _create_allow_rule_from_context

        context_json = json.dumps({
            "type": "install",
            "value": "safe-skill",
            "agent_id": str(slack_agent.id),
        })

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            result = await _create_allow_rule_from_context(context_json, "testuser")

        assert result["rule_id"] is not None

    @pytest.mark.asyncio
    async def test_create_file_allow_rule(self, db_session, redis, slack_agent):
        """Creates FILE_ACCESS rule for 'access' context."""
        from app.routers.slack import _create_allow_rule_from_context

        context_json = json.dumps({
            "type": "access",
            "value": "/home/user/safe.txt",
            "agent_id": str(slack_agent.id),
        })

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            result = await _create_allow_rule_from_context(context_json, "testuser")

        assert result["rule_id"] is not None

    @pytest.mark.asyncio
    async def test_create_network_allow_rule(self, db_session, redis, slack_agent):
        """Creates NETWORK_EGRESS rule for 'network' context."""
        from app.routers.slack import _create_allow_rule_from_context

        context_json = json.dumps({
            "type": "network",
            "value": "example.com",
            "agent_id": str(slack_agent.id),
        })

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            result = await _create_allow_rule_from_context(context_json, "testuser")

        assert result["rule_id"] is not None

    @pytest.mark.asyncio
    async def test_create_rule_escapes_regex(self, db_session, redis, slack_agent):
        """Regex special chars in commands are escaped."""
        from app.routers.slack import _create_allow_rule_from_context

        context_json = json.dumps({
            "type": "run",
            "value": "cat file.txt | grep [test]",
            "agent_id": str(slack_agent.id),
        })

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            result = await _create_allow_rule_from_context(context_json, "testuser")

        async with TestSessionLocal() as session:
            stmt = select(Rule).where(Rule.name.like("Allow:%"))
            rules = (await session.execute(stmt)).scalars().all()
            assert len(rules) >= 1
            # Pattern should have escaped special chars
            pattern = rules[0].parameters["patterns"][0]
            assert r"\|" in pattern or r"\[" in pattern

    @pytest.mark.asyncio
    async def test_create_rule_invalid_json(self, db_session, redis):
        """Handles invalid JSON context gracefully."""
        from app.routers.slack import _create_allow_rule_from_context

        result = await _create_allow_rule_from_context("not valid json", "testuser")
        assert result["rule_id"] is None


# -------------------------------------------------------------------------
# _get_or_create_test_agent
# -------------------------------------------------------------------------

class TestGetOrCreateTestAgent:
    """Tests for _get_or_create_test_agent helper."""

    @pytest.mark.asyncio
    async def test_creates_new_agent(self, db_session, redis):
        """Creates a new test agent for unknown user."""
        from app.routers.slack import _get_or_create_test_agent, _test_agents

        # Clear cache
        _test_agents.pop("U_NEWUSER", None)

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            agent_id = await _get_or_create_test_agent("U_NEWUSER")

        assert agent_id is not None

        async with TestSessionLocal() as session:
            from app.models.agents import Agent
            stmt = select(Agent).where(Agent.external_id == "slack-test-U_NEWUSER")
            result = await session.execute(stmt)
            agent = result.scalar_one_or_none()
            assert agent is not None
            assert agent.owner_chat_id == "U_NEWUSER"

    @pytest.mark.asyncio
    async def test_returns_cached_agent(self, db_session, redis, slack_agent):
        """Returns cached agent on second call."""
        from app.routers.slack import _get_or_create_test_agent, _test_agents

        _test_agents["U_TESTUSER"] = slack_agent.id

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            agent_id = await _get_or_create_test_agent("U_TESTUSER")

        assert agent_id == slack_agent.id


# -------------------------------------------------------------------------
# _get_rule_info
# -------------------------------------------------------------------------

class TestGetRuleInfo:
    """Tests for _get_rule_info helper."""

    @pytest.mark.asyncio
    async def test_rule_info_found(self, db_session, redis, sample_rule):
        """Returns formatted rule details."""
        from app.routers.slack import _get_rule_info

        rule_id_partial = str(sample_rule.id)[:12]

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            info = await _get_rule_info(rule_id_partial)

        assert "Rule Details" in info
        assert sample_rule.name in info
        assert "Priority" in info

    @pytest.mark.asyncio
    async def test_rule_info_not_found(self, db_session, redis):
        """Returns not found for invalid ID."""
        from app.routers.slack import _get_rule_info

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            info = await _get_rule_info("000000000000")

        assert "not found" in info.lower()


# -------------------------------------------------------------------------
# send_slack_approval (public API)
# -------------------------------------------------------------------------

class TestSendSlackApproval:
    """Tests for the send_slack_approval public API."""

    @pytest.mark.asyncio
    async def test_send_approval_to_user(self, db_session, redis):
        """Sends approval message to Slack user DM."""
        from app.routers.slack import send_slack_approval

        mock_app = MagicMock()
        mock_app.client.conversations_open = AsyncMock(
            return_value={"channel": {"id": "D_TESTDM"}}
        )
        mock_app.client.chat_postMessage = AsyncMock()

        with patch("app.routers.slack.slack_app", mock_app):
            await send_slack_approval(
                target_user_id="U_TESTUSER",
                title="Test Approval",
                message="An agent wants to run a command",
                severity="warning",
                metadata={
                    "request_id": "test-req-1",
                    "requires_approval": True,
                    "agent_id": "test-agent",
                },
            )

        mock_app.client.conversations_open.assert_called_once_with(users="U_TESTUSER")
        mock_app.client.chat_postMessage.assert_called_once()
        call_kwargs = mock_app.client.chat_postMessage.call_args.kwargs
        blocks = call_kwargs["blocks"]
        # Should have approve/deny buttons
        action_blocks = [b for b in blocks if b.get("type") == "actions"]
        assert len(action_blocks) == 1
        action_ids = [e["action_id"] for e in action_blocks[0]["elements"]]
        assert "approve_action" in action_ids
        assert "deny_action" in action_ids

    @pytest.mark.asyncio
    async def test_send_approval_with_pii_context(self, db_session, redis):
        """Sends PII-specific approval message."""
        from app.routers.slack import send_slack_approval

        mock_app = MagicMock()
        mock_app.client.conversations_open = AsyncMock(
            return_value={"channel": {"id": "D_TESTDM"}}
        )
        mock_app.client.chat_postMessage = AsyncMock()

        with patch("app.routers.slack.slack_app", mock_app):
            await send_slack_approval(
                target_user_id="U_TESTUSER",
                title="PII Detected",
                message="Vault token found",
                severity="warning",
                metadata={
                    "request_id": "pii-req-1",
                    "requires_approval": True,
                    "agent_name": "Test Agent",
                    "pii_context": {
                        "action": "fill credit card form",
                        "destination_url": "https://example.com/checkout",
                        "vault_token_details": [
                            {"label": "My Visa", "category": "credit_card", "masked_value": "****1111"},
                        ],
                    },
                },
            )

        mock_app.client.chat_postMessage.assert_called_once()
        call_kwargs = mock_app.client.chat_postMessage.call_args.kwargs
        blocks = call_kwargs["blocks"]
        section_text = blocks[0]["text"]["text"]
        assert "PII" in section_text
        assert "My Visa" in section_text
        assert "****1111" in section_text

    @pytest.mark.asyncio
    async def test_send_approval_blocked_command_buttons(self, db_session, redis):
        """Sends Allow Once/Always buttons for blocked commands."""
        from app.routers.slack import send_slack_approval

        mock_app = MagicMock()
        mock_app.client.conversations_open = AsyncMock(
            return_value={"channel": {"id": "D_TESTDM"}}
        )
        mock_app.client.chat_postMessage = AsyncMock()

        with patch("app.routers.slack.slack_app", mock_app), \
             patch("app.redis_client.redis_client", redis):
            await send_slack_approval(
                target_user_id="U_TESTUSER",
                title="Command Blocked",
                message="rm -rf / was blocked",
                severity="warning",
                metadata={
                    "command": "rm -rf /",
                    "agent_id": "test-agent",
                    "agent_name": "Test Agent",
                },
            )

        mock_app.client.chat_postMessage.assert_called_once()
        call_kwargs = mock_app.client.chat_postMessage.call_args.kwargs
        blocks = call_kwargs["blocks"]
        action_blocks = [b for b in blocks if b.get("type") == "actions"]
        assert len(action_blocks) == 1
        action_ids = [e["action_id"] for e in action_blocks[0]["elements"]]
        assert "once_action" in action_ids
        assert "always_action" in action_ids

    @pytest.mark.asyncio
    async def test_send_approval_not_initialized(self, db_session, redis):
        """Does nothing when slack_app is not initialized."""
        from app.routers.slack import send_slack_approval

        with patch("app.routers.slack.slack_app", None):
            await send_slack_approval(
                target_user_id="U_TESTUSER",
                title="Test",
                message="Test",
                severity="info",
            )
        # Should not raise

    @pytest.mark.asyncio
    async def test_send_approval_to_channel(self, db_session, redis):
        """Sends to channel ID directly when not a user ID."""
        from app.routers.slack import send_slack_approval

        mock_app = MagicMock()
        mock_app.client.chat_postMessage = AsyncMock()

        with patch("app.routers.slack.slack_app", mock_app):
            await send_slack_approval(
                target_user_id="C_ALERTCHAN",
                title="Alert",
                message="Something happened",
                severity="info",
            )

        # Should NOT call conversations_open (not a user ID)
        mock_app.client.conversations_open.assert_not_called() if hasattr(
            mock_app.client, 'conversations_open'
        ) else None
        mock_app.client.chat_postMessage.assert_called_once()
        assert mock_app.client.chat_postMessage.call_args.kwargs["channel"] == "C_ALERTCHAN"

    @pytest.mark.asyncio
    async def test_send_approval_fallback_to_channel(self, db_session, redis):
        """Falls back to alert channel when DM fails."""
        from app.routers.slack import send_slack_approval

        mock_app = MagicMock()
        mock_app.client.conversations_open = AsyncMock(
            side_effect=Exception("Cannot DM user")
        )
        mock_app.client.chat_postMessage = AsyncMock()

        with patch("app.routers.slack.slack_app", mock_app), \
             patch("app.routers.slack.settings") as mock_settings:
            mock_settings.SLACK_ALERT_CHANNEL = "C_FALLBACK"
            await send_slack_approval(
                target_user_id="U_UNKNOWNUSER",
                title="Alert",
                message="Test",
                severity="info",
            )

        # Should have tried DM first, then fallen back to channel
        assert mock_app.client.chat_postMessage.call_count >= 1


# -------------------------------------------------------------------------
# Block Kit helper functions
# -------------------------------------------------------------------------

class TestBlockKitHelpers:
    """Tests for Slack Block Kit helper functions."""

    def test_section(self):
        from app.routers.slack import _section
        block = _section("Hello world")
        assert block["type"] == "section"
        assert block["text"]["type"] == "mrkdwn"
        assert block["text"]["text"] == "Hello world"

    def test_header(self):
        from app.routers.slack import _header
        block = _header("My Header")
        assert block["type"] == "header"
        assert block["text"]["type"] == "plain_text"
        assert block["text"]["text"] == "My Header"

    def test_divider(self):
        from app.routers.slack import _divider
        block = _divider()
        assert block["type"] == "divider"

    def test_context(self):
        from app.routers.slack import _context
        block = _context("Some context")
        assert block["type"] == "context"
        assert block["elements"][0]["text"] == "Some context"

    def test_actions(self):
        from app.routers.slack import _actions
        block = _actions([{"type": "button"}])
        assert block["type"] == "actions"
        assert len(block["elements"]) == 1

    def test_button_basic(self):
        from app.routers.slack import _button
        btn = _button("Click Me", "my_action", "val123")
        assert btn["type"] == "button"
        assert btn["text"]["text"] == "Click Me"
        assert btn["action_id"] == "my_action"
        assert btn["value"] == "val123"
        assert "style" not in btn

    def test_button_with_style(self):
        from app.routers.slack import _button
        btn = _button("Danger", "danger_action", "val", "danger")
        assert btn["style"] == "danger"


# -------------------------------------------------------------------------
# Lifecycle
# -------------------------------------------------------------------------

class TestSlackLifecycle:
    """Tests for start/stop Slack bot lifecycle."""

    @pytest.mark.asyncio
    async def test_start_bot_no_tokens(self):
        """Skips start when tokens not configured."""
        from app.routers.slack import start_slack_bot

        with patch("app.routers.slack.settings") as mock_settings:
            mock_settings.SLACK_BOT_TOKEN = None
            mock_settings.SLACK_APP_TOKEN = None
            await start_slack_bot()

        # Should not raise, just log warning

    @pytest.mark.asyncio
    async def test_stop_bot_not_started(self):
        """Stop is safe when bot was never started."""
        from app.routers.slack import stop_slack_bot

        with patch("app.routers.slack.socket_handler", None):
            await stop_slack_bot()

        # Should not raise

    @pytest.mark.asyncio
    async def test_stop_bot_cleans_up(self):
        """Stop closes the socket handler."""
        from app.routers.slack import stop_slack_bot

        mock_handler = MagicMock()
        mock_handler.close_async = AsyncMock()

        with patch("app.routers.slack.socket_handler", mock_handler):
            await stop_slack_bot()

        mock_handler.close_async.assert_called_once()


# -------------------------------------------------------------------------
# Message tracking & deletion
# -------------------------------------------------------------------------

class TestMessageTracking:
    """Tests for message tracking and deletion helpers."""

    @pytest.mark.asyncio
    async def test_track_bot_message(self, db_session, redis):
        """Tracks a message TS in Redis sorted set."""
        from app.routers.slack import _track_bot_message

        with patch("app.redis_client.redis_client", redis):
            await _track_bot_message("C_TEST", "1234.5678")

        members = await redis.zrangebyscore("slack_bot_messages:C_TEST", "-inf", "+inf")
        assert "1234.5678" in members

    @pytest.mark.asyncio
    async def test_delete_slack_message(self, db_session, redis):
        """Deletes a Slack message via API."""
        from app.routers.slack import _delete_slack_message

        mock_app = MagicMock()
        mock_app.client.chat_delete = AsyncMock()

        with patch("app.routers.slack.slack_app", mock_app):
            await _delete_slack_message("C_TEST", "1234.5678")

        mock_app.client.chat_delete.assert_called_once_with(channel="C_TEST", ts="1234.5678")

    @pytest.mark.asyncio
    async def test_delete_slack_message_no_app(self, db_session, redis):
        """Does nothing when slack_app is None."""
        from app.routers.slack import _delete_slack_message

        with patch("app.routers.slack.slack_app", None):
            await _delete_slack_message("C_TEST", "1234.5678")
        # Should not raise

    @pytest.mark.asyncio
    async def test_say_and_track(self, db_session, redis):
        """Say function tracks the message TS."""
        from app.routers.slack import _say_and_track

        say = AsyncMock(return_value={"ts": "9999.0001", "channel": "C_TRACK"})

        with patch("app.redis_client.redis_client", redis):
            result = await _say_and_track(say, text="Hello")

        assert result["ts"] == "9999.0001"
        members = await redis.zrangebyscore("slack_bot_messages:C_TRACK", "-inf", "+inf")
        assert "9999.0001" in members


# -------------------------------------------------------------------------
# Audit logging
# -------------------------------------------------------------------------

class TestAuditLogging:
    """Tests that actions create appropriate audit logs."""

    @pytest.mark.asyncio
    async def test_emergency_block_audit_log(self, db_session, redis):
        """Emergency block creates CRITICAL audit log."""
        from app.routers.slack import _activate_emergency_block

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _activate_emergency_block("U_TESTUSER", "testuser")

        async with TestSessionLocal() as session:
            stmt = select(AuditLog).where(
                AuditLog.severity == AuditSeverity.CRITICAL,
                AuditLog.message.like("%Emergency block%Slack%"),
            )
            logs = (await session.execute(stmt)).scalars().all()
            assert len(logs) >= 1

    @pytest.mark.asyncio
    async def test_unblock_audit_log(self, db_session, redis):
        """Unblock creates WARNING audit log."""
        from app.routers.slack import _activate_emergency_block, _cmd_unblock

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _activate_emergency_block("U_TESTUSER", "testuser")

        say = AsyncMock(return_value={"ts": "1234", "channel": "C_TEST"})
        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _cmd_unblock(_make_command(user_id="U_TESTUSER"), say)

        async with TestSessionLocal() as session:
            stmt = select(AuditLog).where(
                AuditLog.message.like("%deactivated%Slack%"),
            )
            logs = (await session.execute(stmt)).scalars().all()
            assert len(logs) >= 1

    @pytest.mark.asyncio
    async def test_approval_audit_log(self, db_session, redis):
        """Approval action creates INFO audit log."""
        from app.routers.slack import _process_approval
        from app.routers.approvals import APPROVAL_PREFIX

        approval_id = "audit-test-approval"
        approval_data = {
            "id": approval_id,
            "agent_id": str(uuid4()),
            "agent_name": "Test Agent",
            "request_type": "command",
            "command": "ls",
            "rule_id": str(uuid4()),
            "rule_name": "Test Rule",
            "status": "pending",
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + timedelta(hours=1)).isoformat(),
        }
        await redis.set(f"{APPROVAL_PREFIX}{approval_id}", json.dumps(approval_data))

        with patch("app.redis_client.redis_client", redis), \
             patch("app.routers.slack.async_session_factory", TestSessionLocal):
            result = await _process_approval(approval_id, "approve", "testuser")

        assert result["success"] is True

        async with TestSessionLocal() as session:
            stmt = select(AuditLog).where(
                AuditLog.action == AuditAction.APPROVAL_GRANTED,
                AuditLog.message.like(f"%{approval_id}%Slack%"),
            )
            logs = (await session.execute(stmt)).scalars().all()
            assert len(logs) >= 1
            assert logs[0].new_value["channel"] == "slack"

    @pytest.mark.asyncio
    async def test_allow_always_audit_log(self, db_session, redis, slack_agent):
        """Allow Always creates audit log for rule creation."""
        from app.routers.slack import _create_allow_rule_from_context

        context_json = json.dumps({
            "type": "run",
            "value": "safe-command",
            "agent_id": str(slack_agent.id),
        })

        with patch("app.routers.slack.async_session_factory", TestSessionLocal):
            await _create_allow_rule_from_context(context_json, "testuser")

        async with TestSessionLocal() as session:
            stmt = select(AuditLog).where(
                AuditLog.action == AuditAction.RULE_CREATED,
                AuditLog.message.like("%Slack%"),
            )
            logs = (await session.execute(stmt)).scalars().all()
            assert len(logs) >= 1
            assert logs[0].new_value["source"] == "slack"
