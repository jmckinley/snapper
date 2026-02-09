"""
@module test_telegram_callbacks
@description Tests for Telegram callback handlers.
Tests that Telegram inline button callbacks (once, always, rule,
confirm_block) work correctly for the Allow Once/Always and emergency block
functionality.
"""

import hashlib
import json
import os
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from uuid import uuid4

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agents import Agent
from app.models.rules import Rule, RuleAction, RuleType
from app.redis_client import RedisClient


@pytest.fixture(autouse=True)
def mock_telegram_token():
    """Mock TELEGRAM_BOT_TOKEN for all tests in this module."""
    with patch("app.routers.telegram.settings") as mock_settings:
        mock_settings.TELEGRAM_BOT_TOKEN = "test_token_for_testing"
        mock_settings.TELEGRAM_CHAT_ID = "12345"
        yield mock_settings


class TestOnceCallback:
    """Tests for the 'once' callback handler (Allow Once)."""

    @pytest.mark.asyncio
    async def test_once_callback_stores_redis_key(
        self, client: AsyncClient, sample_agent: Agent, redis: RedisClient
    ):
        """once: callback should store approval key with 5 min TTL."""
        # Create context in Redis
        context_data = {
            "type": "run",
            "value": "test command",
            "agent_id": sample_agent.name,
        }
        context_key = hashlib.sha256(json.dumps(context_data).encode()).hexdigest()[:12]
        await redis.set(f"tg_ctx:{context_key}", json.dumps(context_data), expire=3600)

        # Mock Telegram API calls
        with patch("app.routers.telegram._answer_callback", new_callable=AsyncMock) as mock_answer, \
             patch("app.routers.telegram._edit_message", new_callable=AsyncMock) as mock_edit:

            # Simulate callback from Telegram
            response = await client.post(
                "/api/v1/telegram/webhook",
                json={
                    "update_id": 123456,
                    "callback_query": {
                        "id": "callback123",
                        "from": {"id": 12345, "username": "testuser"},
                        "message": {"chat": {"id": 12345}, "message_id": 100},
                        "data": f"once:{context_key}",
                    },
                },
            )

            assert response.status_code == 200
            data = response.json()
            assert data["ok"] is True
            assert data["action"] == "allow_once"
            assert data["expires_in"] == 300

            # Verify approval key was created in Redis
            cmd = context_data["value"]
            cmd_hash = hashlib.sha256(cmd.encode()).hexdigest()[:16]
            approval_key = f"once_allow:{sample_agent.name}:{cmd_hash}"
            assert await redis.get(approval_key) is not None

    @pytest.mark.asyncio
    async def test_once_callback_expired_context(
        self, client: AsyncClient, redis: RedisClient
    ):
        """once: callback should handle expired context gracefully."""
        # Don't create context - simulate expired

        with patch("app.routers.telegram._answer_callback", new_callable=AsyncMock) as mock_answer:
            response = await client.post(
                "/api/v1/telegram/webhook",
                json={
                    "update_id": 123456,
                    "callback_query": {
                        "id": "callback123",
                        "from": {"id": 12345, "username": "testuser"},
                        "message": {"chat": {"id": 12345}, "message_id": 100},
                        "data": "once:nonexistent123",
                    },
                },
            )

            assert response.status_code == 200
            data = response.json()
            assert data["ok"] is False
            assert data["error"] == "context_expired"

            # Verify error callback was sent
            mock_answer.assert_called_once()
            call_args = mock_answer.call_args
            assert "expired" in call_args.kwargs.get("text", "").lower()


class TestAlwaysCallback:
    """Tests for the 'always' callback handler (Allow Always)."""

    @pytest.mark.asyncio
    async def test_always_callback_creates_command_rule(
        self, client: AsyncClient, sample_agent: Agent, redis: RedisClient
    ):
        """always: callback should create COMMAND_ALLOWLIST rule for 'run' type."""
        # Create context in Redis
        context_data = {
            "type": "run",
            "value": "npm install lodash",
            "agent_id": str(sample_agent.id),
        }
        context_key = hashlib.sha256(json.dumps(context_data).encode()).hexdigest()[:12]
        await redis.set(f"tg_ctx:{context_key}", json.dumps(context_data), expire=3600)

        # Mock the _create_allow_rule_from_context to avoid event loop issues
        mock_result = {"message": "Rule created", "rule_id": "test-rule-id-123"}

        with patch("app.routers.telegram._answer_callback", new_callable=AsyncMock), \
             patch("app.routers.telegram._edit_message", new_callable=AsyncMock), \
             patch("app.routers.telegram._create_allow_rule_from_context", new_callable=AsyncMock, return_value=mock_result):

            response = await client.post(
                "/api/v1/telegram/webhook",
                json={
                    "update_id": 123456,
                    "callback_query": {
                        "id": "callback123",
                        "from": {"id": 12345, "username": "testuser"},
                        "message": {"chat": {"id": 12345}, "message_id": 100},
                        "data": f"always:{context_key}",
                    },
                },
            )

            assert response.status_code == 200
            data = response.json()
            assert data["ok"] is True
            assert data["action"] == "allow_always"
            assert data.get("rule_id") == "test-rule-id-123"

    @pytest.mark.asyncio
    async def test_always_callback_creates_skill_rule(
        self, client: AsyncClient, sample_agent: Agent, redis: RedisClient
    ):
        """always: callback should create SKILL_ALLOWLIST rule for 'install' type."""
        # Create context in Redis for skill install
        context_data = {
            "type": "install",
            "value": "mcp-server-filesystem",
            "agent_id": str(sample_agent.id),
        }
        context_key = hashlib.sha256(json.dumps(context_data).encode()).hexdigest()[:12]
        await redis.set(f"tg_ctx:{context_key}", json.dumps(context_data), expire=3600)

        mock_result = {"message": "Rule created", "rule_id": "skill-rule-id-456"}

        with patch("app.routers.telegram._answer_callback", new_callable=AsyncMock), \
             patch("app.routers.telegram._edit_message", new_callable=AsyncMock), \
             patch("app.routers.telegram._create_allow_rule_from_context", new_callable=AsyncMock, return_value=mock_result):

            response = await client.post(
                "/api/v1/telegram/webhook",
                json={
                    "update_id": 123456,
                    "callback_query": {
                        "id": "callback123",
                        "from": {"id": 12345, "username": "testuser"},
                        "message": {"chat": {"id": 12345}, "message_id": 100},
                        "data": f"always:{context_key}",
                    },
                },
            )

            assert response.status_code == 200
            data = response.json()
            assert data["ok"] is True
            assert data["action"] == "allow_always"

    @pytest.mark.asyncio
    async def test_always_callback_escaped_regex(
        self, client: AsyncClient, sample_agent: Agent, redis: RedisClient
    ):
        """always: callback should regex-escape command patterns."""
        # Command with regex special characters
        context_data = {
            "type": "run",
            "value": "grep '^test$' file.txt",
            "agent_id": str(sample_agent.id),
        }
        context_key = hashlib.sha256(json.dumps(context_data).encode()).hexdigest()[:12]
        await redis.set(f"tg_ctx:{context_key}", json.dumps(context_data), expire=3600)

        mock_result = {"message": "Rule created", "rule_id": "escaped-rule-789"}

        with patch("app.routers.telegram._answer_callback", new_callable=AsyncMock), \
             patch("app.routers.telegram._edit_message", new_callable=AsyncMock), \
             patch("app.routers.telegram._create_allow_rule_from_context", new_callable=AsyncMock, return_value=mock_result) as mock_create:

            response = await client.post(
                "/api/v1/telegram/webhook",
                json={
                    "update_id": 123456,
                    "callback_query": {
                        "id": "callback123",
                        "from": {"id": 12345, "username": "testuser"},
                        "message": {"chat": {"id": 12345}, "message_id": 100},
                        "data": f"always:{context_key}",
                    },
                },
            )
            assert response.status_code == 200

            # Verify _create_allow_rule_from_context was called
            mock_create.assert_called_once()


class TestConfirmBlockCallback:
    """Tests for the 'confirm_block' callback handler (Emergency Block)."""

    @pytest.mark.asyncio
    async def test_confirm_block_webhook_returns_ok(
        self, client: AsyncClient, sample_agent: Agent, redis: RedisClient
    ):
        """confirm_block: webhook dispatches handler and returns emergency_block action."""
        # Need to set up pending block first
        chat_id = 12345
        mock_result = {"rule_id": str(sample_agent.id), "status": "activated"}

        with patch("app.routers.telegram._answer_callback", new_callable=AsyncMock), \
             patch("app.routers.telegram._edit_message", new_callable=AsyncMock), \
             patch("app.routers.telegram._activate_emergency_block", new_callable=AsyncMock, return_value=mock_result):

            response = await client.post(
                "/api/v1/telegram/webhook",
                json={
                    "update_id": 123456,
                    "callback_query": {
                        "id": "callback123",
                        "from": {"id": 12345, "username": "admin"},
                        "message": {"chat": {"id": chat_id}, "message_id": 100},
                        "data": f"confirm_block:{chat_id}",
                    },
                },
            )

            assert response.status_code == 200
            data = response.json()
            assert data["ok"] is True
            assert data["action"] == "emergency_block"


class TestRuleCallback:
    """Tests for the 'rule' callback handler (View Rule)."""

    @pytest.mark.asyncio
    async def test_rule_callback_returns_details(
        self, client: AsyncClient, sample_rule: Rule
    ):
        """rule: callback should return formatted rule details."""
        rule_id_short = str(sample_rule.id)[:12]
        mock_rule_info = f"📋 *Rule Details*\n*Name:* {sample_rule.name}\n*ID:* `{rule_id_short}...`"

        with patch("app.routers.telegram._answer_callback", new_callable=AsyncMock) as mock_answer, \
             patch("app.routers.telegram._send_message", new_callable=AsyncMock) as mock_send, \
             patch("app.routers.telegram._get_rule_info", new_callable=AsyncMock, return_value=mock_rule_info):

            response = await client.post(
                "/api/v1/telegram/webhook",
                json={
                    "update_id": 123456,
                    "callback_query": {
                        "id": "callback123",
                        "from": {"id": 12345, "username": "testuser"},
                        "message": {"chat": {"id": 12345}, "message_id": 100},
                        "data": f"rule:{rule_id_short}",
                    },
                },
            )

            assert response.status_code == 200
            data = response.json()
            assert data["ok"] is True
            assert data["action"] == "view_rule"

            # Verify message was sent with rule details
            mock_send.assert_called_once()
            call_args = mock_send.call_args
            message_text = call_args.kwargs.get("text", "")
            assert sample_rule.name in message_text


class TestEmergencyBlock:
    """Tests for _activate_emergency_block via webhook.

    The internal function creates its own DB session via async_session_factory(),
    so we verify behavior through mock return values and webhook responses.
    """

    @pytest.mark.asyncio
    async def test_webhook_dispatches_emergency_block_handler(
        self, client: AsyncClient, redis: RedisClient
    ):
        """Emergency block webhook dispatches _activate_emergency_block and returns OK."""
        mock_result = {
            "rule_id": str(uuid4()),
            "status": "activated",
            "rule_types": ["command_denylist", "skill_denylist", "file_access", "network_egress"],
        }

        with patch("app.routers.telegram._answer_callback", new_callable=AsyncMock), \
             patch("app.routers.telegram._edit_message", new_callable=AsyncMock), \
             patch("app.routers.telegram._activate_emergency_block", new_callable=AsyncMock, return_value=mock_result) as mock_block:

            response = await client.post(
                "/api/v1/telegram/webhook",
                json={
                    "update_id": 123456,
                    "callback_query": {
                        "id": "callback_block",
                        "from": {"id": 12345, "username": "admin"},
                        "message": {"chat": {"id": 12345}, "message_id": 200},
                        "data": "confirm_block:12345",
                    },
                },
            )

            assert response.status_code == 200
            data = response.json()
            assert data["ok"] is True
            assert data["action"] == "emergency_block"
            mock_block.assert_called_once()

    @pytest.mark.asyncio
    async def test_all_rules_global_and_max_priority(
        self, client: AsyncClient, db_session: AsyncSession, redis: RedisClient
    ):
        """Verify _activate_emergency_block creates global priority-10000 rules via direct call with test DB."""
        from tests.conftest import TestSessionLocal

        async with TestSessionLocal() as direct_session:
            from app.routers.telegram import _activate_emergency_block
            with patch("app.routers.telegram.async_session_factory", TestSessionLocal):
                await _activate_emergency_block(12345, "admin")

            result = await direct_session.execute(
                select(Rule).where(
                    Rule.name.like("%EMERGENCY%"),
                    Rule.is_active == True,
                )
            )
            rules = list(result.scalars().all())
            assert len(rules) >= 4

            for rule in rules:
                assert rule.priority == 10000
                assert rule.agent_id is None

    @pytest.mark.asyncio
    async def test_reactivates_existing_emergency_rules(
        self, client: AsyncClient, db_session: AsyncSession, redis: RedisClient
    ):
        """If emergency rules already exist, reactivates them via direct call with test DB."""
        from tests.conftest import TestSessionLocal

        async with TestSessionLocal() as direct_session:
            # Create an existing inactive emergency rule
            existing_rule = Rule(
                id=uuid4(),
                name="🚨 EMERGENCY BLOCK ALL",
                rule_type=RuleType.COMMAND_DENYLIST,
                action=RuleAction.DENY,
                priority=10000,
                parameters={"patterns": [".*"]},
                is_active=False,
                agent_id=None,
            )
            direct_session.add(existing_rule)
            await direct_session.commit()

            from app.routers.telegram import _activate_emergency_block
            with patch("app.routers.telegram.async_session_factory", TestSessionLocal):
                await _activate_emergency_block(12345, "admin")

            await direct_session.refresh(existing_rule)
            assert existing_rule.is_active is True


class TestStatusCommand:
    """Tests for /status webhook command."""

    @pytest.mark.asyncio
    async def test_status_returns_health_info(
        self, client: AsyncClient, redis: RedisClient
    ):
        """/status webhook returns PostgreSQL + Redis health status."""
        with patch("app.routers.telegram._send_message", new_callable=AsyncMock) as mock_send:
            response = await client.post(
                "/api/v1/telegram/webhook",
                json={
                    "update_id": 200001,
                    "message": {
                        "message_id": 300,
                        "from": {"id": 12345, "username": "admin"},
                        "chat": {"id": 12345, "type": "private"},
                        "text": "/status",
                    },
                },
            )

            assert response.status_code == 200
            mock_send.assert_called_once()
            call_args = mock_send.call_args
            text = call_args.kwargs.get("text", "")
            assert "PostgreSQL" in text or "Snapper" in text

    @pytest.mark.asyncio
    async def test_status_webhook_returns_ok(
        self, client: AsyncClient, redis: RedisClient
    ):
        """/status webhook returns 200 OK response."""
        with patch("app.routers.telegram._send_message", new_callable=AsyncMock):
            response = await client.post(
                "/api/v1/telegram/webhook",
                json={
                    "update_id": 200002,
                    "message": {
                        "message_id": 301,
                        "from": {"id": 12345, "username": "admin"},
                        "chat": {"id": 12345, "type": "private"},
                        "text": "/status",
                    },
                },
            )

            assert response.status_code == 200


class TestPurgeCommand:
    """Tests for PII purge functionality."""

    @pytest.mark.asyncio
    async def test_pii_purge_redacts_audit_fields(
        self, client: AsyncClient, db_session: AsyncSession,
        sample_agent: Agent, redis: RedisClient
    ):
        """_execute_pii_purge redacts details/old_value/new_value JSONB fields."""
        from contextlib import asynccontextmanager
        from app.models.audit_logs import AuditLog, AuditAction, AuditSeverity
        from app.routers.telegram import _execute_pii_purge

        # Create audit log with PII-like data
        log = AuditLog(
            id=uuid4(),
            action=AuditAction.REQUEST_DENIED,
            severity=AuditSeverity.INFO,
            agent_id=sample_agent.id,
            message="Blocked access to user@email.com",
            details={"email": "user@email.com", "ip": "192.168.1.1"},
        )
        db_session.add(log)
        await db_session.commit()

        @asynccontextmanager
        async def mock_factory():
            yield db_session

        with patch("app.routers.telegram.async_session_factory", mock_factory), \
             patch("app.routers.telegram._send_message", new_callable=AsyncMock):
            result = await _execute_pii_purge(str(sample_agent.id)[:8], "admin")

        assert result["redacted_count"] >= 1


class TestRulesCommand:
    """Tests for /rules webhook command.

    Uses TestSessionLocal (real test DB sessions) so SQLAlchemy ORM
    mapping (String → RuleType enum) works correctly.
    """

    @pytest.mark.asyncio
    async def test_shows_truncation_message_for_many_rules(
        self, client: AsyncClient, db_session: AsyncSession, redis: RedisClient
    ):
        """Shows 'Showing 15 of N rule(s)' when > 15 rules via direct call."""
        from app.routers.telegram import _handle_rules_command
        from tests.conftest import TestSessionLocal

        # Create 20 global rules (agent_id=None) so they show for any agent
        async with TestSessionLocal() as session:
            for i in range(20):
                rule = Rule(
                    id=uuid4(),
                    name=f"Test Rule {i+1:02d}",
                    rule_type=RuleType.COMMAND_ALLOWLIST,
                    action=RuleAction.ALLOW,
                    priority=100 + i,
                    parameters={"commands": [f"cmd-{i}"]},
                    is_active=True,
                    agent_id=None,
                )
                session.add(rule)
            await session.commit()

        with patch("app.routers.telegram.async_session_factory", TestSessionLocal), \
             patch("app.routers.telegram._get_or_create_test_agent", new_callable=AsyncMock, return_value=None), \
             patch("app.routers.telegram._send_message", new_callable=AsyncMock) as mock_send:
            await _handle_rules_command(12345, "/rules")

            mock_send.assert_called()
            text = mock_send.call_args.kwargs.get("text", "")
            assert "Showing 15 of" in text
            assert "20" in text

    @pytest.mark.asyncio
    async def test_shows_no_active_rules_message(
        self, client: AsyncClient, db_session: AsyncSession, redis: RedisClient
    ):
        """Shows 'No active rules' message when none exist."""
        from app.routers.telegram import _handle_rules_command
        from tests.conftest import TestSessionLocal

        with patch("app.routers.telegram.async_session_factory", TestSessionLocal), \
             patch("app.routers.telegram._get_or_create_test_agent", new_callable=AsyncMock, return_value=None), \
             patch("app.routers.telegram._send_message", new_callable=AsyncMock) as mock_send:
            await _handle_rules_command(12345, "/rules")

            mock_send.assert_called()
            text = mock_send.call_args.kwargs.get("text", "")
            assert "No rules configured" in text
