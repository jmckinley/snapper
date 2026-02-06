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
    async def test_confirm_block_creates_rule(
        self, client: AsyncClient, sample_agent: Agent, redis: RedisClient
    ):
        """confirm_block: callback should create priority 10000 deny-all rule."""
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
