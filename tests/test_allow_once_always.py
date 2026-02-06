"""
@module test_allow_once_always
@description Tests for Allow Once/Always functionality.
Tests that one-time approvals (from Telegram's "Allow Once" button)
correctly grant access to otherwise-blocked commands, and that the approval
is properly consumed after a single use.
"""

import hashlib
import pytest
from uuid import uuid4

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agents import Agent
from app.models.rules import Rule, RuleAction, RuleType
from app.redis_client import RedisClient


class TestAllowOnceKeyGrantsAccess:
    """Tests for one-time approval Redis keys."""

    @pytest.mark.asyncio
    async def test_allow_once_key_grants_access(
        self, client: AsyncClient, sample_agent: Agent, redis: RedisClient
    ):
        """Redis once_allow key should allow an otherwise-blocked command."""
        # Create a deny rule that would block cat commands
        command = "cat /etc/passwd"

        # First, verify the command would be denied without the one-time approval
        response = await client.post(
            "/api/v1/rules/evaluate",
            json={
                "agent_id": sample_agent.external_id,
                "request_type": "command",
                "command": command,
            },
        )
        assert response.status_code == 200
        # With DENY_BY_DEFAULT=true and no allow rules, should be denied
        data = response.json()
        assert data["decision"] == "deny"

        # Now create a one-time approval key
        cmd_hash = hashlib.sha256(command.encode()).hexdigest()[:16]
        approval_key = f"once_allow:{sample_agent.name}:{cmd_hash}"
        await redis.set(approval_key, "1", expire=300)

        # The command should now be allowed
        response = await client.post(
            "/api/v1/rules/evaluate",
            json={
                "agent_id": sample_agent.external_id,
                "request_type": "command",
                "command": command,
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "allow"
        assert "One-time approval" in data["reason"]

    @pytest.mark.asyncio
    async def test_allow_once_key_consumed_after_use(
        self, client: AsyncClient, sample_agent: Agent, redis: RedisClient
    ):
        """One-time approval key should be deleted after single use."""
        command = "rm -rf /tmp/testdir"
        cmd_hash = hashlib.sha256(command.encode()).hexdigest()[:16]
        approval_key = f"once_allow:{sample_agent.name}:{cmd_hash}"

        # Create the approval key
        await redis.set(approval_key, "1", expire=300)

        # Verify key exists
        assert await redis.get(approval_key) is not None

        # Use the approval
        response = await client.post(
            "/api/v1/rules/evaluate",
            json={
                "agent_id": sample_agent.external_id,
                "request_type": "command",
                "command": command,
            },
        )
        assert response.status_code == 200
        assert response.json()["decision"] == "allow"

        # Key should now be deleted
        assert await redis.get(approval_key) is None

        # Second request should be denied (no more one-time approval)
        response = await client.post(
            "/api/v1/rules/evaluate",
            json={
                "agent_id": sample_agent.external_id,
                "request_type": "command",
                "command": command,
            },
        )
        assert response.status_code == 200
        assert response.json()["decision"] == "deny"

    @pytest.mark.asyncio
    async def test_allow_once_with_agent_name_lookup(
        self, client: AsyncClient, sample_agent: Agent, redis: RedisClient
    ):
        """Allow once should work when keyed by agent name (not just external_id)."""
        command = "ls -la /secret"
        cmd_hash = hashlib.sha256(command.encode()).hexdigest()[:16]

        # Create key using agent name
        approval_key = f"once_allow:{sample_agent.name}:{cmd_hash}"
        await redis.set(approval_key, "1", expire=300)

        # Request using external_id should still find the key
        response = await client.post(
            "/api/v1/rules/evaluate",
            json={
                "agent_id": sample_agent.external_id,
                "request_type": "command",
                "command": command,
            },
        )
        assert response.status_code == 200
        assert response.json()["decision"] == "allow"

    @pytest.mark.asyncio
    async def test_allow_once_does_not_affect_other_commands(
        self, client: AsyncClient, sample_agent: Agent, redis: RedisClient
    ):
        """Allow once should only match the exact command hash."""
        approved_command = "cat /etc/passwd"
        other_command = "cat /etc/shadow"

        # Create approval for approved_command
        cmd_hash = hashlib.sha256(approved_command.encode()).hexdigest()[:16]
        approval_key = f"once_allow:{sample_agent.name}:{cmd_hash}"
        await redis.set(approval_key, "1", expire=300)

        # Different command should still be denied
        response = await client.post(
            "/api/v1/rules/evaluate",
            json={
                "agent_id": sample_agent.external_id,
                "request_type": "command",
                "command": other_command,
            },
        )
        assert response.status_code == 200
        assert response.json()["decision"] == "deny"

        # Approved command should be allowed
        response = await client.post(
            "/api/v1/rules/evaluate",
            json={
                "agent_id": sample_agent.external_id,
                "request_type": "command",
                "command": approved_command,
            },
        )
        assert response.status_code == 200
        assert response.json()["decision"] == "allow"

    @pytest.mark.asyncio
    async def test_allow_once_bypasses_deny_rule(
        self, client: AsyncClient, db_session: AsyncSession, sample_agent: Agent, redis: RedisClient
    ):
        """Allow once should bypass even explicit deny rules."""
        command = "sudo rm -rf /"

        # Create an explicit deny rule for this dangerous command
        deny_rule = Rule(
            id=uuid4(),
            name="Block dangerous rm",
            description="Block rm -rf / commands",
            agent_id=sample_agent.id,
            rule_type=RuleType.COMMAND_DENYLIST,
            action=RuleAction.DENY,
            priority=1000,  # High priority
            parameters={"patterns": [r"sudo\s+rm\s+-rf\s+/"]},
            is_active=True,
        )
        db_session.add(deny_rule)
        await db_session.commit()

        # Without approval, should be denied
        response = await client.post(
            "/api/v1/rules/evaluate",
            json={
                "agent_id": sample_agent.external_id,
                "request_type": "command",
                "command": command,
            },
        )
        assert response.status_code == 200
        assert response.json()["decision"] == "deny"

        # Create one-time approval
        cmd_hash = hashlib.sha256(command.encode()).hexdigest()[:16]
        approval_key = f"once_allow:{sample_agent.name}:{cmd_hash}"
        await redis.set(approval_key, "1", expire=300)

        # With approval, should be allowed despite the deny rule
        response = await client.post(
            "/api/v1/rules/evaluate",
            json={
                "agent_id": sample_agent.external_id,
                "request_type": "command",
                "command": command,
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "allow"
        assert "One-time approval" in data["reason"]
