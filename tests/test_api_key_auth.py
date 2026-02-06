"""Tests for API key authentication."""

import pytest
from uuid import uuid4

from app.models.agents import Agent, AgentStatus, TrustLevel, generate_api_key


class TestAPIKeyGeneration:
    """Tests for API key generation."""

    def test_api_key_format(self):
        """Test that generated keys have correct format."""
        key = generate_api_key()
        assert key.startswith("snp_")
        assert len(key) > 40  # snp_ + 32+ chars

    def test_api_keys_are_unique(self):
        """Test that each generated key is unique."""
        keys = [generate_api_key() for _ in range(100)]
        assert len(set(keys)) == 100


class TestAPIKeyAuth:
    """Tests for API key authentication on /evaluate endpoint."""

    @pytest.mark.asyncio
    async def test_evaluate_with_valid_api_key(self, client, sample_agent):
        """Test that valid API key authenticates successfully."""
        response = await client.post(
            "/api/v1/rules/evaluate",
            headers={"X-API-Key": sample_agent.api_key},
            json={
                "agent_id": sample_agent.external_id,
                "request_type": "command",
                "command": "ls -la",
            },
        )
        assert response.status_code == 200
        # Should not be denied for invalid key
        assert response.json()["decision"] != "deny" or "API key" not in response.json().get("reason", "")

    @pytest.mark.asyncio
    async def test_evaluate_with_invalid_api_key(self, client, sample_agent):
        """Test that invalid API key is rejected."""
        response = await client.post(
            "/api/v1/rules/evaluate",
            headers={"X-API-Key": "snp_invalid_key_12345"},
            json={
                "agent_id": sample_agent.external_id,
                "request_type": "command",
                "command": "ls -la",
            },
        )
        assert response.status_code == 200
        assert response.json()["decision"] == "deny"
        assert "Invalid API key" in response.json()["reason"]

    @pytest.mark.asyncio
    async def test_evaluate_with_malformed_api_key(self, client, sample_agent):
        """Test that malformed API key (wrong prefix) is rejected."""
        response = await client.post(
            "/api/v1/rules/evaluate",
            headers={"X-API-Key": "bad_prefix_key"},
            json={
                "agent_id": sample_agent.external_id,
                "request_type": "command",
                "command": "ls -la",
            },
        )
        assert response.status_code == 200
        assert response.json()["decision"] == "deny"
        assert "Invalid API key format" in response.json()["reason"]

    @pytest.mark.asyncio
    async def test_evaluate_without_api_key_uses_agent_id(self, client, sample_agent):
        """Test that requests without API key fall back to agent_id lookup."""
        response = await client.post(
            "/api/v1/rules/evaluate",
            json={
                "agent_id": sample_agent.external_id,
                "request_type": "command",
                "command": "ls -la",
            },
        )
        assert response.status_code == 200
        # Should work without API key when REQUIRE_API_KEY=false
        assert "API key required" not in response.json().get("reason", "")

    @pytest.mark.asyncio
    async def test_evaluate_with_suspended_agent(self, client, db_session, sample_agent):
        """Test that suspended agent is denied even with valid key."""
        sample_agent.status = AgentStatus.SUSPENDED
        await db_session.commit()

        response = await client.post(
            "/api/v1/rules/evaluate",
            headers={"X-API-Key": sample_agent.api_key},
            json={
                "agent_id": sample_agent.external_id,
                "request_type": "command",
                "command": "ls -la",
            },
        )
        assert response.status_code == 200
        assert response.json()["decision"] == "deny"
        assert "suspended" in response.json()["reason"].lower()

    @pytest.mark.asyncio
    async def test_api_key_updates_last_used(self, client, db_session, sample_agent):
        """Test that using API key updates last_used timestamp."""
        assert sample_agent.api_key_last_used is None

        await client.post(
            "/api/v1/rules/evaluate",
            headers={"X-API-Key": sample_agent.api_key},
            json={
                "agent_id": sample_agent.external_id,
                "request_type": "command",
                "command": "ls -la",
            },
        )

        await db_session.refresh(sample_agent)
        assert sample_agent.api_key_last_used is not None


class TestAgentAPIKeyEndpoints:
    """Tests for API key management endpoints."""

    @pytest.mark.asyncio
    async def test_create_agent_returns_api_key(self, client):
        """Test that creating an agent returns the API key."""
        response = await client.post(
            "/api/v1/agents",
            json={
                "name": "Test Agent",
                "external_id": f"test-agent-{uuid4().hex[:8]}",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert "api_key" in data
        assert data["api_key"].startswith("snp_")

    @pytest.mark.asyncio
    async def test_get_agent_returns_api_key(self, client, sample_agent):
        """Test that getting an agent returns the API key."""
        response = await client.get(f"/api/v1/agents/{sample_agent.id}")
        assert response.status_code == 200
        data = response.json()
        assert "api_key" in data
        assert data["api_key"] == sample_agent.api_key

    @pytest.mark.asyncio
    async def test_regenerate_api_key(self, client, sample_agent):
        """Test regenerating an agent's API key."""
        old_key = sample_agent.api_key

        response = await client.post(
            f"/api/v1/agents/{sample_agent.id}/regenerate-key",
        )
        assert response.status_code == 200
        data = response.json()
        assert "api_key" in data
        assert data["api_key"].startswith("snp_")
        assert data["api_key"] != old_key


class TestLearningMode:
    """Tests for learning mode behavior."""

    @pytest.mark.asyncio
    async def test_learning_mode_allows_denied_request(self, client, sample_agent, db_session):
        """Test that learning mode allows requests that would be denied."""
        import os
        from app.models.rules import Rule, RuleType, RuleAction
        from app.config import get_settings

        # Enable learning mode for this test
        original_value = os.environ.get("LEARNING_MODE", "false")
        os.environ["LEARNING_MODE"] = "true"
        get_settings.cache_clear()

        try:
            # Create a deny rule
            rule = Rule(
                id=uuid4(),
                name="Block rm",
                agent_id=sample_agent.id,
                rule_type=RuleType.COMMAND_DENYLIST,
                action=RuleAction.DENY,
                priority=100,
                parameters={"patterns": ["^rm\\s"]},
                is_active=True,
            )
            db_session.add(rule)
            await db_session.commit()

            # With learning mode on, should allow but mark as would_have_blocked
            response = await client.post(
                "/api/v1/rules/evaluate",
                headers={"X-API-Key": sample_agent.api_key},
                json={
                    "agent_id": sample_agent.external_id,
                    "request_type": "command",
                    "command": "rm -rf /tmp/test",
                },
            )
            assert response.status_code == 200
            data = response.json()
            # In learning mode, should be allowed
            assert data["decision"] == "allow"
            assert "LEARNING MODE" in data.get("reason", "")
        finally:
            # Restore original setting
            os.environ["LEARNING_MODE"] = original_value
            get_settings.cache_clear()
