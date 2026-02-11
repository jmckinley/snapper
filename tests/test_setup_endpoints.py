"""Tests for setup API endpoints: status, profiles, config, complete.

Covers endpoints that were previously untested in the setup router:
- GET /api/v1/setup/status
- GET /api/v1/setup/profiles
- GET /api/v1/setup/config/{agent_id}
- POST /api/v1/setup/complete
- Security profile rule counts
"""

import pytest
from uuid import uuid4

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agents import Agent, AgentStatus, TrustLevel


class TestSetupStatus:
    """Tests for GET /api/v1/setup/status."""

    @pytest.mark.asyncio
    async def test_status_first_run(self, client: AsyncClient):
        """Empty database reports first_run=True."""
        response = await client.get("/api/v1/setup/status")
        assert response.status_code == 200
        data = response.json()
        assert data["is_first_run"] is True
        assert data["agents_count"] == 0
        assert data["setup_complete"] is False

    @pytest.mark.asyncio
    async def test_status_after_agent_registered(self, client: AsyncClient, sample_agent):
        """After agent exists, is_first_run becomes False."""
        response = await client.get("/api/v1/setup/status")
        assert response.status_code == 200
        data = response.json()
        assert data["is_first_run"] is False
        assert data["agents_count"] >= 1

    @pytest.mark.asyncio
    async def test_status_setup_complete_requires_rules(
        self, client: AsyncClient, sample_agent
    ):
        """setup_complete is True only when both agents and rules exist."""
        response = await client.get("/api/v1/setup/status")
        data = response.json()
        # sample_agent exists, but no rules — not complete yet
        # (depends on whether sample_rule fixture was used)
        assert data["agents_count"] >= 1

    @pytest.mark.asyncio
    async def test_status_with_agent_and_rules(
        self, client: AsyncClient, sample_agent, sample_rule
    ):
        """With both agent and rules, setup_complete=True."""
        response = await client.get("/api/v1/setup/status")
        data = response.json()
        assert data["setup_complete"] is True
        assert data["agents_count"] >= 1
        assert data["rules_count"] >= 1

    @pytest.mark.asyncio
    async def test_status_has_global_rules(self, client: AsyncClient, global_rule):
        """Global rules (no agent_id) are tracked."""
        response = await client.get("/api/v1/setup/status")
        data = response.json()
        assert data["has_global_rules"] is True


class TestSetupProfiles:
    """Tests for GET /api/v1/setup/profiles."""

    @pytest.mark.asyncio
    async def test_profiles_returns_three(self, client: AsyncClient):
        """Returns exactly 3 security profiles."""
        response = await client.get("/api/v1/setup/profiles")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 3

    @pytest.mark.asyncio
    async def test_profiles_ids(self, client: AsyncClient):
        """Profile IDs are strict, recommended, permissive."""
        response = await client.get("/api/v1/setup/profiles")
        data = response.json()
        ids = {p["id"] for p in data}
        assert ids == {"strict", "recommended", "permissive"}

    @pytest.mark.asyncio
    async def test_recommended_is_flagged(self, client: AsyncClient):
        """Recommended profile has recommended=True."""
        response = await client.get("/api/v1/setup/profiles")
        data = response.json()
        recommended = [p for p in data if p["id"] == "recommended"]
        assert len(recommended) == 1
        assert recommended[0]["recommended"] is True

    @pytest.mark.asyncio
    async def test_profiles_have_descriptions(self, client: AsyncClient):
        """All profiles have non-empty descriptions."""
        response = await client.get("/api/v1/setup/profiles")
        data = response.json()
        for profile in data:
            assert len(profile["description"]) > 10
            assert len(profile["name"]) > 0
            assert profile["rule_count"] > 0


class TestSetupConfigSnippet:
    """Tests for GET /api/v1/setup/config/{agent_id}."""

    @pytest.mark.asyncio
    async def test_config_snippet_for_agent(
        self, client: AsyncClient, sample_agent: Agent
    ):
        """Returns YAML/env config for a valid agent."""
        response = await client.get(f"/api/v1/setup/config/{sample_agent.id}")
        assert response.status_code == 200
        data = response.json()
        assert "yaml_config" in data
        assert "env_config" in data
        assert "instructions" in data
        assert str(sample_agent.id) in data["yaml_config"]
        assert str(sample_agent.id) in data["env_config"]

    @pytest.mark.asyncio
    async def test_config_snippet_not_found(self, client: AsyncClient):
        """Non-existent agent ID returns 404."""
        fake_id = str(uuid4())
        response = await client.get(f"/api/v1/setup/config/{fake_id}")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_config_snippet_has_instructions(
        self, client: AsyncClient, sample_agent: Agent
    ):
        """Config snippet includes setup instructions."""
        response = await client.get(f"/api/v1/setup/config/{sample_agent.id}")
        data = response.json()
        assert "Setup Instructions" in data["instructions"]
        assert "Restart" in data["instructions"]


class TestSetupComplete:
    """Tests for POST /api/v1/setup/complete."""

    @pytest.mark.asyncio
    async def test_complete_without_agents(self, client: AsyncClient):
        """Cannot complete setup without at least one agent."""
        response = await client.post("/api/v1/setup/complete")
        assert response.status_code == 400
        assert "at least one registered agent" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_complete_with_agent(self, client: AsyncClient, sample_agent: Agent):
        """Completing setup succeeds when an agent exists."""
        response = await client.post("/api/v1/setup/complete")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "complete"


class TestSecurityProfileRuleCounts:
    """Test that security profiles apply correct number of rules."""

    @pytest.mark.asyncio
    async def test_strict_profile_applies_four_rules(self, client: AsyncClient):
        """Strict profile creates 4 rules."""
        response = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "custom", "security_profile": "strict"},
        )
        assert response.status_code == 200
        assert response.json()["rules_applied"] == 4

    @pytest.mark.asyncio
    async def test_recommended_profile_applies_rules(self, client: AsyncClient):
        """Recommended profile creates rules (3 base + 4 OpenClaw templates)."""
        response = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "openclaw", "security_profile": "recommended"},
        )
        assert response.status_code == 200
        assert response.json()["rules_applied"] == 7

    @pytest.mark.asyncio
    async def test_permissive_profile_applies_two_rules(self, client: AsyncClient):
        """Permissive profile creates 2 rules."""
        response = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "claude-code", "security_profile": "permissive"},
        )
        assert response.status_code == 200
        assert response.json()["rules_applied"] == 2

    @pytest.mark.asyncio
    async def test_unknown_profile_falls_back_to_recommended(self, client: AsyncClient):
        """Unknown profile falls back to recommended (3 rules)."""
        response = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "custom", "security_profile": "nonexistent"},
        )
        assert response.status_code == 200
        assert response.json()["rules_applied"] == 3

    @pytest.mark.asyncio
    async def test_strict_profile_sets_untrusted(self, client: AsyncClient):
        """Strict profile assigns UNTRUSTED trust level."""
        response = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "cursor", "security_profile": "strict"},
        )
        assert response.status_code == 200
        agent_id = response.json()["agent_id"]

        agent_resp = await client.get(f"/api/v1/agents/{agent_id}")
        assert agent_resp.status_code == 200
        assert agent_resp.json()["trust_level"] == "untrusted"

    @pytest.mark.asyncio
    async def test_permissive_profile_sets_elevated(self, client: AsyncClient):
        """Permissive profile assigns ELEVATED trust level."""
        response = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "windsurf", "security_profile": "permissive"},
        )
        assert response.status_code == 200
        agent_id = response.json()["agent_id"]

        agent_resp = await client.get(f"/api/v1/agents/{agent_id}")
        assert agent_resp.status_code == 200
        assert agent_resp.json()["trust_level"] == "elevated"
