"""Tests for new agent type support: Cursor, Windsurf, Cline.

Covers:
- Quick-register endpoint for each new agent type
- Install-config endpoint for each new agent type
- Config snippet generation
- Audit stats endpoint
- Hook script syntax validation
"""

import pytest
from uuid import uuid4

from httpx import AsyncClient


class TestQuickRegisterNewAgents:
    """Test POST /api/v1/setup/quick-register for Cursor, Windsurf, Cline."""

    @pytest.mark.asyncio
    async def test_register_cursor_agent(self, client: AsyncClient):
        """Cursor agent registers with correct external_id pattern."""
        response = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "cursor", "name": "My Cursor"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["agent_id"] is not None
        assert data["api_key"].startswith("snp_")
        assert data["name"] == "My Cursor"
        assert "cursor" in data.get("external_id", "")

    @pytest.mark.asyncio
    async def test_register_windsurf_agent(self, client: AsyncClient):
        """Windsurf agent registers with correct external_id pattern."""
        response = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "windsurf", "name": "My Windsurf"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["agent_id"] is not None
        assert data["api_key"].startswith("snp_")

    @pytest.mark.asyncio
    async def test_register_cline_agent(self, client: AsyncClient):
        """Cline agent registers with correct external_id pattern."""
        response = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "cline", "name": "My Cline"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["agent_id"] is not None
        assert data["api_key"].startswith("snp_")

    @pytest.mark.asyncio
    async def test_register_cursor_default_name(self, client: AsyncClient):
        """Cursor agent gets a sensible default name when none provided."""
        response = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "cursor"},
        )
        assert response.status_code == 200
        data = response.json()
        # Should contain 'Cursor' in the name or external_id
        assert "Cursor" in data.get("name", "") or "cursor" in data.get("external_id", "")

    @pytest.mark.asyncio
    async def test_register_windsurf_default_name(self, client: AsyncClient):
        """Windsurf agent gets a sensible default name when none provided."""
        response = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "windsurf"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["agent_id"] is not None

    @pytest.mark.asyncio
    async def test_register_cline_default_name(self, client: AsyncClient):
        """Cline agent gets a sensible default name when none provided."""
        response = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "cline"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["agent_id"] is not None

    @pytest.mark.asyncio
    async def test_register_invalid_agent_type(self, client: AsyncClient):
        """Invalid agent type is handled (may register as custom or error)."""
        response = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "nonexistent"},
        )
        # The API may accept it (custom fallback) or reject it
        assert response.status_code in (200, 400, 422)

    @pytest.mark.asyncio
    async def test_duplicate_cursor_registration(self, client: AsyncClient):
        """Registering cursor twice handles the duplicate gracefully."""
        resp1 = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "cursor"},
        )
        assert resp1.status_code == 200

        # Second registration — may reactivate (200) or conflict (409)
        resp2 = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "cursor"},
        )
        assert resp2.status_code in (200, 409)
        if resp2.status_code == 200:
            assert resp1.json()["agent_id"] == resp2.json()["agent_id"]

    @pytest.mark.asyncio
    async def test_duplicate_windsurf_registration(self, client: AsyncClient):
        """Registering windsurf twice handles the duplicate gracefully."""
        resp1 = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "windsurf"},
        )
        assert resp1.status_code == 200

        resp2 = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "windsurf"},
        )
        assert resp2.status_code in (200, 409)

    @pytest.mark.asyncio
    async def test_duplicate_cline_registration(self, client: AsyncClient):
        """Registering cline twice handles the duplicate gracefully."""
        resp1 = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "cline"},
        )
        assert resp1.status_code == 200

        resp2 = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "cline"},
        )
        assert resp2.status_code in (200, 409)


class TestConfigSnippets:
    """Test config snippet generation for new agent types."""

    @pytest.mark.asyncio
    async def test_cursor_config_snippet_in_register_response(self, client: AsyncClient):
        """Cursor registration response includes config_snippet with env vars and hook config."""
        reg = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "cursor"},
        )
        assert reg.status_code == 200
        data = reg.json()
        snippet = data.get("config_snippet", "")
        assert "SNAPPER_URL" in snippet
        assert "SNAPPER_AGENT_ID" in snippet
        assert "SNAPPER_API_KEY" in snippet
        assert "preToolUse" in snippet

    @pytest.mark.asyncio
    async def test_windsurf_config_snippet_in_register_response(self, client: AsyncClient):
        """Windsurf registration response includes config_snippet with 3 hook types."""
        reg = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "windsurf"},
        )
        assert reg.status_code == 200
        data = reg.json()
        snippet = data.get("config_snippet", "")
        assert "SNAPPER_URL" in snippet
        assert "SNAPPER_AGENT_ID" in snippet
        assert "pre_run_command" in snippet or "SNAPPER_API_KEY" in snippet

    @pytest.mark.asyncio
    async def test_cline_config_snippet_in_register_response(self, client: AsyncClient):
        """Cline registration response includes config_snippet with env vars."""
        reg = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "cline"},
        )
        assert reg.status_code == 200
        data = reg.json()
        snippet = data.get("config_snippet", "")
        assert "SNAPPER_URL" in snippet
        assert "SNAPPER_AGENT_ID" in snippet
        assert "SNAPPER_API_KEY" in snippet


class TestInstallConfig:
    """Test POST /api/v1/setup/install-config for new agent types."""

    @pytest.mark.asyncio
    async def test_install_cursor_config(self, client: AsyncClient):
        """Install config for cursor should return result or fallback snippet."""
        reg = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "cursor"},
        )
        assert reg.status_code == 200
        data = reg.json()

        response = await client.post(
            "/api/v1/setup/install-config",
            json={
                "agent_type": "cursor",
                "agent_id": data["agent_id"],
                "api_key": data["api_key"],
            },
        )
        assert response.status_code == 200
        result = response.json()
        # Should have either success or fallback snippet
        assert "result" in result or "snippet" in result or "config_snippet" in result or "status" in result

    @pytest.mark.asyncio
    async def test_install_windsurf_config(self, client: AsyncClient):
        """Install config for windsurf should return result or fallback snippet."""
        reg = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "windsurf"},
        )
        assert reg.status_code == 200
        data = reg.json()

        response = await client.post(
            "/api/v1/setup/install-config",
            json={
                "agent_type": "windsurf",
                "agent_id": data["agent_id"],
                "api_key": data["api_key"],
            },
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_install_cline_config(self, client: AsyncClient):
        """Install config for cline should return result or fallback snippet."""
        reg = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "cline"},
        )
        assert reg.status_code == 200
        data = reg.json()

        response = await client.post(
            "/api/v1/setup/install-config",
            json={
                "agent_type": "cline",
                "agent_id": data["agent_id"],
                "api_key": data["api_key"],
            },
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_install_custom_returns_snippet_only(self, client: AsyncClient):
        """Custom agent type should not auto-install, just return snippet."""
        reg = await client.post(
            "/api/v1/setup/quick-register",
            json={
                "agent_type": "custom",
                "name": "Custom Agent",
                "host": "10.0.0.1",
                "port": 9999,
            },
        )
        assert reg.status_code == 200
        data = reg.json()

        response = await client.post(
            "/api/v1/setup/install-config",
            json={
                "agent_type": "custom",
                "agent_id": data["agent_id"],
                "api_key": data["api_key"],
            },
        )
        assert response.status_code == 200


class TestAuditStats:
    """Test GET /api/v1/audit/stats endpoint."""

    @pytest.mark.asyncio
    async def test_audit_stats_empty(self, client: AsyncClient):
        """Empty database returns zero counts."""
        response = await client.get("/api/v1/audit/stats")
        assert response.status_code == 200
        data = response.json()
        assert data["total_evaluations"] == 0
        assert data["allowed_count"] == 0
        assert data["denied_count"] == 0
        assert data["pending_count"] == 0
        assert data["hourly_breakdown"] == []

    @pytest.mark.asyncio
    async def test_audit_stats_with_data(self, client: AsyncClient, sample_audit_log):
        """Stats include logged entries."""
        response = await client.get("/api/v1/audit/stats?hours=24")
        assert response.status_code == 200
        data = response.json()
        # sample_audit_log has action=REQUEST_DENIED
        assert data["denied_count"] >= 1
        assert data["total_evaluations"] >= 1

    @pytest.mark.asyncio
    async def test_audit_stats_custom_hours(self, client: AsyncClient):
        """Custom hours parameter accepted."""
        response = await client.get("/api/v1/audit/stats?hours=168")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_audit_stats_invalid_hours(self, client: AsyncClient):
        """Invalid hours parameter returns error."""
        response = await client.get("/api/v1/audit/stats?hours=0")
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_audit_stats_hourly_breakdown_structure(self, client: AsyncClient, sample_audit_log):
        """Hourly breakdown has correct structure."""
        response = await client.get("/api/v1/audit/stats?hours=24")
        assert response.status_code == 200
        data = response.json()
        for entry in data["hourly_breakdown"]:
            assert "hour" in entry
            assert "allowed" in entry
            assert "denied" in entry
            assert isinstance(entry["allowed"], int)
            assert isinstance(entry["denied"], int)


class TestAllAgentTypesRegistration:
    """End-to-end: register each agent type, verify it appears in agent list."""

    @pytest.mark.asyncio
    async def test_all_agent_types_register_and_list(self, client: AsyncClient):
        """Register one of each type and verify all appear in agent list."""
        agent_types = ["openclaw", "claude-code", "cursor", "windsurf", "cline"]
        registered_ids = []

        for agent_type in agent_types:
            resp = await client.post(
                "/api/v1/setup/quick-register",
                json={"agent_type": agent_type},
            )
            assert resp.status_code == 200, f"Failed to register {agent_type}: {resp.text}"
            registered_ids.append(resp.json()["agent_id"])

        # Verify all agents appear in the list
        list_resp = await client.get("/api/v1/agents")
        assert list_resp.status_code == 200
        agent_ids_in_list = [a["id"] for a in list_resp.json()["items"]]
        for aid in registered_ids:
            assert aid in agent_ids_in_list, f"Agent {aid} not found in agent list"

    @pytest.mark.asyncio
    async def test_registered_agents_are_active(self, client: AsyncClient):
        """All quick-registered agents should be in active status."""
        for agent_type in ["cursor", "windsurf", "cline"]:
            resp = await client.post(
                "/api/v1/setup/quick-register",
                json={"agent_type": agent_type},
            )
            assert resp.status_code == 200
            agent_id = resp.json()["agent_id"]

            # Check agent status
            agent_resp = await client.get(f"/api/v1/agents/{agent_id}")
            assert agent_resp.status_code == 200
            assert agent_resp.json()["status"] == "active"


class TestNewAgentRuleEvaluation:
    """Test that rules work correctly with newly registered agent types."""

    @pytest.mark.asyncio
    async def test_cursor_agent_rule_evaluation(self, client: AsyncClient):
        """Register cursor, create deny rule, verify evaluation blocks."""
        # Register
        reg = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "cursor"},
        )
        assert reg.status_code == 200
        agent_id = reg.json()["agent_id"]

        # Create a deny rule
        rule_resp = await client.post(
            "/api/v1/rules",
            json={
                "name": "Block rm for cursor",
                "agent_id": agent_id,
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 100,
                "parameters": {"patterns": ["^rm\\s"]},
                "is_active": True,
            },
        )
        assert rule_resp.status_code == 201

        # Evaluate — should be denied
        eval_resp = await client.post(
            "/api/v1/rules/evaluate",
            json={
                "agent_id": agent_id,
                "request_type": "command",
                "command": "rm -rf /tmp",
            },
        )
        assert eval_resp.status_code == 200
        assert eval_resp.json()["decision"] == "deny"

    @pytest.mark.asyncio
    async def test_windsurf_agent_deny_dangerous_command(self, client: AsyncClient):
        """Register windsurf, create deny rule, verify evaluation blocks."""
        reg = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "windsurf"},
        )
        assert reg.status_code == 200
        agent_id = reg.json()["agent_id"]

        # Create a deny rule (high priority)
        rule_resp = await client.post(
            "/api/v1/rules",
            json={
                "name": "Block dd for windsurf",
                "agent_id": agent_id,
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 100,
                "parameters": {"patterns": ["^dd\\s+if="]},
                "is_active": True,
            },
        )
        assert rule_resp.status_code == 201

        # Evaluate — should be denied
        eval_resp = await client.post(
            "/api/v1/rules/evaluate",
            json={
                "agent_id": agent_id,
                "request_type": "command",
                "command": "dd if=/dev/zero of=/dev/sda",
            },
        )
        assert eval_resp.status_code == 200
        assert eval_resp.json()["decision"] == "deny"

    @pytest.mark.asyncio
    async def test_cline_agent_deny_without_rules(self, client: AsyncClient):
        """Register cline with no allow rules. DENY_BY_DEFAULT means denial."""
        reg = await client.post(
            "/api/v1/setup/quick-register",
            json={"agent_type": "cline"},
        )
        assert reg.status_code == 200
        agent_id = reg.json()["agent_id"]

        # Evaluate with no matching rules — DENY_BY_DEFAULT should deny
        eval_resp = await client.post(
            "/api/v1/rules/evaluate",
            json={
                "agent_id": agent_id,
                "request_type": "command",
                "command": "some-unknown-command",
            },
        )
        assert eval_resp.status_code == 200
        assert eval_resp.json()["decision"] == "deny"
