"""Tests for agent API endpoints."""

import pytest
from uuid import uuid4


class TestAgentEndpoints:
    """Tests for /api/v1/agents endpoints."""

    @pytest.mark.asyncio
    async def test_list_agents_empty(self, client):
        """Test listing agents when none exist."""
        response = await client.get("/api/v1/agents")
        assert response.status_code == 200
        data = response.json()
        assert data["items"] == []
        assert data["total"] == 0

    @pytest.mark.asyncio
    async def test_create_agent(self, client):
        """Test creating a new agent."""
        agent_data = {
            "name": "Test Agent",
            "external_id": f"test-{uuid4().hex[:8]}",
            "description": "A test agent",
            "trust_level": "untrusted",
            "allowed_origins": ["http://localhost:8000"],
            "require_localhost_only": True,
        }

        response = await client.post("/api/v1/agents", json=agent_data)
        assert response.status_code == 201

        data = response.json()
        assert data["name"] == agent_data["name"]
        assert data["external_id"] == agent_data["external_id"]
        assert data["status"] == "pending"
        assert data["trust_level"] == "untrusted"
        assert "id" in data

    @pytest.mark.asyncio
    async def test_create_agent_duplicate_external_id(self, client):
        """Test that duplicate external_id is rejected."""
        external_id = f"test-{uuid4().hex[:8]}"
        agent_data = {
            "name": "Test Agent 1",
            "external_id": external_id,
        }

        # First creation should succeed
        response = await client.post("/api/v1/agents", json=agent_data)
        assert response.status_code == 201

        # Second creation with same external_id should fail
        agent_data["name"] = "Test Agent 2"
        response = await client.post("/api/v1/agents", json=agent_data)
        assert response.status_code == 409

    @pytest.mark.asyncio
    async def test_get_agent(self, client, sample_agent):
        """Test getting an agent by ID."""
        response = await client.get(f"/api/v1/agents/{sample_agent.id}")
        assert response.status_code == 200

        data = response.json()
        assert data["id"] == str(sample_agent.id)
        assert data["name"] == sample_agent.name

    @pytest.mark.asyncio
    async def test_get_agent_not_found(self, client):
        """Test getting a non-existent agent."""
        fake_id = uuid4()
        response = await client.get(f"/api/v1/agents/{fake_id}")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_update_agent(self, client, sample_agent):
        """Test updating an agent."""
        update_data = {
            "name": "Updated Agent Name",
            "description": "Updated description",
        }

        response = await client.put(
            f"/api/v1/agents/{sample_agent.id}",
            json=update_data,
        )
        assert response.status_code == 200

        data = response.json()
        assert data["name"] == update_data["name"]
        assert data["description"] == update_data["description"]

    @pytest.mark.asyncio
    async def test_delete_agent(self, client, sample_agent):
        """Test soft deleting an agent."""
        response = await client.delete(f"/api/v1/agents/{sample_agent.id}")
        assert response.status_code == 204

        # Verify it's not returned in list
        response = await client.get("/api/v1/agents")
        data = response.json()
        agent_ids = [a["id"] for a in data["items"]]
        assert str(sample_agent.id) not in agent_ids

    @pytest.mark.asyncio
    async def test_suspend_agent(self, client, sample_agent):
        """Test suspending an agent."""
        response = await client.post(f"/api/v1/agents/{sample_agent.id}/suspend")
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "suspended"

    @pytest.mark.asyncio
    async def test_activate_agent(self, client, sample_agent):
        """Test activating an agent."""
        # First suspend
        await client.post(f"/api/v1/agents/{sample_agent.id}/suspend")

        # Then activate
        response = await client.post(f"/api/v1/agents/{sample_agent.id}/activate")
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "active"

    @pytest.mark.asyncio
    async def test_quarantine_agent(self, client, sample_agent):
        """Test quarantining an agent."""
        response = await client.post(
            f"/api/v1/agents/{sample_agent.id}/quarantine",
            params={"reason": "Security concern"},
        )
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "quarantined"

    @pytest.mark.asyncio
    async def test_list_agents_with_filters(self, client, sample_agent):
        """Test listing agents with filters."""
        # Filter by status
        response = await client.get("/api/v1/agents?status=active")
        assert response.status_code == 200
        data = response.json()
        assert all(a["status"] == "active" for a in data["items"])

        # Filter by trust level
        response = await client.get("/api/v1/agents?trust_level=standard")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_agent_status_endpoint(self, client, sample_agent):
        """Test getting real-time agent status."""
        response = await client.get(f"/api/v1/agents/{sample_agent.id}/status")
        assert response.status_code == 200

        data = response.json()
        assert data["id"] == str(sample_agent.id)
        assert "active_rules_count" in data
        assert "recent_violations_count" in data
