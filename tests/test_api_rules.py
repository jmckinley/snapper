"""Tests for rule API endpoints."""

import pytest
from uuid import uuid4


class TestRuleEndpoints:
    """Tests for /api/v1/rules endpoints."""

    @pytest.mark.asyncio
    async def test_list_rules_empty(self, client):
        """Test listing rules when none exist."""
        response = await client.get("/api/v1/rules")
        assert response.status_code == 200
        data = response.json()
        assert data["items"] == []
        assert data["total"] == 0

    @pytest.mark.asyncio
    async def test_create_rule(self, client, sample_agent):
        """Test creating a new rule."""
        rule_data = {
            "name": "Test Rate Limit",
            "description": "A test rate limit rule",
            "agent_id": str(sample_agent.id),
            "rule_type": "rate_limit",
            "action": "deny",
            "priority": 10,
            "parameters": {
                "max_requests": 100,
                "window_seconds": 60,
                "scope": "agent",
            },
            "is_active": True,
            "tags": ["test"],
        }

        response = await client.post("/api/v1/rules", json=rule_data)
        assert response.status_code == 201

        data = response.json()
        assert data["name"] == rule_data["name"]
        assert data["rule_type"] == rule_data["rule_type"]
        assert data["parameters"]["max_requests"] == 100
        assert "id" in data

    @pytest.mark.asyncio
    async def test_create_global_rule(self, client):
        """Test creating a global rule (no agent_id)."""
        rule_data = {
            "name": "Global Credential Protection",
            "rule_type": "credential_protection",
            "action": "deny",
            "priority": 100,
            "parameters": {
                "protected_patterns": [r"\.env$"],
                "block_plaintext_secrets": True,
            },
        }

        response = await client.post("/api/v1/rules", json=rule_data)
        assert response.status_code == 201

        data = response.json()
        assert data["agent_id"] is None
        assert data["is_global"] is True

    @pytest.mark.asyncio
    async def test_get_rule(self, client, sample_rule):
        """Test getting a rule by ID."""
        response = await client.get(f"/api/v1/rules/{sample_rule.id}")
        assert response.status_code == 200

        data = response.json()
        assert data["id"] == str(sample_rule.id)
        assert data["name"] == sample_rule.name

    @pytest.mark.asyncio
    async def test_get_rule_not_found(self, client):
        """Test getting a non-existent rule."""
        fake_id = uuid4()
        response = await client.get(f"/api/v1/rules/{fake_id}")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_update_rule(self, client, sample_rule):
        """Test updating a rule."""
        update_data = {
            "name": "Updated Rule Name",
            "priority": 20,
            "is_active": False,
        }

        response = await client.put(
            f"/api/v1/rules/{sample_rule.id}",
            json=update_data,
        )
        assert response.status_code == 200

        data = response.json()
        assert data["name"] == update_data["name"]
        assert data["priority"] == update_data["priority"]
        assert data["is_active"] is False

    @pytest.mark.asyncio
    async def test_delete_rule(self, client, sample_rule):
        """Test soft deleting a rule."""
        response = await client.delete(f"/api/v1/rules/{sample_rule.id}")
        assert response.status_code == 204

        # Verify it's not returned in list
        response = await client.get("/api/v1/rules")
        data = response.json()
        rule_ids = [r["id"] for r in data["items"]]
        assert str(sample_rule.id) not in rule_ids

    @pytest.mark.asyncio
    async def test_list_rule_templates(self, client):
        """Test listing available rule templates."""
        response = await client.get("/api/v1/rules/templates")
        assert response.status_code == 200

        templates = response.json()
        assert isinstance(templates, list)
        assert len(templates) > 0

        # Check template structure
        template = templates[0]
        assert "id" in template
        assert "name" in template
        assert "rule_type" in template
        assert "default_parameters" in template

    @pytest.mark.asyncio
    async def test_apply_template(self, client, sample_agent):
        """Test applying a rule template."""
        response = await client.post(
            "/api/v1/rules/templates/rate-limit-standard/apply",
            json={"agent_id": str(sample_agent.id)},
        )
        assert response.status_code == 200

        data = response.json()
        assert data["rule_type"] == "rate_limit"
        assert data["agent_id"] == str(sample_agent.id)

    @pytest.mark.asyncio
    async def test_validate_rule(self, client, sample_agent):
        """Test rule validation (dry run)."""
        rule_data = {
            "name": "Test Rule",
            "rule_type": "rate_limit",
            "action": "deny",
            "parameters": {
                "max_requests": 100,
                "window_seconds": 60,
            },
        }

        response = await client.post(
            "/api/v1/rules/validate",
            json={
                "rule": rule_data,
                "test_context": {
                    "agent_id": str(sample_agent.id),
                    "request_type": "api",
                },
            },
        )
        assert response.status_code == 200

        data = response.json()
        assert "is_valid" in data
        assert "validation_errors" in data

    @pytest.mark.asyncio
    async def test_export_rules(self, client, sample_rule):
        """Test exporting rules."""
        response = await client.post(
            "/api/v1/rules/export",
            json={"format": "json"},
        )
        assert response.status_code == 200

        data = response.json()
        assert data["format"] == "json"
        assert data["rules_count"] >= 1
        assert "data" in data

    @pytest.mark.asyncio
    async def test_import_rules(self, client, sample_agent):
        """Test importing rules."""
        rules_to_import = [
            {
                "name": "Imported Rule 1",
                "rule_type": "rate_limit",
                "action": "deny",
                "priority": 10,
                "parameters": {"max_requests": 50, "window_seconds": 60},
                "is_active": True,
                "tags": [],
            }
        ]

        response = await client.post(
            "/api/v1/rules/import",
            json={
                "rules": rules_to_import,
                "dry_run": False,
            },
        )
        assert response.status_code == 200

        data = response.json()
        assert data["imported"] == 1
        assert data["errors"] == []

    @pytest.mark.asyncio
    async def test_list_rules_with_filters(self, client, sample_rule, sample_agent):
        """Test listing rules with filters."""
        # Filter by agent
        response = await client.get(f"/api/v1/rules?agent_id={sample_agent.id}")
        assert response.status_code == 200

        # Filter by rule type
        response = await client.get("/api/v1/rules?rule_type=rate_limit")
        assert response.status_code == 200

        # Filter by active status
        response = await client.get("/api/v1/rules?is_active=true")
        assert response.status_code == 200
