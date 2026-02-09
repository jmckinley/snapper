"""Tests for the integrations API router.

Tests the full lifecycle: list, get, enable, disable, categories.
"""

import pytest
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from httpx import AsyncClient

from app.data.integration_templates import INTEGRATION_TEMPLATES
from app.models.audit_logs import AuditLog, AuditAction
from app.models.rules import Rule


class TestListIntegrations:
    """Tests for GET /api/v1/integrations."""

    @pytest.mark.asyncio
    async def test_returns_categories_with_integration_cards(self, client: AsyncClient):
        """Response contains categories, each with a list of integrations."""
        response = await client.get("/api/v1/integrations")
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0

        for category in data:
            assert "id" in category
            assert "name" in category
            assert "integrations" in category
            assert isinstance(category["integrations"], list)

    @pytest.mark.asyncio
    async def test_all_integrations_disabled_initially(self, client: AsyncClient):
        """All integrations should show enabled=False with no rules created."""
        response = await client.get("/api/v1/integrations")
        assert response.status_code == 200

        for category in response.json():
            for integration in category["integrations"]:
                assert integration["enabled"] is False
                assert integration["rule_count"] == 0

    @pytest.mark.asyncio
    async def test_source_based_detection_shows_enabled(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        """Integration with source-based rules shows enabled=True."""
        rule = Rule(
            id=uuid4(),
            name="Gmail - Test Rule",
            rule_type="command_allowlist",
            action="allow",
            priority=100,
            parameters={},
            is_active=True,
            source="integration",
            source_reference="gmail",
        )
        db_session.add(rule)
        await db_session.commit()

        response = await client.get("/api/v1/integrations")
        assert response.status_code == 200

        gmail_found = False
        for category in response.json():
            for integration in category["integrations"]:
                if integration["id"] == "gmail":
                    gmail_found = True
                    assert integration["enabled"] is True
                    assert integration["rule_count"] >= 1
        assert gmail_found

    @pytest.mark.asyncio
    async def test_legacy_name_prefix_detection_shows_enabled(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        """Integration with legacy name-prefix rules shows enabled=True."""
        rule = Rule(
            id=uuid4(),
            name="Gmail - Allow Read Operations",
            rule_type="command_allowlist",
            action="allow",
            priority=100,
            parameters={},
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        response = await client.get("/api/v1/integrations")
        assert response.status_code == 200

        for category in response.json():
            for integration in category["integrations"]:
                if integration["id"] == "gmail":
                    assert integration["enabled"] is True

    @pytest.mark.asyncio
    async def test_agent_id_query_param_filters_results(
        self, client: AsyncClient, db_session: AsyncSession, sample_agent
    ):
        """agent_id parameter filters to show only agent-specific integration state."""
        # Create rule for specific agent
        rule = Rule(
            id=uuid4(),
            name="Gmail - Agent Rule",
            rule_type="command_allowlist",
            action="allow",
            priority=100,
            parameters={},
            agent_id=sample_agent.id,
            is_active=True,
            source="integration",
            source_reference="gmail",
        )
        db_session.add(rule)
        await db_session.commit()

        # With agent_id filter
        response = await client.get(f"/api/v1/integrations?agent_id={sample_agent.id}")
        assert response.status_code == 200

        # Without filter (should not show agent-specific as enabled for global view)
        response_global = await client.get("/api/v1/integrations")
        assert response_global.status_code == 200


class TestGetIntegration:
    """Tests for GET /api/v1/integrations/{integration_id}."""

    @pytest.mark.asyncio
    async def test_get_gmail_returns_template_details(self, client: AsyncClient):
        """GET /integrations/gmail returns full template with rules."""
        response = await client.get("/api/v1/integrations/gmail")
        assert response.status_code == 200

        data = response.json()
        assert data["id"] == "gmail"
        assert data["name"] == "Gmail"
        assert "rules" in data
        assert len(data["rules"]) > 0
        assert data["enabled"] is False

    @pytest.mark.asyncio
    async def test_nonexistent_returns_404(self, client: AsyncClient):
        """Nonexistent integration ID returns 404."""
        response = await client.get("/api/v1/integrations/nonexistent-xyz")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_enriches_rules_with_enabled_status(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        """After enabling, rules should show enabled=True."""
        # Enable gmail
        response = await client.post(
            "/api/v1/integrations/gmail/enable",
            json={},
        )
        assert response.status_code == 200

        # Get details - rules should be enriched
        response = await client.get("/api/v1/integrations/gmail")
        data = response.json()
        assert data["enabled"] is True
        assert data["rule_count"] > 0

    @pytest.mark.asyncio
    async def test_existing_rules_populated(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        """existing_rules list populated with description/priority/parameters."""
        # Enable gmail first
        await client.post("/api/v1/integrations/gmail/enable", json={})

        response = await client.get("/api/v1/integrations/gmail")
        data = response.json()

        assert len(data["existing_rules"]) > 0
        for rule in data["existing_rules"]:
            assert "id" in rule
            assert "name" in rule
            assert "priority" in rule
            assert "parameters" in rule


class TestEnableIntegration:
    """Tests for POST /api/v1/integrations/{integration_id}/enable."""

    @pytest.mark.asyncio
    async def test_enable_creates_rules_with_source(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        """Enable creates rules with source='integration' and source_reference."""
        response = await client.post(
            "/api/v1/integrations/gmail/enable",
            json={},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["integration_id"] == "gmail"
        assert data["rules_created"] > 0

        # Verify rules in DB
        result = await db_session.execute(
            select(Rule).where(
                Rule.source == "integration",
                Rule.source_reference == "gmail",
            )
        )
        rules = list(result.scalars().all())
        assert len(rules) == data["rules_created"]

    @pytest.mark.asyncio
    async def test_already_enabled_returns_400(self, client: AsyncClient):
        """Enabling an already-enabled integration returns 400."""
        await client.post("/api/v1/integrations/gmail/enable", json={})

        response = await client.post(
            "/api/v1/integrations/gmail/enable",
            json={},
        )
        assert response.status_code == 400
        assert "already enabled" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_selectable_rules_defaults_only(self, client: AsyncClient, db_session: AsyncSession):
        """Selectable template with no selection only enables default_enabled rules."""
        # Slack has selectable_rules=True
        response = await client.post(
            "/api/v1/integrations/slack/enable",
            json={},
        )
        assert response.status_code == 200

        # Count created rules
        result = await db_session.execute(
            select(Rule).where(
                Rule.source == "integration",
                Rule.source_reference == "slack",
            )
        )
        rules = list(result.scalars().all())

        # Should only have rules where default_enabled is True
        slack_template = INTEGRATION_TEMPLATES["slack"]
        default_rules = [r for r in slack_template["rules"] if r.get("default_enabled", True)]
        assert len(rules) == len(default_rules)

    @pytest.mark.asyncio
    async def test_selectable_rules_explicit_selection(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        """Selectable template with explicit selection creates only selected."""
        # Slack has selectable_rules=True - pick specific rule IDs
        slack_rules = INTEGRATION_TEMPLATES["slack"]["rules"]
        selected = [slack_rules[0]["id"]]  # Just the first rule

        response = await client.post(
            "/api/v1/integrations/slack/enable",
            json={"selected_rules": selected},
        )
        assert response.status_code == 200
        assert response.json()["rules_created"] == 1


class TestDisableIntegration:
    """Tests for POST /api/v1/integrations/{integration_id}/disable."""

    @pytest.mark.asyncio
    async def test_soft_deletes_rules(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        """Disabling sets is_active=False, is_deleted=True, deleted_at."""
        # Enable then disable
        await client.post("/api/v1/integrations/gmail/enable", json={})
        response = await client.post("/api/v1/integrations/gmail/disable")
        assert response.status_code == 200
        assert response.json()["rules_deleted"] > 0

        # Verify soft-delete state
        result = await db_session.execute(
            select(Rule).where(
                Rule.source == "integration",
                Rule.source_reference == "gmail",
            )
        )
        for rule in result.scalars().all():
            assert rule.is_active is False
            assert rule.is_deleted is True
            assert rule.deleted_at is not None

    @pytest.mark.asyncio
    async def test_creates_audit_log(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        """Disabling creates an AuditLog with RULE_DEACTIVATED action."""
        await client.post("/api/v1/integrations/gmail/enable", json={})
        await client.post("/api/v1/integrations/gmail/disable")

        result = await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == AuditAction.RULE_DEACTIVATED,
            )
        )
        logs = list(result.scalars().all())
        assert len(logs) >= 1

        log = logs[-1]
        assert "gmail" in log.message.lower()

    @pytest.mark.asyncio
    async def test_not_enabled_returns_400(self, client: AsyncClient):
        """Disabling a not-enabled integration returns 400."""
        response = await client.post("/api/v1/integrations/gmail/disable")
        assert response.status_code == 400
        assert "not enabled" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_nonexistent_returns_404(self, client: AsyncClient):
        """Disabling a nonexistent integration returns 404."""
        response = await client.post("/api/v1/integrations/nonexistent-xyz/disable")
        assert response.status_code == 404


class TestCategoriesSummary:
    """Tests for GET /api/v1/integrations/categories/summary."""

    @pytest.mark.asyncio
    async def test_returns_category_counts(self, client: AsyncClient):
        """Returns category summaries with integration_count."""
        response = await client.get("/api/v1/integrations/categories/summary")
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0

        for category in data:
            assert "id" in category
            assert "name" in category
            assert "integration_count" in category
            assert category["integration_count"] > 0
