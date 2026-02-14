"""Tests for the integrations API router.

Tests active-packs, disable-server-rules, and traffic discovery endpoints.
"""

import pytest
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from httpx import AsyncClient

from app.data.rule_packs import RULE_PACKS
from app.models.audit_logs import AuditLog, AuditAction
from app.models.rules import Rule


class TestActivePacks:
    """Tests for GET /api/v1/integrations/active-packs."""

    @pytest.mark.asyncio
    async def test_returns_empty_when_no_rules(self, client: AsyncClient):
        """Empty DB returns empty list."""
        response = await client.get("/api/v1/integrations/active-packs")
        assert response.status_code == 200
        assert response.json() == []

    @pytest.mark.asyncio
    async def test_groups_rule_pack_rules(self, client: AsyncClient, db_session: AsyncSession):
        """Rules with source='rule_pack' grouped by source_reference."""
        rule1 = Rule(
            id=uuid4(),
            name="GitHub - Read Repos & Issues",
            rule_type="command_allowlist",
            action="allow",
            priority=100,
            parameters={"patterns": ["^mcp__github__get.*"]},
            is_active=True,
            source="rule_pack",
            source_reference="github",
        )
        rule2 = Rule(
            id=uuid4(),
            name="GitHub - Block Destructive Operations",
            rule_type="command_denylist",
            action="deny",
            priority=200,
            parameters={"patterns": ["^mcp__github__delete.*"]},
            is_active=True,
            source="rule_pack",
            source_reference="github",
        )
        db_session.add(rule1)
        db_session.add(rule2)
        await db_session.commit()

        response = await client.get("/api/v1/integrations/active-packs")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["pack_id"] == "github"
        assert data[0]["display_name"] == "GitHub"
        assert data[0]["rule_count"] == 2

    @pytest.mark.asyncio
    async def test_groups_traffic_discovery_rules(self, client: AsyncClient, db_session: AsyncSession):
        """Rules with source='traffic_discovery' grouped by source_reference."""
        for i in range(3):
            rule = Rule(
                id=uuid4(),
                name=f"notion rule {i}",
                rule_type="command_allowlist",
                action="allow",
                priority=100,
                parameters={},
                is_active=True,
                source="traffic_discovery",
                source_reference="mcp_server:notion",
            )
            db_session.add(rule)
        await db_session.commit()

        response = await client.get("/api/v1/integrations/active-packs")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["source_reference"] == "mcp_server:notion"
        assert data[0]["rule_count"] == 3
        assert data[0]["display_name"] == "Notion"

    @pytest.mark.asyncio
    async def test_excludes_deleted_rules(self, client: AsyncClient, db_session: AsyncSession):
        """Soft-deleted rules not included."""
        rule = Rule(
            id=uuid4(),
            name="Deleted rule",
            rule_type="command_allowlist",
            action="allow",
            priority=100,
            parameters={},
            is_active=False,
            is_deleted=True,
            source="rule_pack",
            source_reference="github",
        )
        db_session.add(rule)
        await db_session.commit()

        response = await client.get("/api/v1/integrations/active-packs")
        assert response.status_code == 200
        assert response.json() == []

    @pytest.mark.asyncio
    async def test_excludes_non_pack_sources(self, client: AsyncClient, db_session: AsyncSession):
        """Rules with other source values not included."""
        rule = Rule(
            id=uuid4(),
            name="Manual rule",
            rule_type="command_allowlist",
            action="allow",
            priority=100,
            parameters={},
            is_active=True,
            source="manual",
            source_reference="test",
        )
        db_session.add(rule)
        await db_session.commit()

        response = await client.get("/api/v1/integrations/active-packs")
        assert response.status_code == 200
        assert response.json() == []


class TestDisableServerRules:
    """Tests for POST /api/v1/integrations/traffic/disable-server-rules."""

    @pytest.mark.asyncio
    async def test_soft_deletes_rule_pack_rules(self, client: AsyncClient, db_session: AsyncSession):
        """Disabling by pack_id soft-deletes rules with that source_reference."""
        rule = Rule(
            id=uuid4(),
            name="GitHub - Read",
            rule_type="command_allowlist",
            action="allow",
            priority=100,
            parameters={},
            is_active=True,
            source="rule_pack",
            source_reference="github",
        )
        db_session.add(rule)
        await db_session.commit()

        response = await client.post(
            "/api/v1/integrations/traffic/disable-server-rules",
            json={"server_name": "github"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["rules_deleted"] == 1

        # Verify soft-delete
        await db_session.refresh(rule)
        assert rule.is_active is False
        assert rule.is_deleted is True
        assert rule.deleted_at is not None

    @pytest.mark.asyncio
    async def test_soft_deletes_traffic_discovery_rules(self, client: AsyncClient, db_session: AsyncSession):
        """Disabling by mcp_server:<name> soft-deletes traffic discovery rules."""
        rule = Rule(
            id=uuid4(),
            name="notion auto rule",
            rule_type="command_allowlist",
            action="allow",
            priority=100,
            parameters={},
            is_active=True,
            source="traffic_discovery",
            source_reference="mcp_server:notion",
        )
        db_session.add(rule)
        await db_session.commit()

        response = await client.post(
            "/api/v1/integrations/traffic/disable-server-rules",
            json={"server_name": "notion"},
        )
        assert response.status_code == 200
        assert response.json()["rules_deleted"] == 1

    @pytest.mark.asyncio
    async def test_creates_audit_log(self, client: AsyncClient, db_session: AsyncSession):
        """Disabling creates an audit log entry."""
        rule = Rule(
            id=uuid4(),
            name="Slack - Read",
            rule_type="command_allowlist",
            action="allow",
            priority=100,
            parameters={},
            is_active=True,
            source="rule_pack",
            source_reference="slack",
        )
        db_session.add(rule)
        await db_session.commit()

        await client.post(
            "/api/v1/integrations/traffic/disable-server-rules",
            json={"server_name": "slack"},
        )

        result = await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == AuditAction.RULE_DEACTIVATED,
            )
        )
        logs = list(result.scalars().all())
        assert len(logs) >= 1
        assert "slack" in logs[-1].message.lower()

    @pytest.mark.asyncio
    async def test_not_found_returns_404(self, client: AsyncClient):
        """Disabling with no matching rules returns 404."""
        response = await client.post(
            "/api/v1/integrations/traffic/disable-server-rules",
            json={"server_name": "nonexistent-server-xyz"},
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_empty_name_returns_400(self, client: AsyncClient):
        """Empty server_name returns 400."""
        response = await client.post(
            "/api/v1/integrations/traffic/disable-server-rules",
            json={"server_name": "  "},
        )
        assert response.status_code == 400


class TestCreateServerRulesSourceValues:
    """Tests for source/source_reference values in create-server-rules."""

    @pytest.mark.asyncio
    async def test_curated_server_uses_rule_pack_source(self, client: AsyncClient, db_session: AsyncSession):
        """Known server with curated pack sets source='rule_pack'."""
        response = await client.post(
            "/api/v1/integrations/traffic/create-server-rules",
            json={"server_name": "github"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["source"] == "rule_pack"
        # GitHub pack has 4 rules
        assert data["rules_created"] == len(RULE_PACKS["github"]["rules"])

        # Verify source in DB
        result = await db_session.execute(
            select(Rule).where(
                Rule.source == "rule_pack",
                Rule.source_reference == "github",
            )
        )
        rules = list(result.scalars().all())
        assert len(rules) == data["rules_created"]

    @pytest.mark.asyncio
    async def test_unknown_server_uses_traffic_discovery_source(self, client: AsyncClient, db_session: AsyncSession):
        """Unknown server sets source='traffic_discovery'."""
        response = await client.post(
            "/api/v1/integrations/traffic/create-server-rules",
            json={"server_name": "my_custom_thing"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["source"] == "traffic_discovery"
        assert data["rules_created"] == 3

        result = await db_session.execute(
            select(Rule).where(
                Rule.source == "traffic_discovery",
                Rule.source_reference == "mcp_server:my_custom_thing",
            )
        )
        rules = list(result.scalars().all())
        assert len(rules) == 3
