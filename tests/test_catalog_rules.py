"""Tests for catalog-based rule generation."""

import re
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.catalog_rule_generator import generate_rules_from_catalog, _build_tool_pattern


class TestBuildToolPattern:
    """Test regex pattern building."""

    def test_basic_pattern(self):
        pattern = _build_tool_pattern("github", "github", ["get_repo", "list_issues"])
        regex = re.compile(pattern)
        assert regex.match("mcp__github__get_repo")
        assert regex.match("mcp__github__list_issues")
        assert regex.match("github_get_repo")
        assert not regex.match("mcp__github__create_repo")
        assert not regex.match("mcp__gitlab__get_repo")

    def test_hyphen_name(self):
        pattern = _build_tool_pattern("brave_search", "brave-search", ["search"])
        regex = re.compile(pattern)
        assert regex.match("mcp__brave_search__search")
        assert regex.match("mcp__brave-search__search")
        assert regex.match("brave_search_search")

    def test_single_tool(self):
        pattern = _build_tool_pattern("notion", "notion", ["search_pages"])
        regex = re.compile(pattern)
        assert regex.match("mcp__notion__search_pages")
        assert not regex.match("mcp__notion__create_page")


class TestGenerateRulesFromCatalog:
    """Test catalog rule generation with mock DB."""

    @pytest.fixture
    def mock_db(self):
        db = AsyncMock()
        return db

    def _make_catalog_entry(self, tools=None, name="test-server"):
        """Create a mock MCPServerCatalog entry."""
        entry = MagicMock()
        entry.name = name
        entry.normalized_name = name.lower()
        entry.tools = tools or []
        entry.trust_tier = "community"
        entry.auth_type = "api_key"
        entry.tools_count = len(tools or [])
        return entry

    @pytest.mark.asyncio
    async def test_returns_none_when_no_server(self, mock_db):
        """No catalog entry → return None."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result

        result = await generate_rules_from_catalog(mock_db, "unknown-server")
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_when_no_tools(self, mock_db):
        """Server exists but no tools → return None."""
        entry = self._make_catalog_entry(tools=[])
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = entry
        mock_db.execute.return_value = mock_result

        result = await generate_rules_from_catalog(mock_db, "test-server")
        assert result is None

    @pytest.mark.asyncio
    async def test_generates_rules_for_mixed_tools(self, mock_db):
        """Server with read/write/delete tools → generates 4 rules."""
        tools = [
            {"name": "get_item", "description": "Get an item"},
            {"name": "list_items", "description": "List items"},
            {"name": "create_item", "description": "Create an item"},
            {"name": "update_item", "description": "Update an item"},
            {"name": "delete_item", "description": "Delete an item"},
        ]
        entry = self._make_catalog_entry(tools=tools, name="myserver")

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = entry
        mock_db.execute.return_value = mock_result

        result = await generate_rules_from_catalog(mock_db, "myserver")
        assert result is not None
        assert len(result) == 4  # read, write, delete, catchall

        # Check rule types
        actions = [r["action"] for r in result]
        assert "allow" in actions
        assert "require_approval" in actions
        assert "deny" in actions

        # Verify read rule matches actual tool names
        read_rule = [r for r in result if r["action"] == "allow"][0]
        pattern = read_rule["parameters"]["patterns"][0]
        regex = re.compile(pattern)
        assert regex.match("mcp__myserver__get_item")
        assert regex.match("mcp__myserver__list_items")
        assert not regex.match("mcp__myserver__create_item")

    @pytest.mark.asyncio
    async def test_generates_rules_for_read_only_tools(self, mock_db):
        """Server with only read tools → 2 rules (read + catchall)."""
        tools = [
            {"name": "search", "description": "Search"},
            {"name": "list_all", "description": "List all"},
        ]
        entry = self._make_catalog_entry(tools=tools, name="searchsvc")

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = entry
        mock_db.execute.return_value = mock_result

        result = await generate_rules_from_catalog(mock_db, "searchsvc")
        assert result is not None
        assert len(result) == 2  # read + catchall
        assert result[0]["action"] == "allow"

    @pytest.mark.asyncio
    async def test_empty_server_name(self, mock_db):
        result = await generate_rules_from_catalog(mock_db, "")
        assert result is None

    @pytest.mark.asyncio
    async def test_catalog_description_in_rules(self, mock_db):
        """Rule descriptions include trust tier and auth type."""
        tools = [{"name": "get_data"}]
        entry = self._make_catalog_entry(tools=tools, name="myapi")
        entry.trust_tier = "verified"
        entry.auth_type = "oauth"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = entry
        mock_db.execute.return_value = mock_result

        result = await generate_rules_from_catalog(mock_db, "myapi")
        assert result is not None
        assert "[verified]" in result[0]["description"]
        assert "(auth: oauth)" in result[0]["description"]
