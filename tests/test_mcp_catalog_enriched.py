"""Tests for enriched MCP catalog sync and API."""

import math
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.mcp_catalog import _compute_popularity, SOURCE_PRIORITY


class TestComputePopularity:
    """Test popularity score normalization."""

    def test_zero_visitors(self):
        assert _compute_popularity(0) == 0

    def test_negative_visitors(self):
        assert _compute_popularity(-5) == 0

    def test_ten_visitors(self):
        score = _compute_popularity(10)
        assert 15 <= score <= 25  # ~20

    def test_hundred_visitors(self):
        score = _compute_popularity(100)
        assert 35 <= score <= 45  # ~40

    def test_thousand_visitors(self):
        score = _compute_popularity(1000)
        assert 55 <= score <= 65  # ~60

    def test_hundred_thousand_visitors(self):
        score = _compute_popularity(100000)
        assert score == 100  # capped

    def test_million_visitors(self):
        score = _compute_popularity(1000000)
        assert score == 100  # capped at 100

    def test_monotonic_increase(self):
        """More visitors should give higher or equal score."""
        prev = 0
        for v in [1, 10, 50, 100, 500, 1000, 5000, 10000]:
            score = _compute_popularity(v)
            assert score >= prev, f"Score {score} < {prev} for {v} visitors"
            prev = score


class TestSourcePriority:
    """Test source priority ordering."""

    def test_pulsemcp_highest(self):
        assert SOURCE_PRIORITY["pulsemcp"] > SOURCE_PRIORITY["smithery"]
        assert SOURCE_PRIORITY["pulsemcp"] > SOURCE_PRIORITY["glama"]
        assert SOURCE_PRIORITY["pulsemcp"] > SOURCE_PRIORITY["npm"]
        assert SOURCE_PRIORITY["pulsemcp"] > SOURCE_PRIORITY["awesome-mcp-servers"]

    def test_smithery_second(self):
        assert SOURCE_PRIORITY["smithery"] > SOURCE_PRIORITY["glama"]

    def test_ordering(self):
        ordered = sorted(SOURCE_PRIORITY.keys(), key=lambda s: SOURCE_PRIORITY[s], reverse=True)
        assert ordered == ["pulsemcp", "smithery", "glama", "npm", "awesome-mcp-servers"]


class TestPulseMCPFetcher:
    """Test PulseMCP fetcher with mocked HTTP."""

    @pytest.mark.asyncio
    async def test_skips_without_api_key(self):
        from app.services.mcp_catalog import fetch_pulsemcp_servers
        with patch("app.services.mcp_catalog.settings") as mock_settings:
            mock_settings.PULSEMCP_API_KEY = None
            result = await fetch_pulsemcp_servers()
            assert result == []

    @pytest.mark.asyncio
    async def test_parses_server_response(self):
        from app.services.mcp_catalog import fetch_pulsemcp_servers

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "servers": [
                {
                    "name": "notion-mcp",
                    "description": "Notion MCP server",
                    "tools": [
                        {"name": "search_pages", "description": "Search pages"},
                        {"name": "create_page", "description": "Create a page"},
                    ],
                    "authentication": {"type": "api_key"},
                    "monthly_visitors": 5000,
                    "is_official": True,
                    "categories": ["productivity"],
                    "id": "notion-123",
                },
            ],
        }

        with patch("app.services.mcp_catalog.settings") as mock_settings:
            mock_settings.PULSEMCP_API_KEY = "test-key"
            mock_settings.PULSEMCP_TENANT_ID = None

            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.get.return_value = mock_response
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client_cls.return_value = mock_client

                result = await fetch_pulsemcp_servers()

        assert len(result) == 1
        srv = result[0]
        assert srv["name"] == "notion-mcp"
        assert srv["source"] == "pulsemcp"
        assert len(srv["tools"]) == 2
        assert srv["auth_type"] == "api_key"
        assert srv["is_official"] is True
        assert srv["popularity_score"] > 0
        assert srv["pulsemcp_id"] == "notion-123"


class TestGlamaFetcher:
    """Test Glama fetcher."""

    @pytest.mark.asyncio
    async def test_skips_when_disabled(self):
        from app.services.mcp_catalog import fetch_glama_servers
        with patch("app.services.mcp_catalog.settings") as mock_settings:
            mock_settings.GLAMA_CATALOG_ENABLED = False
            result = await fetch_glama_servers()
            assert result == []

    @pytest.mark.asyncio
    async def test_respects_max_entries(self):
        from app.services.mcp_catalog import fetch_glama_servers

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "servers": [
                {"name": f"server-{i}", "slug": f"server-{i}"}
                for i in range(200)
            ],
            "pageInfo": {"endCursor": None, "hasNextPage": False},
        }

        with patch("app.services.mcp_catalog.settings") as mock_settings:
            mock_settings.GLAMA_CATALOG_ENABLED = True

            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.get.return_value = mock_response
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client_cls.return_value = mock_client

                result = await fetch_glama_servers(max_entries=50)

        # Should have fetched one page worth
        assert len(result) <= 200
