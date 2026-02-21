"""Tests for extension config sync service and router."""

import json
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.services.extension_config import (
    _build_service_registry,
    _extract_visit_domains,
    build_config_bundle,
    cache_bundle,
    compute_etag,
    get_or_build_bundle,
    invalidate_bundle,
)


# ---------------------------------------------------------------------------
# Service layer tests
# ---------------------------------------------------------------------------


class TestBuildServiceRegistry:
    """Test static registry building."""

    def test_returns_list(self):
        registry = _build_service_registry()
        assert isinstance(registry, list)
        assert len(registry) > 0

    def test_entries_have_required_fields(self):
        registry = _build_service_registry()
        for entry in registry:
            assert "source" in entry
            assert "label" in entry
            assert "domains" in entry
            assert "tier" in entry
            assert "risk" in entry
            assert "category" in entry

    def test_tier_classification(self):
        registry = _build_service_registry()
        by_source = {e["source"]: e for e in registry}

        # Tier 1 services
        assert by_source["chatgpt"]["tier"] == 1
        assert by_source["claude"]["tier"] == 1
        assert by_source["deepseek"]["tier"] == 1

        # Tier 3 services
        if "together" in by_source:
            assert by_source["together"]["tier"] == 3
        if "character_ai" in by_source:
            assert by_source["character_ai"]["tier"] == 3

    def test_includes_data_residency(self):
        registry = _build_service_registry()
        for entry in registry:
            assert "data_residency" in entry

    def test_deepseek_is_high_risk(self):
        registry = _build_service_registry()
        by_source = {e["source"]: e for e in registry}
        assert by_source["deepseek"]["risk"] == "high"


class TestExtractVisitDomains:
    """Test Tier 3 domain extraction."""

    def test_extracts_tier3_only(self):
        registry = [
            {"source": "chatgpt", "tier": 1, "domains": ["chatgpt.com"]},
            {"source": "mistral", "tier": 2, "domains": ["chat.mistral.ai"]},
            {"source": "together", "tier": 3, "domains": ["together.xyz"]},
        ]
        domains = _extract_visit_domains(registry)
        assert "together.xyz" in domains
        assert "chatgpt.com" not in domains
        assert "chat.mistral.ai" not in domains

    def test_deduplicates_and_sorts(self):
        registry = [
            {"source": "a", "tier": 3, "domains": ["z.com", "a.com"]},
            {"source": "b", "tier": 3, "domains": ["a.com", "m.com"]},
        ]
        domains = _extract_visit_domains(registry)
        assert domains == ["a.com", "m.com", "z.com"]

    def test_empty_registry(self):
        assert _extract_visit_domains([]) == []


class TestComputeEtag:
    """Test ETag computation."""

    def test_deterministic(self):
        bundle = {"service_registry": [{"source": "test"}], "blocked_services": []}
        etag1 = compute_etag(bundle)
        etag2 = compute_etag(bundle)
        assert etag1 == etag2

    def test_config_version_ignored(self):
        """ETag should not change when only config_version changes."""
        bundle1 = {"config_version": "2026-01-01", "service_registry": []}
        bundle2 = {"config_version": "2026-02-01", "service_registry": []}
        assert compute_etag(bundle1) == compute_etag(bundle2)

    def test_content_change_changes_etag(self):
        bundle1 = {"service_registry": [], "blocked_services": []}
        bundle2 = {"service_registry": [], "blocked_services": ["deepseek"]}
        assert compute_etag(bundle1) != compute_etag(bundle2)

    def test_etag_is_hex_string(self):
        etag = compute_etag({"data": "test"})
        assert len(etag) == 16
        assert all(c in "0123456789abcdef" for c in etag)


class TestBuildConfigBundle:
    """Test config bundle building."""

    @pytest.mark.asyncio
    async def test_returns_all_keys(self):
        db = AsyncMock()
        bundle = await build_config_bundle(db, org_id=None)
        assert "config_version" in bundle
        assert "sync_interval_seconds" in bundle
        assert "service_registry" in bundle
        assert "blocked_services" in bundle
        assert "feature_flags" in bundle
        assert "visit_domains" in bundle

    @pytest.mark.asyncio
    async def test_default_no_blocked_services(self):
        db = AsyncMock()
        bundle = await build_config_bundle(db, org_id=None)
        assert bundle["blocked_services"] == []

    @pytest.mark.asyncio
    async def test_default_feature_flags(self):
        db = AsyncMock()
        bundle = await build_config_bundle(db, org_id=None)
        assert bundle["feature_flags"]["pii_scanning"] is True
        assert bundle["feature_flags"]["clipboard_monitoring"] is True
        assert bundle["feature_flags"]["shadow_ai_tracking"] is True
        assert bundle["feature_flags"]["pii_blocking_mode"] == "warn"

    @pytest.mark.asyncio
    async def test_service_registry_populated(self):
        db = AsyncMock()
        bundle = await build_config_bundle(db, org_id=None)
        assert len(bundle["service_registry"]) > 0

    @pytest.mark.asyncio
    async def test_visit_domains_populated(self):
        db = AsyncMock()
        bundle = await build_config_bundle(db, org_id=None)
        # Visit domains come from tier 3 services
        assert isinstance(bundle["visit_domains"], list)

    @pytest.mark.asyncio
    async def test_org_blocked_services_merged(self):
        """Org settings should override blocked_services."""
        org_id = uuid4()
        mock_org = MagicMock()
        mock_org.settings = {
            "extension_config": {
                "blocked_services": ["deepseek", "chatgpt"],
            }
        }

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_org

        db = AsyncMock()
        db.execute.return_value = mock_result

        bundle = await build_config_bundle(db, org_id=org_id)
        assert bundle["blocked_services"] == ["deepseek", "chatgpt"]

    @pytest.mark.asyncio
    async def test_org_feature_flags_merged(self):
        """Org feature flags should merge with defaults."""
        org_id = uuid4()
        mock_org = MagicMock()
        mock_org.settings = {
            "extension_config": {
                "feature_flags": {"pii_scanning": False, "pii_blocking_mode": "block"},
            }
        }

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_org

        db = AsyncMock()
        db.execute.return_value = mock_result

        bundle = await build_config_bundle(db, org_id=org_id)
        assert bundle["feature_flags"]["pii_scanning"] is False
        assert bundle["feature_flags"]["pii_blocking_mode"] == "block"
        # Non-overridden flags keep defaults
        assert bundle["feature_flags"]["clipboard_monitoring"] is True

    @pytest.mark.asyncio
    async def test_org_sync_interval_override(self):
        org_id = uuid4()
        mock_org = MagicMock()
        mock_org.settings = {
            "extension_config": {
                "sync_interval_seconds": 1800,
            }
        }

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_org

        db = AsyncMock()
        db.execute.return_value = mock_result

        bundle = await build_config_bundle(db, org_id=org_id)
        assert bundle["sync_interval_seconds"] == 1800

    @pytest.mark.asyncio
    async def test_org_not_found_returns_defaults(self):
        org_id = uuid4()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None

        db = AsyncMock()
        db.execute.return_value = mock_result

        bundle = await build_config_bundle(db, org_id=org_id)
        assert bundle["blocked_services"] == []


class TestCacheAndRetrieve:
    """Test Redis caching flow."""

    @pytest.mark.asyncio
    async def test_cache_bundle_returns_etag(self):
        redis = AsyncMock()
        bundle = {"service_registry": [], "blocked_services": []}
        etag = await cache_bundle(None, bundle, redis)
        assert isinstance(etag, str)
        assert len(etag) == 16
        redis.set.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_or_build_uses_cache(self):
        """When cache hit, should not call build_config_bundle."""
        cached_bundle = {"service_registry": [{"source": "test"}], "blocked_services": []}
        cached_etag = compute_etag(cached_bundle)
        cached_payload = json.dumps({"bundle": cached_bundle, "etag": cached_etag})

        redis = AsyncMock()
        redis.get.return_value = cached_payload

        db = AsyncMock()

        bundle, etag = await get_or_build_bundle(db, None, redis)
        assert bundle == cached_bundle
        assert etag == cached_etag
        db.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_or_build_cache_miss_builds(self):
        """When cache miss, should build fresh bundle."""
        redis = AsyncMock()
        redis.get.return_value = None

        db = AsyncMock()

        bundle, etag = await get_or_build_bundle(db, None, redis)
        assert "service_registry" in bundle
        assert isinstance(etag, str)
        # Should have cached the result
        redis.set.assert_called_once()

    @pytest.mark.asyncio
    async def test_invalidate_deletes_key(self):
        org_id = uuid4()
        redis = AsyncMock()

        await invalidate_bundle(org_id, redis)
        redis.delete.assert_called_once_with(f"ext_config:{org_id}")

    @pytest.mark.asyncio
    async def test_invalidate_global(self):
        redis = AsyncMock()

        await invalidate_bundle(None, redis)
        redis.delete.assert_called_once_with("ext_config:global")
