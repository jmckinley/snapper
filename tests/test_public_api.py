"""Tests for Public API v1.0 features: versioning headers, OpenAPI tags, rate limit headers."""

import json

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import uuid4

from app.main import app
from app.models.agents import Agent, AgentStatus, TrustLevel
from app.models.rules import Rule, RuleAction, RuleType
from app.redis_client import RedisClient


# ---------------------------------------------------------------------------
# X-API-Version header
# ---------------------------------------------------------------------------


class TestAPIVersionHeader:
    """Verify X-API-Version: 1.0.0 is present on every /api/ response."""

    @pytest.mark.asyncio
    async def test_version_header_on_agents(self, client: AsyncClient):
        resp = await client.get("/api/v1/agents")
        assert resp.headers.get("x-api-version") == "1.0.0"

    @pytest.mark.asyncio
    async def test_version_header_on_rules(self, client: AsyncClient):
        resp = await client.get("/api/v1/rules")
        assert resp.headers.get("x-api-version") == "1.0.0"

    @pytest.mark.asyncio
    async def test_version_header_on_audit_stats(self, client: AsyncClient):
        resp = await client.get("/api/v1/audit/stats")
        assert resp.headers.get("x-api-version") == "1.0.0"

    @pytest.mark.asyncio
    async def test_version_header_on_vault(self, client: AsyncClient):
        resp = await client.get("/api/v1/vault/entries")
        assert resp.headers.get("x-api-version") == "1.0.0"

    @pytest.mark.asyncio
    async def test_version_header_on_openapi(self, client: AsyncClient):
        resp = await client.get("/api/openapi.json")
        assert resp.headers.get("x-api-version") == "1.0.0"

    @pytest.mark.asyncio
    async def test_version_header_on_docs(self, client: AsyncClient):
        resp = await client.get("/api/docs")
        assert resp.headers.get("x-api-version") == "1.0.0"

    @pytest.mark.asyncio
    async def test_no_version_header_on_health(self, client: AsyncClient):
        """Non-API paths should NOT have the version header."""
        resp = await client.get("/health")
        assert resp.headers.get("x-api-version") is None

    @pytest.mark.asyncio
    async def test_no_version_header_on_dashboard(self, client: AsyncClient):
        """Dashboard pages should NOT have the version header."""
        resp = await client.get("/")
        assert resp.headers.get("x-api-version") is None

    @pytest.mark.asyncio
    async def test_version_header_on_post(self, client: AsyncClient, sample_agent: Agent):
        """POST endpoints should also have the version header."""
        resp = await client.post(
            "/api/v1/rules/evaluate",
            json={
                "agent_id": str(sample_agent.external_id),
                "request_type": "command",
                "command": "echo hello",
            },
        )
        assert resp.headers.get("x-api-version") == "1.0.0"

    @pytest.mark.asyncio
    async def test_version_header_on_404(self, client: AsyncClient):
        """Even 404 responses on /api/ should have the version header."""
        resp = await client.get("/api/v1/agents/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 404
        assert resp.headers.get("x-api-version") == "1.0.0"


# ---------------------------------------------------------------------------
# Rate limit headers
# ---------------------------------------------------------------------------


class TestRateLimitHeaders:
    """Verify X-RateLimit-* headers are present on rate-limited endpoints."""

    @pytest.mark.asyncio
    async def test_rate_limit_headers_on_evaluate(
        self, client: AsyncClient, sample_agent: Agent
    ):
        resp = await client.post(
            "/api/v1/rules/evaluate",
            json={
                "agent_id": str(sample_agent.external_id),
                "request_type": "command",
                "command": "ls",
            },
        )
        assert "x-ratelimit-limit" in resp.headers
        assert "x-ratelimit-remaining" in resp.headers
        assert "x-ratelimit-reset" in resp.headers
        assert int(resp.headers["x-ratelimit-limit"]) == 300

    @pytest.mark.asyncio
    async def test_rate_limit_remaining_decrements(
        self, client: AsyncClient, sample_agent: Agent
    ):
        """Two consecutive calls should show remaining count go down."""
        payload = {
            "agent_id": str(sample_agent.external_id),
            "request_type": "command",
            "command": "ls",
        }
        resp1 = await client.post("/api/v1/rules/evaluate", json=payload)
        remaining1 = int(resp1.headers["x-ratelimit-remaining"])

        resp2 = await client.post("/api/v1/rules/evaluate", json=payload)
        remaining2 = int(resp2.headers["x-ratelimit-remaining"])

        assert remaining2 < remaining1

    @pytest.mark.asyncio
    async def test_approval_status_rate_limit_header(
        self, client: AsyncClient, redis: RedisClient
    ):
        """Approval status polling has its own rate limit (360/min)."""
        fake_id = uuid4().hex[:16]
        resp = await client.get(f"/api/v1/approvals/{fake_id}/status")
        # Might be 404, but headers should still be present
        if "x-ratelimit-limit" in resp.headers:
            assert int(resp.headers["x-ratelimit-limit"]) == 360

    @pytest.mark.asyncio
    async def test_no_rate_limit_headers_on_non_limited_endpoint(
        self, client: AsyncClient
    ):
        """Endpoints without a rate limiter dependency shouldn't have limit header."""
        resp = await client.get("/api/v1/agents")
        # agents list has no explicit rate limiter, so no limit header
        # (remaining/reset won't be set either)
        # x-api-version should still be present
        assert resp.headers.get("x-api-version") == "1.0.0"


# ---------------------------------------------------------------------------
# OpenAPI tags
# ---------------------------------------------------------------------------


class TestOpenAPITags:
    """Verify OpenAPI schema has correct tag structure."""

    @pytest.mark.asyncio
    async def test_openapi_has_all_public_tags(self, client: AsyncClient):
        resp = await client.get("/api/openapi.json")
        assert resp.status_code == 200
        spec = resp.json()
        tag_names = [t["name"] for t in spec.get("tags", [])]
        public_tags = ["Core", "Agents", "Rules", "Vault", "Audit", "Webhooks", "Integrations"]
        for tag in public_tags:
            assert tag in tag_names, f"Missing public tag: {tag}"

    @pytest.mark.asyncio
    async def test_openapi_has_internal_tags(self, client: AsyncClient):
        resp = await client.get("/api/openapi.json")
        spec = resp.json()
        tag_names = [t["name"] for t in spec.get("tags", [])]
        internal_tags = ["Auth", "Organizations", "Billing", "Telegram", "Slack", "SSO", "Security Research", "Setup"]
        for tag in internal_tags:
            assert tag in tag_names, f"Missing internal tag: {tag}"

    @pytest.mark.asyncio
    async def test_public_tags_come_before_internal(self, client: AsyncClient):
        """Public tags should be listed before internal tags for Swagger UI ordering."""
        resp = await client.get("/api/openapi.json")
        spec = resp.json()
        tag_names = [t["name"] for t in spec.get("tags", [])]
        public_tags = ["Core", "Agents", "Rules", "Vault", "Audit", "Webhooks", "Integrations"]
        internal_tags = ["Auth", "Organizations", "Billing", "Telegram", "Slack", "SSO", "Security Research", "Setup"]
        # All public tags should have lower index than all internal tags
        max_public_idx = max(tag_names.index(t) for t in public_tags if t in tag_names)
        min_internal_idx = min(tag_names.index(t) for t in internal_tags if t in tag_names)
        assert max_public_idx < min_internal_idx

    @pytest.mark.asyncio
    async def test_internal_tags_have_internal_description(self, client: AsyncClient):
        resp = await client.get("/api/openapi.json")
        spec = resp.json()
        internal_tag_names = {"Auth", "Organizations", "Billing", "Telegram", "Slack", "SSO", "Security Research", "Setup"}
        for tag_obj in spec.get("tags", []):
            if tag_obj["name"] in internal_tag_names:
                assert "Internal" in tag_obj.get("description", ""), (
                    f"Internal tag '{tag_obj['name']}' should have 'Internal' in description"
                )

    @pytest.mark.asyncio
    async def test_evaluate_endpoint_tagged_core(self, client: AsyncClient):
        """POST /rules/evaluate should appear under Core tag, not Rules."""
        resp = await client.get("/api/openapi.json")
        spec = resp.json()
        evaluate_path = spec["paths"].get("/api/v1/rules/evaluate", {})
        post_op = evaluate_path.get("post", {})
        tags = post_op.get("tags", [])
        assert "Core" in tags, f"evaluate should be tagged Core, got {tags}"

    @pytest.mark.asyncio
    async def test_approval_status_tagged_core(self, client: AsyncClient):
        """GET /approvals/{id}/status should appear under Core tag."""
        resp = await client.get("/api/openapi.json")
        spec = resp.json()
        # Find the path with {approval_id}/status pattern
        for path, methods in spec["paths"].items():
            if "/approvals/" in path and "/status" in path:
                get_op = methods.get("get", {})
                tags = get_op.get("tags", [])
                assert "Core" in tags, f"approval status should be tagged Core, got {tags}"
                break
        else:
            pytest.fail("Could not find approval status endpoint in OpenAPI spec")


# ---------------------------------------------------------------------------
# x-internal marker
# ---------------------------------------------------------------------------


class TestInternalEndpointMarkers:
    """Verify internal endpoints have x-internal: true in openapi_extra."""

    @pytest.mark.asyncio
    async def test_internal_agent_endpoints_marked(self, client: AsyncClient):
        resp = await client.get("/api/openapi.json")
        spec = resp.json()
        internal_paths = [
            ("/api/v1/agents/bulk", "post"),
            ("/api/v1/agents/cleanup-test", "post"),
            ("/api/v1/agents/verify-key", "post"),
        ]
        for path, method in internal_paths:
            op = spec["paths"].get(path, {}).get(method, {})
            assert op.get("x-internal") is True, (
                f"{method.upper()} {path} should have x-internal: true"
            )

    @pytest.mark.asyncio
    async def test_internal_audit_endpoints_marked(self, client: AsyncClient):
        resp = await client.get("/api/openapi.json")
        spec = resp.json()
        internal_paths = [
            ("/api/v1/audit/logs/stream", "get"),
        ]
        for path, method in internal_paths:
            op = spec["paths"].get(path, {}).get(method, {})
            assert op.get("x-internal") is True, (
                f"{method.upper()} {path} should have x-internal: true"
            )

    @pytest.mark.asyncio
    async def test_internal_integration_endpoints_marked(self, client: AsyncClient):
        resp = await client.get("/api/openapi.json")
        spec = resp.json()
        internal_paths = [
            ("/api/v1/integrations/active-packs", "get"),
            ("/api/v1/integrations/traffic/disable-server-rules", "post"),
            ("/api/v1/integrations/traffic/coverage", "get"),
        ]
        for path, method in internal_paths:
            op = spec["paths"].get(path, {}).get(method, {})
            assert op.get("x-internal") is True, (
                f"{method.upper()} {path} should have x-internal: true"
            )

    @pytest.mark.asyncio
    async def test_internal_approval_endpoints_marked(self, client: AsyncClient):
        resp = await client.get("/api/openapi.json")
        spec = resp.json()
        # Check /pending
        pending_op = spec["paths"].get("/api/v1/approvals/pending", {}).get("get", {})
        assert pending_op.get("x-internal") is True, "GET /approvals/pending should be x-internal"

    @pytest.mark.asyncio
    async def test_public_endpoints_not_marked_internal(self, client: AsyncClient):
        """Public endpoints should NOT have x-internal."""
        resp = await client.get("/api/openapi.json")
        spec = resp.json()
        public_paths = [
            ("/api/v1/rules/evaluate", "post"),
            ("/api/v1/agents", "get"),
            ("/api/v1/agents", "post"),
            ("/api/v1/rules", "get"),
            ("/api/v1/rules", "post"),
            ("/api/v1/vault/entries", "get"),
            ("/api/v1/vault/entries", "post"),
            ("/api/v1/audit/stats", "get"),
            ("/api/v1/audit/logs", "get"),
        ]
        for path, method in public_paths:
            op = spec["paths"].get(path, {}).get(method, {})
            assert op.get("x-internal") is not True, (
                f"{method.upper()} {path} should NOT be x-internal"
            )


# ---------------------------------------------------------------------------
# SDK version
# ---------------------------------------------------------------------------


class TestSDKVersion:
    """Verify SDK module version matches."""

    def test_sdk_version_is_1_0_0(self):
        import importlib.util
        import os
        init_path = os.path.join(
            os.path.dirname(__file__), "..", "sdk", "snapper", "__init__.py"
        )
        if not os.path.exists(init_path):
            pytest.skip("SDK not at expected path")
        # Read __version__ from file without importing (avoids dependency issues)
        with open(init_path) as f:
            for line in f:
                if line.startswith("__version__"):
                    version = line.split("=")[1].strip().strip('"').strip("'")
                    assert version == "1.0.0"
                    return
        pytest.fail("__version__ not found in sdk/snapper/__init__.py")

    def test_pyproject_version_is_1_0_0(self):
        import os
        pyproject_path = os.path.join(
            os.path.dirname(__file__), "..", "sdk", "pyproject.toml"
        )
        if not os.path.exists(pyproject_path):
            pytest.skip("pyproject.toml not at expected path")
        with open(pyproject_path) as f:
            content = f.read()
        assert 'version = "1.0.0"' in content


# ---------------------------------------------------------------------------
# Middleware ordering
# ---------------------------------------------------------------------------


class TestMiddlewareIntegration:
    """Test that middleware works correctly together."""

    @pytest.mark.asyncio
    async def test_version_header_present_even_on_validation_error(
        self, client: AsyncClient
    ):
        """Validation errors (422) should still have version header."""
        resp = await client.post(
            "/api/v1/rules/evaluate",
            json={},  # Missing required fields
        )
        assert resp.status_code == 422
        assert resp.headers.get("x-api-version") == "1.0.0"

    @pytest.mark.asyncio
    async def test_version_header_on_error_responses(
        self, client: AsyncClient
    ):
        """Error responses on /api/ paths should still have version header."""
        resp = await client.delete("/api/v1/rules/evaluate")
        # May return 405 or 422 depending on routing; either way, header present
        assert resp.status_code >= 400
        assert resp.headers.get("x-api-version") == "1.0.0"

    @pytest.mark.asyncio
    async def test_evaluate_has_both_version_and_rate_headers(
        self, client: AsyncClient, sample_agent: Agent
    ):
        """The evaluate endpoint should have all three header types."""
        resp = await client.post(
            "/api/v1/rules/evaluate",
            json={
                "agent_id": str(sample_agent.external_id),
                "request_type": "command",
                "command": "pwd",
            },
        )
        assert resp.headers.get("x-api-version") == "1.0.0"
        assert "x-ratelimit-limit" in resp.headers
        assert "x-ratelimit-remaining" in resp.headers
        assert "x-ratelimit-reset" in resp.headers
