"""Tests for approval workflow API endpoints."""

import pytest
from uuid import uuid4
import asyncio

from httpx import AsyncClient

from app.redis_client import RedisClient
from app.routers.approvals import (
    create_approval_request,
    get_approval_request,
    update_approval_status,
    APPROVAL_PREFIX,
)


class TestApprovalWorkflow:
    """Tests for approval workflow."""

    @pytest.mark.asyncio
    async def test_create_and_check_pending(self, client: AsyncClient, redis: RedisClient):
        """New approval request is in pending status."""
        # Create an approval request
        approval_id = await create_approval_request(
            redis=redis,
            agent_id="test-agent-123",
            agent_name="Test Agent",
            request_type="command",
            rule_id="test-rule-456",
            rule_name="Test Rule",
            command="rm -rf /",
            timeout_seconds=300,
        )

        # Check status via API
        response = await client.get(f"/api/v1/approvals/{approval_id}/status")

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == approval_id
        assert data["status"] == "pending"
        assert data["wait_seconds"] is not None

    @pytest.mark.asyncio
    async def test_approve_decision(self, client: AsyncClient, redis: RedisClient):
        """Approve decision changes status to approved."""
        # Create an approval request
        approval_id = await create_approval_request(
            redis=redis,
            agent_id="test-agent",
            agent_name="Test Agent",
            request_type="file_access",
            rule_id="rule-123",
            rule_name="File Rule",
            file_path="/etc/passwd",
        )

        # Approve it
        response = await client.post(
            f"/api/v1/approvals/{approval_id}/decide",
            json={"decision": "approve", "decided_by": "test_user"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "approved"
        assert "test_user" in data["reason"]

    @pytest.mark.asyncio
    async def test_deny_decision(self, client: AsyncClient, redis: RedisClient):
        """Deny decision changes status to denied."""
        # Create an approval request
        approval_id = await create_approval_request(
            redis=redis,
            agent_id="test-agent",
            agent_name="Test Agent",
            request_type="network",
            rule_id="rule-456",
            rule_name="Network Rule",
        )

        # Deny it
        response = await client.post(
            f"/api/v1/approvals/{approval_id}/decide",
            json={"decision": "deny", "decided_by": "security_admin"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "denied"
        assert "security_admin" in data["reason"]

    @pytest.mark.asyncio
    async def test_invalid_decision_rejected(self, client: AsyncClient, redis: RedisClient):
        """Bad decision value returns 400."""
        # Create an approval request
        approval_id = await create_approval_request(
            redis=redis,
            agent_id="test-agent",
            agent_name="Test Agent",
            request_type="command",
            rule_id="rule-789",
            rule_name="Command Rule",
        )

        # Try invalid decision
        response = await client.post(
            f"/api/v1/approvals/{approval_id}/decide",
            json={"decision": "maybe"},
        )

        assert response.status_code == 400
        assert "approve" in response.json()["detail"] or "deny" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_decide_already_decided(self, client: AsyncClient, redis: RedisClient):
        """Re-deciding on already decided approval returns 400."""
        # Create and approve
        approval_id = await create_approval_request(
            redis=redis,
            agent_id="test-agent",
            agent_name="Test Agent",
            request_type="command",
            rule_id="rule-000",
            rule_name="Test Rule",
        )

        # First decision
        response = await client.post(
            f"/api/v1/approvals/{approval_id}/decide",
            json={"decision": "approve"},
        )
        assert response.status_code == 200

        # Try to decide again
        response = await client.post(
            f"/api/v1/approvals/{approval_id}/decide",
            json={"decision": "deny"},
        )

        assert response.status_code == 400
        assert "already" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_expired_request(self, client: AsyncClient, redis: RedisClient):
        """Short TTL approval shows as expired."""
        # Create with very short timeout
        approval_id = await create_approval_request(
            redis=redis,
            agent_id="test-agent",
            agent_name="Test Agent",
            request_type="command",
            rule_id="rule-exp",
            rule_name="Expiring Rule",
            timeout_seconds=1,  # 1 second timeout
        )

        # Wait for expiration
        await asyncio.sleep(2)

        # Check status - should be expired
        response = await client.get(f"/api/v1/approvals/{approval_id}/status")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "expired"

    @pytest.mark.asyncio
    async def test_nonexistent_approval(self, client: AsyncClient):
        """Random approval ID returns expired status."""
        random_id = str(uuid4())

        response = await client.get(f"/api/v1/approvals/{random_id}/status")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "expired"
        assert "not found" in data["reason"].lower()

    @pytest.mark.asyncio
    async def test_list_pending_approvals(self, client: AsyncClient, redis: RedisClient):
        """Lists all pending approval requests."""
        # Create a couple of pending approvals
        await create_approval_request(
            redis=redis,
            agent_id="agent-1",
            agent_name="Agent 1",
            request_type="command",
            rule_id="rule-1",
            rule_name="Rule 1",
        )
        await create_approval_request(
            redis=redis,
            agent_id="agent-2",
            agent_name="Agent 2",
            request_type="file_access",
            rule_id="rule-2",
            rule_name="Rule 2",
        )

        response = await client.get("/api/v1/approvals/pending")

        assert response.status_code == 200
        data = response.json()
        assert "pending" in data
        assert "count" in data
        assert data["count"] >= 2
