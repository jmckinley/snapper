"""Tests for PII purge endpoint."""

import pytest
from uuid import uuid4

from app.models.agents import Agent, AgentStatus, TrustLevel
from app.models.audit_logs import AuditLog, AuditAction, AuditSeverity


class TestPIIPurgeAPI:
    """Tests for PII purge endpoint at /agents/{agent_id}/purge-pii."""

    @pytest.mark.asyncio
    async def test_purge_requires_confirmation(self, client, sample_agent):
        """Test that purge without confirm=True returns 400."""
        response = await client.post(
            f"/api/v1/agents/{sample_agent.id}/purge-pii",
            params={"confirm": False},
        )

        assert response.status_code == 400
        assert "confirm=true" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_purge_with_confirmation(self, client, sample_agent):
        """Test that purge with confirm=True succeeds."""
        response = await client.post(
            f"/api/v1/agents/{sample_agent.id}/purge-pii",
            params={"confirm": True},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "PII purge completed" in data["message"]
        assert "results" in data

    @pytest.mark.asyncio
    async def test_purge_agent_not_found(self, client):
        """Test that purge with invalid agent_id returns 404."""
        fake_id = uuid4()
        response = await client.post(
            f"/api/v1/agents/{fake_id}/purge-pii",
            params={"confirm": True},
        )

        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_purge_clears_redis_cache(self, client, sample_agent, redis):
        """Test that purge clears Redis cache keys for agent."""
        # Set up some cache keys
        await redis.set(f"agent:{sample_agent.id}:session", "test-session-data")
        await redis.set(f"conversation:{sample_agent.id}:123", "test-conversation")

        response = await client.post(
            f"/api/v1/agents/{sample_agent.id}/purge-pii",
            params={"confirm": True},
        )

        assert response.status_code == 200

        # Verify cache keys are cleared (using scan to check for any remaining keys)
        # The purge should have deleted keys matching the patterns
        cursor = 0
        found_keys = []
        while True:
            cursor, keys = await redis.scan(cursor, match=f"agent:{sample_agent.id}:*", count=100)
            found_keys.extend(keys)
            if cursor == 0:
                break
        assert len(found_keys) == 0

    @pytest.mark.asyncio
    async def test_purge_redacts_audit_logs(self, db_session, client, sample_agent):
        """Test that PII patterns in audit logs are redacted."""
        # Create audit log with PII (SSN pattern)
        audit_log = AuditLog(
            id=uuid4(),
            action=AuditAction.REQUEST_ALLOWED,
            severity=AuditSeverity.INFO,
            agent_id=sample_agent.id,
            message="User SSN is 123-45-6789 and email is test@example.com",
        )
        db_session.add(audit_log)
        await db_session.commit()

        response = await client.post(
            f"/api/v1/agents/{sample_agent.id}/purge-pii",
            params={"confirm": True},
        )

        assert response.status_code == 200

        # Refresh and check if SSN was redacted
        await db_session.refresh(audit_log)
        assert "123-45-6789" not in audit_log.message
        assert "[REDACTED" in audit_log.message

    @pytest.mark.asyncio
    async def test_purge_creates_audit_entry(self, db_session, client, sample_agent):
        """Test that purge action creates an audit log entry."""
        from sqlalchemy import select

        # Count audit logs before
        result = await db_session.execute(
            select(AuditLog).where(
                AuditLog.agent_id == sample_agent.id,
                AuditLog.action == AuditAction.SECURITY_ALERT,
            )
        )
        before_count = len(list(result.scalars().all()))

        response = await client.post(
            f"/api/v1/agents/{sample_agent.id}/purge-pii",
            params={"confirm": True},
        )

        assert response.status_code == 200

        # Check that a new audit log was created
        result = await db_session.execute(
            select(AuditLog).where(
                AuditLog.agent_id == sample_agent.id,
                AuditLog.action == AuditAction.SECURITY_ALERT,
            )
        )
        after_count = len(list(result.scalars().all()))
        assert after_count > before_count

        # Verify the audit log mentions PII purge
        result = await db_session.execute(
            select(AuditLog).where(
                AuditLog.agent_id == sample_agent.id,
                AuditLog.action == AuditAction.SECURITY_ALERT,
            ).order_by(AuditLog.created_at.desc())
        )
        latest = result.scalars().first()
        assert "PII purge" in latest.message
