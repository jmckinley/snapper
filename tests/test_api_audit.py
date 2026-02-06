"""Tests for audit API endpoints."""

import pytest
from uuid import uuid4

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_logs import (
    AuditLog,
    AuditAction,
    AuditSeverity,
    PolicyViolation,
    Alert,
)


class TestAuditLogs:
    """Tests for audit log endpoints."""

    @pytest.mark.asyncio
    async def test_list_audit_logs_empty(self, client: AsyncClient):
        """Empty list returns total=0."""
        response = await client.get("/api/v1/audit/logs")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["items"] == []
        assert data["page"] == 1

    @pytest.mark.asyncio
    async def test_list_audit_logs_with_data(
        self, client: AsyncClient, sample_audit_log: AuditLog
    ):
        """Returns log entries when data exists."""
        response = await client.get("/api/v1/audit/logs")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 1
        assert len(data["items"]) >= 1

        # Verify our sample log is in the results
        log_ids = [item["id"] for item in data["items"]]
        assert str(sample_audit_log.id) in log_ids

    @pytest.mark.asyncio
    async def test_filter_by_agent_id(
        self, client: AsyncClient, sample_audit_log: AuditLog, sample_agent
    ):
        """agent_id filter returns only logs for that agent."""
        response = await client.get(
            "/api/v1/audit/logs", params={"agent_id": str(sample_agent.id)}
        )

        assert response.status_code == 200
        data = response.json()

        # All returned logs should be for this agent
        for item in data["items"]:
            assert item["agent_id"] == str(sample_agent.id)

    @pytest.mark.asyncio
    async def test_filter_by_severity(
        self, client: AsyncClient, sample_audit_log: AuditLog
    ):
        """severity filter works correctly."""
        response = await client.get(
            "/api/v1/audit/logs", params={"severity": "warning"}
        )

        assert response.status_code == 200
        data = response.json()

        # All returned logs should have warning severity
        for item in data["items"]:
            assert item["severity"] == "warning"

    @pytest.mark.asyncio
    async def test_pagination_works(
        self, client: AsyncClient, db_session: AsyncSession, sample_agent
    ):
        """Page and page_size parameters work correctly."""
        # Create multiple audit logs
        for i in range(5):
            log = AuditLog(
                id=uuid4(),
                action=AuditAction.REQUEST_ALLOWED,
                severity=AuditSeverity.INFO,
                agent_id=sample_agent.id,
                message=f"Test log {i}",
                details={},
            )
            db_session.add(log)
        await db_session.commit()

        # Request page 1 with size 2
        response = await client.get(
            "/api/v1/audit/logs", params={"page": 1, "page_size": 2}
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data["items"]) == 2
        assert data["page"] == 1
        assert data["page_size"] == 2


class TestViolations:
    """Tests for violation endpoints."""

    @pytest.mark.asyncio
    async def test_list_violations(
        self, client: AsyncClient, sample_violation: PolicyViolation
    ):
        """Returns violations when data exists."""
        response = await client.get("/api/v1/audit/violations")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 1

        # Verify our sample violation is in the results
        violation_ids = [item["id"] for item in data["items"]]
        assert str(sample_violation.id) in violation_ids

    @pytest.mark.asyncio
    async def test_resolve_violation(
        self, client: AsyncClient, sample_violation: PolicyViolation
    ):
        """POST resolve marks violation as resolved."""
        response = await client.post(
            f"/api/v1/audit/violations/{sample_violation.id}/resolve",
            json={"resolution_notes": "Fixed by test"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["is_resolved"] is True
        assert data["resolution_notes"] == "Fixed by test"
        assert data["resolved_at"] is not None

    @pytest.mark.asyncio
    async def test_resolve_nonexistent(self, client: AsyncClient):
        """Resolving a random UUID returns 404."""
        random_id = uuid4()
        response = await client.post(
            f"/api/v1/audit/violations/{random_id}/resolve",
            json={"resolution_notes": "This should fail"},
        )

        assert response.status_code == 404


class TestAlerts:
    """Tests for alert endpoints."""

    @pytest.mark.asyncio
    async def test_list_alerts(self, client: AsyncClient, sample_alert: Alert):
        """Returns alerts when data exists."""
        response = await client.get("/api/v1/audit/alerts")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 1

        # Verify our sample alert is in the results
        alert_ids = [item["id"] for item in data["items"]]
        assert str(sample_alert.id) in alert_ids

    @pytest.mark.asyncio
    async def test_acknowledge_alert(self, client: AsyncClient, sample_alert: Alert):
        """POST acknowledge marks alert as acknowledged."""
        response = await client.post(
            f"/api/v1/audit/alerts/{sample_alert.id}/acknowledge",
            json={},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["is_acknowledged"] is True
        assert data["acknowledged_at"] is not None
