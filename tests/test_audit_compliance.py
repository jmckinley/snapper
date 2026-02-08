"""Tests for audit compliance report and additional audit endpoint filters.

Covers:
- GET /api/v1/audit/reports/compliance (empty + populated)
- Audit log date range filtering
- Audit log action filter
- Alert type + severity filters
- Violation type filter
- Hourly breakdown correctness with multiple log entries
"""

import pytest
from datetime import datetime, timedelta
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
from app.models.agents import Agent


class TestComplianceReport:
    """Tests for GET /api/v1/audit/reports/compliance."""

    @pytest.mark.asyncio
    async def test_compliance_report_empty(self, client: AsyncClient):
        """Empty database returns zero counts in compliance report."""
        response = await client.get("/api/v1/audit/reports/compliance")
        assert response.status_code == 200
        data = response.json()
        assert data["total_evaluations"] == 0
        assert data["requests_allowed"] == 0
        assert data["requests_denied"] == 0
        assert data["total_violations"] == 0
        assert data["total_alerts"] == 0
        assert "report_period_start" in data
        assert "report_period_end" in data
        assert "generated_at" in data

    @pytest.mark.asyncio
    async def test_compliance_report_with_data(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        sample_agent: Agent,
    ):
        """Compliance report counts evaluations correctly."""
        # Create audit logs of different action types
        now = datetime.utcnow()
        for action in [
            AuditAction.REQUEST_ALLOWED,
            AuditAction.REQUEST_ALLOWED,
            AuditAction.REQUEST_DENIED,
        ]:
            db_session.add(
                AuditLog(
                    id=uuid4(),
                    action=action,
                    severity=AuditSeverity.INFO,
                    agent_id=sample_agent.id,
                    message=f"Test {action}",
                    details={},
                )
            )
        await db_session.commit()

        response = await client.get("/api/v1/audit/reports/compliance")
        assert response.status_code == 200
        data = response.json()
        assert data["total_evaluations"] == 3
        assert data["requests_allowed"] == 2
        assert data["requests_denied"] == 1

    @pytest.mark.asyncio
    async def test_compliance_report_custom_date_range(self, client: AsyncClient):
        """Custom start_date and end_date parameters are accepted."""
        now = datetime.utcnow()
        start = (now - timedelta(days=7)).isoformat()
        end = now.isoformat()
        response = await client.get(
            "/api/v1/audit/reports/compliance",
            params={"start_date": start, "end_date": end},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["report_period_start"] is not None

    @pytest.mark.asyncio
    async def test_compliance_report_includes_violations(
        self,
        client: AsyncClient,
        sample_violation: PolicyViolation,
    ):
        """Compliance report includes violation counts."""
        response = await client.get("/api/v1/audit/reports/compliance")
        assert response.status_code == 200
        data = response.json()
        assert data["total_violations"] >= 1
        assert data["unresolved_violations"] >= 1

    @pytest.mark.asyncio
    async def test_compliance_report_includes_alerts(
        self,
        client: AsyncClient,
        sample_alert: Alert,
    ):
        """Compliance report includes alert counts."""
        response = await client.get("/api/v1/audit/reports/compliance")
        assert response.status_code == 200
        data = response.json()
        assert data["total_alerts"] >= 1
        assert data["unacknowledged_alerts"] >= 1

    @pytest.mark.asyncio
    async def test_compliance_report_agent_and_rule_counts(
        self,
        client: AsyncClient,
        sample_agent: Agent,
        sample_rule,
    ):
        """Compliance report counts agents and rules."""
        response = await client.get("/api/v1/audit/reports/compliance")
        assert response.status_code == 200
        data = response.json()
        assert data["total_agents"] >= 1
        assert data["active_agents"] >= 1
        assert data["total_rules"] >= 1
        assert data["active_rules"] >= 1


class TestAuditLogDateRangeFilter:
    """Tests for audit log date range filtering."""

    @pytest.mark.asyncio
    async def test_filter_by_start_date(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        sample_agent: Agent,
    ):
        """start_date filter excludes older logs."""
        # Create an old log and a recent log
        old_time = datetime.utcnow() - timedelta(days=10)
        recent_time = datetime.utcnow()

        old_log = AuditLog(
            id=uuid4(),
            action=AuditAction.REQUEST_ALLOWED,
            severity=AuditSeverity.INFO,
            agent_id=sample_agent.id,
            message="Old log",
            details={},
            created_at=old_time,
        )
        recent_log = AuditLog(
            id=uuid4(),
            action=AuditAction.REQUEST_DENIED,
            severity=AuditSeverity.WARNING,
            agent_id=sample_agent.id,
            message="Recent log",
            details={},
            created_at=recent_time,
        )
        db_session.add_all([old_log, recent_log])
        await db_session.commit()

        # Filter to only recent logs
        cutoff = (datetime.utcnow() - timedelta(days=1)).isoformat()
        response = await client.get(
            "/api/v1/audit/logs",
            params={"start_date": cutoff},
        )
        assert response.status_code == 200
        data = response.json()
        log_ids = [item["id"] for item in data["items"]]
        assert str(recent_log.id) in log_ids
        assert str(old_log.id) not in log_ids

    @pytest.mark.asyncio
    async def test_filter_by_end_date(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        sample_agent: Agent,
    ):
        """end_date filter excludes newer logs."""
        old_time = datetime.utcnow() - timedelta(days=10)
        old_log = AuditLog(
            id=uuid4(),
            action=AuditAction.REQUEST_ALLOWED,
            severity=AuditSeverity.INFO,
            agent_id=sample_agent.id,
            message="Old log for end_date test",
            details={},
            created_at=old_time,
        )
        db_session.add(old_log)
        await db_session.commit()

        # end_date = 5 days ago — should include old_log but not fresh ones
        cutoff = (datetime.utcnow() - timedelta(days=5)).isoformat()
        response = await client.get(
            "/api/v1/audit/logs",
            params={"end_date": cutoff},
        )
        assert response.status_code == 200
        data = response.json()
        log_ids = [item["id"] for item in data["items"]]
        assert str(old_log.id) in log_ids


class TestAuditLogActionFilter:
    """Tests for filtering audit logs by action type."""

    @pytest.mark.asyncio
    async def test_filter_by_action_allowed(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        sample_agent: Agent,
    ):
        """Filtering by REQUEST_ALLOWED returns only allow logs."""
        allow_log = AuditLog(
            id=uuid4(),
            action=AuditAction.REQUEST_ALLOWED,
            severity=AuditSeverity.INFO,
            agent_id=sample_agent.id,
            message="Allowed action",
            details={},
        )
        deny_log = AuditLog(
            id=uuid4(),
            action=AuditAction.REQUEST_DENIED,
            severity=AuditSeverity.WARNING,
            agent_id=sample_agent.id,
            message="Denied action",
            details={},
        )
        db_session.add_all([allow_log, deny_log])
        await db_session.commit()

        response = await client.get(
            "/api/v1/audit/logs",
            params={"action": "request_allowed"},
        )
        assert response.status_code == 200
        data = response.json()
        for item in data["items"]:
            assert item["action"] == "request_allowed"

    @pytest.mark.asyncio
    async def test_filter_by_action_denied(
        self,
        client: AsyncClient,
        sample_audit_log: AuditLog,
    ):
        """Filtering by REQUEST_DENIED returns deny logs."""
        response = await client.get(
            "/api/v1/audit/logs",
            params={"action": "request_denied"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 1
        for item in data["items"]:
            assert item["action"] == "request_denied"


class TestAuditStatsHourlyBreakdown:
    """Test that hourly breakdown aggregates correctly."""

    @pytest.mark.asyncio
    async def test_hourly_breakdown_multiple_entries(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        sample_agent: Agent,
    ):
        """Multiple logs in same hour aggregate into one breakdown entry."""
        now = datetime.utcnow()
        # Create 3 allowed and 2 denied in the current hour
        for _ in range(3):
            db_session.add(
                AuditLog(
                    id=uuid4(),
                    action=AuditAction.REQUEST_ALLOWED,
                    severity=AuditSeverity.INFO,
                    agent_id=sample_agent.id,
                    message="Allowed",
                    details={},
                )
            )
        for _ in range(2):
            db_session.add(
                AuditLog(
                    id=uuid4(),
                    action=AuditAction.REQUEST_DENIED,
                    severity=AuditSeverity.WARNING,
                    agent_id=sample_agent.id,
                    message="Denied",
                    details={},
                )
            )
        await db_session.commit()

        response = await client.get("/api/v1/audit/stats?hours=1")
        assert response.status_code == 200
        data = response.json()
        assert data["allowed_count"] >= 3
        assert data["denied_count"] >= 2
        assert data["total_evaluations"] >= 5
        # Should have at least 1 hourly breakdown entry
        assert len(data["hourly_breakdown"]) >= 1
        # Find the entry for the current hour
        for entry in data["hourly_breakdown"]:
            if entry["allowed"] >= 3:
                assert entry["denied"] >= 2


class TestAlertFilters:
    """Tests for alert list filtering."""

    @pytest.mark.asyncio
    async def test_filter_alerts_by_severity(
        self,
        client: AsyncClient,
        sample_alert: Alert,
    ):
        """Filtering by severity returns matching alerts."""
        response = await client.get(
            "/api/v1/audit/alerts",
            params={"severity": "error"},
        )
        assert response.status_code == 200
        data = response.json()
        for item in data["items"]:
            assert item["severity"] == "error"

    @pytest.mark.asyncio
    async def test_filter_alerts_by_type(
        self,
        client: AsyncClient,
        sample_alert: Alert,
    ):
        """Filtering by alert_type returns matching alerts."""
        response = await client.get(
            "/api/v1/audit/alerts",
            params={"alert_type": "security_violation"},
        )
        assert response.status_code == 200
        data = response.json()
        for item in data["items"]:
            assert item["alert_type"] == "security_violation"

    @pytest.mark.asyncio
    async def test_filter_alerts_unacknowledged(
        self,
        client: AsyncClient,
        sample_alert: Alert,
    ):
        """Filtering by is_acknowledged=false returns unacked alerts."""
        response = await client.get(
            "/api/v1/audit/alerts",
            params={"is_acknowledged": "false"},
        )
        assert response.status_code == 200
        data = response.json()
        for item in data["items"]:
            assert item["is_acknowledged"] is False

    @pytest.mark.asyncio
    async def test_acknowledge_nonexistent_alert(self, client: AsyncClient):
        """Acknowledging a random UUID returns 404."""
        random_id = uuid4()
        response = await client.post(
            f"/api/v1/audit/alerts/{random_id}/acknowledge",
            json={},
        )
        assert response.status_code == 404


class TestViolationFilters:
    """Tests for violation list filtering."""

    @pytest.mark.asyncio
    async def test_filter_violations_by_type(
        self,
        client: AsyncClient,
        sample_violation: PolicyViolation,
    ):
        """Filtering by violation_type returns matching violations."""
        response = await client.get(
            "/api/v1/audit/violations",
            params={"violation_type": "rate_limit_exceeded"},
        )
        assert response.status_code == 200
        data = response.json()
        for item in data["items"]:
            assert item["violation_type"] == "rate_limit_exceeded"

    @pytest.mark.asyncio
    async def test_filter_violations_unresolved(
        self,
        client: AsyncClient,
        sample_violation: PolicyViolation,
    ):
        """Filtering by is_resolved=false returns unresolved violations."""
        response = await client.get(
            "/api/v1/audit/violations",
            params={"is_resolved": "false"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["unresolved_count"] >= 1
        for item in data["items"]:
            assert item["is_resolved"] is False

    @pytest.mark.asyncio
    async def test_filter_violations_by_severity(
        self,
        client: AsyncClient,
        sample_violation: PolicyViolation,
    ):
        """Filtering by severity returns matching violations."""
        response = await client.get(
            "/api/v1/audit/violations",
            params={"severity": "warning"},
        )
        assert response.status_code == 200
        data = response.json()
        for item in data["items"]:
            assert item["severity"] == "warning"

    @pytest.mark.asyncio
    async def test_violations_pagination(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        sample_agent: Agent,
    ):
        """Violation pagination works correctly."""
        # Create multiple violations
        for i in range(5):
            db_session.add(
                PolicyViolation(
                    id=uuid4(),
                    violation_type="test_type",
                    severity=AuditSeverity.INFO,
                    agent_id=sample_agent.id,
                    description=f"Test violation {i}",
                    context={},
                    is_resolved=False,
                )
            )
        await db_session.commit()

        response = await client.get(
            "/api/v1/audit/violations",
            params={"page": 1, "page_size": 2},
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data["items"]) == 2
        assert data["page"] == 1
        assert data["pages"] >= 3  # 5 items / 2 per page = 3 pages
