"""Tests for the auto-quarantine service."""

import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agents import Agent, AgentStatus
from app.models.audit_logs import AuditAction, AuditLog
from app.services.auto_quarantine import quarantine_agent


class FakeScalarResult:
    """Mimics the SQLAlchemy scalar_one_or_none pattern."""

    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


def _make_agent(status=AgentStatus.ACTIVE, name="test-agent"):
    """Create a mock agent with the expected attributes."""
    agent = MagicMock(spec=Agent)
    agent.id = uuid.uuid4()
    agent.name = name
    agent.status = status
    agent.is_deleted = False
    agent.organization_id = uuid.uuid4()
    agent.owner_chat_id = "123456"
    return agent


def _make_db(agent=None):
    """Create a mock async DB session."""
    db = AsyncMock(spec=AsyncSession)
    db.execute = AsyncMock(return_value=FakeScalarResult(agent))
    db.add = MagicMock()
    db.commit = AsyncMock()
    return db


@pytest.mark.asyncio
async def test_quarantine_sets_agent_status():
    """Quarantine changes agent status to QUARANTINED."""
    agent = _make_agent()
    db = _make_db(agent)

    with patch("app.services.auto_quarantine.publish_event", new_callable=AsyncMock), \
         patch("app.services.auto_quarantine.send_alert"):
        result = await quarantine_agent(db, agent.id, "test reason", "test")

    assert result is True
    assert agent.status == AgentStatus.QUARANTINED


@pytest.mark.asyncio
async def test_quarantine_creates_audit_log():
    """Quarantine creates an audit log entry."""
    agent = _make_agent()
    db = _make_db(agent)

    with patch("app.services.auto_quarantine.publish_event", new_callable=AsyncMock), \
         patch("app.services.auto_quarantine.send_alert"):
        await quarantine_agent(db, agent.id, "high threat", "threat_score")

    # Check that db.add was called with an AuditLog
    added_objects = [call.args[0] for call in db.add.call_args_list]
    audit_logs = [obj for obj in added_objects if isinstance(obj, AuditLog)]
    assert len(audit_logs) == 1
    assert audit_logs[0].action == AuditAction.AGENT_QUARANTINED
    assert "high threat" in audit_logs[0].message


@pytest.mark.asyncio
async def test_quarantine_not_found():
    """Returns False when agent doesn't exist."""
    db = _make_db(agent=None)  # No agent found

    result = await quarantine_agent(db, uuid.uuid4(), "test", "test")
    assert result is False


@pytest.mark.asyncio
async def test_quarantine_already_quarantined():
    """Returns False when agent is already quarantined."""
    agent = _make_agent(status=AgentStatus.QUARANTINED)
    db = _make_db(agent)

    result = await quarantine_agent(db, agent.id, "test", "test")
    assert result is False


@pytest.mark.asyncio
async def test_quarantine_preserves_old_status():
    """Audit log captures the old status."""
    agent = _make_agent(status=AgentStatus.ACTIVE)
    db = _make_db(agent)

    with patch("app.services.auto_quarantine.publish_event", new_callable=AsyncMock), \
         patch("app.services.auto_quarantine.send_alert"):
        await quarantine_agent(db, agent.id, "test", "threat_score")

    added = [call.args[0] for call in db.add.call_args_list]
    audit = [obj for obj in added if isinstance(obj, AuditLog)][0]
    assert audit.old_value["status"] == AgentStatus.ACTIVE


@pytest.mark.asyncio
async def test_quarantine_sends_alert():
    """Quarantine fires an alert via Celery."""
    agent = _make_agent()
    db = _make_db(agent)

    mock_alert = MagicMock()
    with patch("app.services.auto_quarantine.publish_event", new_callable=AsyncMock), \
         patch("app.services.auto_quarantine.send_alert", mock_alert):
        await quarantine_agent(db, agent.id, "threat score 95", "threat_score")

    mock_alert.delay.assert_called_once()
    call_kwargs = mock_alert.delay.call_args.kwargs
    assert "Quarantined" in call_kwargs["title"]
    assert call_kwargs["severity"] == "critical"


@pytest.mark.asyncio
async def test_quarantine_triggered_by_recorded():
    """The triggered_by field is recorded in audit details."""
    agent = _make_agent()
    db = _make_db(agent)

    with patch("app.services.auto_quarantine.publish_event", new_callable=AsyncMock), \
         patch("app.services.auto_quarantine.send_alert"):
        await quarantine_agent(db, agent.id, "kill chain complete", "kill_chain")

    added = [call.args[0] for call in db.add.call_args_list]
    audit = [obj for obj in added if isinstance(obj, AuditLog)][0]
    assert audit.new_value["triggered_by"] == "kill_chain"


@pytest.mark.asyncio
async def test_quarantine_commits_db():
    """DB commit is called after quarantine."""
    agent = _make_agent()
    db = _make_db(agent)

    with patch("app.services.auto_quarantine.publish_event", new_callable=AsyncMock), \
         patch("app.services.auto_quarantine.send_alert"):
        await quarantine_agent(db, agent.id, "test", "test")

    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_quarantine_publishes_siem_event():
    """Quarantine publishes a SIEM event."""
    agent = _make_agent()
    db = _make_db(agent)

    mock_publish = AsyncMock()
    with patch("app.services.auto_quarantine.publish_event", mock_publish), \
         patch("app.services.auto_quarantine.send_alert"):
        await quarantine_agent(db, agent.id, "siem test", "threat_score")

    mock_publish.assert_awaited_once()
    call_kwargs = mock_publish.call_args.kwargs
    assert call_kwargs["action"] == "threat_agent_quarantined"
    assert call_kwargs["severity"] == "critical"
