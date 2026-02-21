"""Shared auto-quarantine logic.

Extracted from ``app/routers/agents.py`` so that background tasks
(threat analysis, device anomaly checks) can quarantine agents without
duplicating the audit + alert flow.
"""

import logging
from typing import Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.agents import Agent, AgentStatus
from app.models.audit_logs import AuditAction, AuditLog, AuditSeverity

logger = logging.getLogger(__name__)
settings = get_settings()


async def quarantine_agent(
    db: AsyncSession,
    agent_id: UUID,
    reason: str,
    triggered_by: str = "system",
) -> bool:
    """Quarantine an agent and create the appropriate audit trail.

    Parameters
    ----------
    db : AsyncSession
        Active database session (caller manages commit/rollback).
    agent_id : UUID
        The agent to quarantine.
    reason : str
        Human-readable reason (included in audit log + alert).
    triggered_by : str
        Source of quarantine: ``"threat_score"``, ``"device_anomaly"``,
        ``"kill_chain"``, ``"manual"``, etc.

    Returns
    -------
    bool
        True if agent was quarantined, False if not found or already quarantined.
    """
    stmt = select(Agent).where(Agent.id == agent_id, Agent.is_deleted == False)
    agent = (await db.execute(stmt)).scalar_one_or_none()

    if not agent:
        logger.warning(f"Auto-quarantine: agent {agent_id} not found")
        return False

    if agent.status == AgentStatus.QUARANTINED:
        logger.info(f"Auto-quarantine: agent {agent_id} already quarantined")
        return False

    old_status = agent.status
    agent.status = AgentStatus.QUARANTINED

    audit_log = AuditLog(
        action=AuditAction.AGENT_QUARANTINED,
        severity=AuditSeverity.CRITICAL,
        agent_id=agent.id,
        organization_id=agent.organization_id,
        message=f"Agent '{agent.name}' auto-quarantined ({triggered_by}): {reason}",
        old_value={"status": old_status},
        new_value={
            "status": AgentStatus.QUARANTINED,
            "reason": reason,
            "triggered_by": triggered_by,
        },
    )
    db.add(audit_log)
    await db.commit()

    # Publish SIEM event (fire-and-forget)
    try:
        from app.services.event_publisher import publish_event
        await publish_event(
            action=AuditAction.THREAT_AGENT_QUARANTINED.value,
            severity="critical",
            message=audit_log.message,
            agent_id=str(agent.id),
            details={"reason": reason, "triggered_by": triggered_by},
            organization_id=str(agent.organization_id) if agent.organization_id else None,
        )
    except Exception:
        pass

    # Send alert via Telegram/Slack
    try:
        from app.tasks.alerts import send_alert
        send_alert.delay(
            title=f"Agent Quarantined: {agent.name}",
            message=(
                f"Agent `{agent.name}` has been auto-quarantined.\n"
                f"*Reason:* {reason}\n"
                f"*Triggered by:* {triggered_by}"
            ),
            severity="critical",
            metadata={
                "agent_id": str(agent.id),
                "agent_name": agent.name,
                "agent_owner_chat_id": getattr(agent, "owner_chat_id", None),
            },
        )
    except Exception:
        pass

    logger.warning(f"Auto-quarantined agent {agent.name} ({agent_id}): {reason}")
    return True
