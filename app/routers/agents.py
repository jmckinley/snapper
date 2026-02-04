"""Agent management API endpoints."""

import logging
from datetime import datetime
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import DbSessionDep, RedisDep, default_rate_limit
from app.models.agents import Agent, AgentStatus, TrustLevel
from app.models.audit_logs import AuditAction, AuditLog, AuditSeverity
from app.models.rules import Rule
from app.schemas.agents import (
    AgentCreate,
    AgentListResponse,
    AgentResponse,
    AgentStatusResponse,
    AgentUpdate,
    BulkAgentCreate,
    BulkAgentResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/agents", dependencies=[Depends(default_rate_limit)])


@router.get("", response_model=AgentListResponse)
async def list_agents(
    db: DbSessionDep,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: Optional[AgentStatus] = Query(None, alias="status"),
    trust_level: Optional[TrustLevel] = None,
    search: Optional[str] = None,
    include_deleted: bool = False,
):
    """List all agents with pagination and filtering."""
    # Build query
    stmt = select(Agent)

    if not include_deleted:
        stmt = stmt.where(Agent.is_deleted == False)

    if status_filter:
        stmt = stmt.where(Agent.status == status_filter)

    if trust_level:
        stmt = stmt.where(Agent.trust_level == trust_level)

    if search:
        stmt = stmt.where(
            Agent.name.ilike(f"%{search}%") | Agent.external_id.ilike(f"%{search}%")
        )

    # Get total count
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    # Apply pagination
    stmt = stmt.order_by(Agent.created_at.desc())
    stmt = stmt.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(stmt)
    agents = list(result.scalars().all())

    return AgentListResponse(
        items=[AgentResponse.model_validate(a) for a in agents],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.post("", response_model=AgentResponse, status_code=status.HTTP_201_CREATED)
async def create_agent(
    agent_data: AgentCreate,
    db: DbSessionDep,
):
    """Register a new agent."""
    # Check for existing external_id
    stmt = select(Agent).where(Agent.external_id == agent_data.external_id)
    existing = (await db.execute(stmt)).scalar_one_or_none()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Agent with external_id '{agent_data.external_id}' already exists",
        )

    # Create agent
    agent = Agent(
        name=agent_data.name,
        external_id=agent_data.external_id,
        description=agent_data.description,
        status=AgentStatus.PENDING,
        trust_level=agent_data.trust_level,
        allowed_origins=agent_data.allowed_origins,
        require_localhost_only=agent_data.require_localhost_only,
        agent_metadata=agent_data.metadata,
        tags=agent_data.tags,
        rate_limit_max_requests=agent_data.rate_limit_max_requests,
        rate_limit_window_seconds=agent_data.rate_limit_window_seconds,
    )

    db.add(agent)
    await db.flush()

    # Create audit log
    audit_log = AuditLog(
        action=AuditAction.AGENT_REGISTERED,
        severity=AuditSeverity.INFO,
        agent_id=agent.id,
        message=f"Agent '{agent.name}' registered",
        new_value={
            "name": agent.name,
            "external_id": agent.external_id,
            "trust_level": agent.trust_level,
        },
    )
    db.add(audit_log)

    await db.commit()
    await db.refresh(agent)

    logger.info(f"Agent created: {agent.id} ({agent.name})")
    return AgentResponse.model_validate(agent)


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: UUID,
    db: DbSessionDep,
):
    """Get agent details by ID."""
    stmt = select(Agent).where(Agent.id == agent_id, Agent.is_deleted == False)
    agent = (await db.execute(stmt)).scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    return AgentResponse.model_validate(agent)


@router.put("/{agent_id}", response_model=AgentResponse)
async def update_agent(
    agent_id: UUID,
    agent_data: AgentUpdate,
    db: DbSessionDep,
):
    """Update an agent."""
    stmt = select(Agent).where(Agent.id == agent_id, Agent.is_deleted == False)
    agent = (await db.execute(stmt)).scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    # Store old values for audit
    old_values = {
        "name": agent.name,
        "status": agent.status,
        "trust_level": agent.trust_level,
    }

    # Update fields
    update_data = agent_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        if field == "metadata":
            setattr(agent, "agent_metadata", value)
        else:
            setattr(agent, field, value)

    # Create audit log
    new_values = {k: update_data.get(k, old_values.get(k)) for k in old_values}
    audit_log = AuditLog(
        action=AuditAction.AGENT_UPDATED,
        severity=AuditSeverity.INFO,
        agent_id=agent.id,
        message=f"Agent '{agent.name}' updated",
        old_value=old_values,
        new_value=new_values,
    )
    db.add(audit_log)

    await db.commit()
    await db.refresh(agent)

    logger.info(f"Agent updated: {agent.id}")
    return AgentResponse.model_validate(agent)


@router.delete("/{agent_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_agent(
    agent_id: UUID,
    db: DbSessionDep,
    hard_delete: bool = False,
):
    """Delete an agent (soft delete by default)."""
    stmt = select(Agent).where(Agent.id == agent_id)
    agent = (await db.execute(stmt)).scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    if hard_delete:
        await db.delete(agent)
    else:
        agent.is_deleted = True
        agent.deleted_at = datetime.utcnow()

    # Create audit log
    audit_log = AuditLog(
        action=AuditAction.AGENT_DELETED,
        severity=AuditSeverity.WARNING,
        agent_id=agent.id,
        message=f"Agent '{agent.name}' deleted",
        old_value={"name": agent.name, "external_id": agent.external_id},
    )
    db.add(audit_log)

    await db.commit()
    logger.info(f"Agent deleted: {agent_id}")


@router.get("/{agent_id}/status", response_model=AgentStatusResponse)
async def get_agent_status(
    agent_id: UUID,
    db: DbSessionDep,
    redis: RedisDep,
):
    """Get real-time agent status."""
    stmt = select(Agent).where(Agent.id == agent_id, Agent.is_deleted == False)
    agent = (await db.execute(stmt)).scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    # Get active rules count
    rules_stmt = select(func.count()).select_from(Rule).where(
        (Rule.agent_id == agent_id) | (Rule.agent_id == None),
        Rule.is_active == True,
        Rule.is_deleted == False,
    )
    active_rules = (await db.execute(rules_stmt)).scalar() or 0

    # Get recent violations count (last 24 hours)
    from app.models.audit_logs import PolicyViolation

    violations_stmt = select(func.count()).select_from(PolicyViolation).where(
        PolicyViolation.agent_id == agent_id,
        PolicyViolation.is_resolved == False,
    )
    violations = (await db.execute(violations_stmt)).scalar() or 0

    # Get rate limit remaining
    rate_key = f"rate_limit:agent:{agent_id}"
    limit_info = await redis.get(rate_key)
    rate_remaining = None
    if limit_info:
        # Parse limit info if stored
        pass

    return AgentStatusResponse(
        id=agent.id,
        external_id=agent.external_id,
        name=agent.name,
        status=agent.status,
        trust_level=agent.trust_level,
        is_active=agent.is_active,
        last_seen_at=agent.last_seen_at,
        active_rules_count=active_rules,
        recent_violations_count=violations,
        rate_limit_remaining=rate_remaining,
    )


@router.post("/bulk", response_model=BulkAgentResponse)
async def bulk_create_agents(
    bulk_data: BulkAgentCreate,
    db: DbSessionDep,
):
    """Bulk register multiple agents."""
    created = []
    failed = []

    for agent_data in bulk_data.agents:
        try:
            # Check for existing
            stmt = select(Agent).where(Agent.external_id == agent_data.external_id)
            existing = (await db.execute(stmt)).scalar_one_or_none()

            if existing:
                failed.append({
                    "external_id": agent_data.external_id,
                    "error": "Already exists",
                })
                continue

            # Create agent
            agent = Agent(
                name=agent_data.name,
                external_id=agent_data.external_id,
                description=agent_data.description,
                status=AgentStatus.PENDING,
                trust_level=agent_data.trust_level,
                allowed_origins=agent_data.allowed_origins,
                require_localhost_only=agent_data.require_localhost_only,
                agent_metadata=agent_data.metadata,
                tags=agent_data.tags,
            )
            db.add(agent)
            await db.flush()

            created.append(AgentResponse.model_validate(agent))

        except Exception as e:
            failed.append({
                "external_id": agent_data.external_id,
                "error": str(e),
            })

    await db.commit()

    return BulkAgentResponse(
        created=created,
        failed=failed,
        total_created=len(created),
        total_failed=len(failed),
    )


@router.post("/{agent_id}/suspend", response_model=AgentResponse)
async def suspend_agent(
    agent_id: UUID,
    db: DbSessionDep,
):
    """Suspend an agent."""
    stmt = select(Agent).where(Agent.id == agent_id, Agent.is_deleted == False)
    agent = (await db.execute(stmt)).scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    old_status = agent.status
    agent.status = AgentStatus.SUSPENDED

    # Create audit log
    audit_log = AuditLog(
        action=AuditAction.AGENT_SUSPENDED,
        severity=AuditSeverity.WARNING,
        agent_id=agent.id,
        message=f"Agent '{agent.name}' suspended",
        old_value={"status": old_status},
        new_value={"status": AgentStatus.SUSPENDED},
    )
    db.add(audit_log)

    await db.commit()
    await db.refresh(agent)

    return AgentResponse.model_validate(agent)


@router.post("/{agent_id}/activate", response_model=AgentResponse)
async def activate_agent(
    agent_id: UUID,
    db: DbSessionDep,
):
    """Activate an agent."""
    stmt = select(Agent).where(Agent.id == agent_id, Agent.is_deleted == False)
    agent = (await db.execute(stmt)).scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    old_status = agent.status
    agent.status = AgentStatus.ACTIVE

    # Create audit log
    audit_log = AuditLog(
        action=AuditAction.AGENT_ACTIVATED,
        severity=AuditSeverity.INFO,
        agent_id=agent.id,
        message=f"Agent '{agent.name}' activated",
        old_value={"status": old_status},
        new_value={"status": AgentStatus.ACTIVE},
    )
    db.add(audit_log)

    await db.commit()
    await db.refresh(agent)

    return AgentResponse.model_validate(agent)


@router.post("/{agent_id}/quarantine", response_model=AgentResponse)
async def quarantine_agent(
    agent_id: UUID,
    db: DbSessionDep,
    reason: Optional[str] = None,
):
    """Quarantine an agent due to security concerns."""
    stmt = select(Agent).where(Agent.id == agent_id, Agent.is_deleted == False)
    agent = (await db.execute(stmt)).scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    old_status = agent.status
    agent.status = AgentStatus.QUARANTINED

    # Create audit log
    audit_log = AuditLog(
        action=AuditAction.AGENT_QUARANTINED,
        severity=AuditSeverity.CRITICAL,
        agent_id=agent.id,
        message=f"Agent '{agent.name}' quarantined" + (f": {reason}" if reason else ""),
        old_value={"status": old_status},
        new_value={"status": AgentStatus.QUARANTINED, "reason": reason},
    )
    db.add(audit_log)

    await db.commit()
    await db.refresh(agent)

    logger.warning(f"Agent quarantined: {agent_id} - {reason}")
    return AgentResponse.model_validate(agent)
