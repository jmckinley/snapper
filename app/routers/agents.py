"""Agent management API endpoints."""

import asyncio
import logging
from datetime import datetime
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import DbSessionDep, OptionalOrgIdDep, RedisDep, default_rate_limit, require_delete_agents, verify_resource_org
from app.middleware.metrics import set_active_agents
from app.services.event_publisher import publish_from_audit_log
from app.services.quota import QuotaChecker
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
    org_id: OptionalOrgIdDep,
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

    # Org scoping
    if org_id:
        stmt = stmt.where(Agent.organization_id == org_id)

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


@router.post(
    "",
    response_model=AgentResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(QuotaChecker("agents"))],
)
async def create_agent(
    agent_data: AgentCreate,
    db: DbSessionDep,
    org_id: OptionalOrgIdDep,
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

    # Check for duplicate name among active agents
    name_stmt = select(Agent).where(
        Agent.name == agent_data.name,
        Agent.is_deleted == False,
    )
    name_exists = (await db.execute(name_stmt)).scalar_one_or_none()
    if name_exists:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"An active agent named '{agent_data.name}' already exists",
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
        owner_chat_id=agent_data.owner_chat_id,
        organization_id=org_id,
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
    asyncio.ensure_future(publish_from_audit_log(audit_log))
    await db.refresh(agent)

    # Update active agents gauge
    count_result = await db.execute(
        select(func.count(Agent.id)).where(Agent.deleted_at.is_(None), Agent.status == AgentStatus.ACTIVE)
    )
    set_active_agents(count_result.scalar() or 0)

    logger.info(f"Agent created: {agent.id} ({agent.name})")
    return AgentResponse.model_validate(agent)


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: UUID,
    db: DbSessionDep,
    org_id: OptionalOrgIdDep,
):
    """Get agent details by ID."""
    stmt = select(Agent).where(Agent.id == agent_id, Agent.is_deleted == False)
    agent = (await db.execute(stmt)).scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    await verify_resource_org(agent.organization_id, org_id)
    return AgentResponse.model_validate(agent)


@router.put("/{agent_id}", response_model=AgentResponse)
async def update_agent(
    agent_id: UUID,
    agent_data: AgentUpdate,
    db: DbSessionDep,
    org_id: OptionalOrgIdDep,
):
    """Update an agent."""
    stmt = select(Agent).where(Agent.id == agent_id, Agent.is_deleted == False)
    agent = (await db.execute(stmt)).scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    await verify_resource_org(agent.organization_id, org_id)

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
    asyncio.ensure_future(publish_from_audit_log(audit_log))
    await db.refresh(agent)

    logger.info(f"Agent updated: {agent.id}")
    return AgentResponse.model_validate(agent)


@router.delete(
    "/{agent_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_delete_agents)],
)
async def delete_agent(
    agent_id: UUID,
    db: DbSessionDep,
    org_id: OptionalOrgIdDep,
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

    await verify_resource_org(agent.organization_id, org_id)

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
    asyncio.ensure_future(publish_from_audit_log(audit_log))

    # Update active agents gauge
    count_result = await db.execute(
        select(func.count(Agent.id)).where(Agent.deleted_at.is_(None), Agent.status == AgentStatus.ACTIVE)
    )
    set_active_agents(count_result.scalar() or 0)

    logger.info(f"Agent deleted: {agent_id}")


@router.get("/{agent_id}/status", response_model=AgentStatusResponse)
async def get_agent_status(
    agent_id: UUID,
    db: DbSessionDep,
    redis: RedisDep,
    org_id: OptionalOrgIdDep,
):
    """Get real-time agent status."""
    stmt = select(Agent).where(Agent.id == agent_id, Agent.is_deleted == False)
    agent = (await db.execute(stmt)).scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    await verify_resource_org(agent.organization_id, org_id)

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


@router.post("/bulk", response_model=BulkAgentResponse, openapi_extra={"x-internal": True})
async def bulk_create_agents(
    bulk_data: BulkAgentCreate,
    db: DbSessionDep,
):
    """Bulk register multiple agents."""
    created = []
    failed = []

    for agent_data in bulk_data.agents:
        try:
            # Check for existing external_id
            stmt = select(Agent).where(Agent.external_id == agent_data.external_id)
            existing = (await db.execute(stmt)).scalar_one_or_none()

            if existing:
                failed.append({
                    "external_id": agent_data.external_id,
                    "error": "Already exists",
                })
                continue

            # Check for duplicate name
            name_stmt = select(Agent).where(
                Agent.name == agent_data.name,
                Agent.is_deleted == False,
            )
            if (await db.execute(name_stmt)).scalar_one_or_none():
                failed.append({
                    "external_id": agent_data.external_id,
                    "error": f"Agent named '{agent_data.name}' already exists",
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
    org_id: OptionalOrgIdDep,
):
    """Suspend an agent."""
    stmt = select(Agent).where(Agent.id == agent_id, Agent.is_deleted == False)
    agent = (await db.execute(stmt)).scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    await verify_resource_org(agent.organization_id, org_id)

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
    asyncio.ensure_future(publish_from_audit_log(audit_log))
    await db.refresh(agent)

    return AgentResponse.model_validate(agent)


@router.post("/{agent_id}/activate", response_model=AgentResponse)
async def activate_agent(
    agent_id: UUID,
    db: DbSessionDep,
    org_id: OptionalOrgIdDep,
):
    """Activate an agent."""
    stmt = select(Agent).where(Agent.id == agent_id, Agent.is_deleted == False)
    agent = (await db.execute(stmt)).scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    await verify_resource_org(agent.organization_id, org_id)

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
    asyncio.ensure_future(publish_from_audit_log(audit_log))
    await db.refresh(agent)

    return AgentResponse.model_validate(agent)


@router.post("/{agent_id}/quarantine", response_model=AgentResponse, openapi_extra={"x-internal": True})
async def quarantine_agent(
    agent_id: UUID,
    db: DbSessionDep,
    org_id: OptionalOrgIdDep,
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

    await verify_resource_org(agent.organization_id, org_id)

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
    asyncio.ensure_future(publish_from_audit_log(audit_log))
    await db.refresh(agent)

    logger.warning(f"Agent quarantined: {agent_id} - {reason}")
    return AgentResponse.model_validate(agent)


@router.post("/{agent_id}/regenerate-key")
async def regenerate_api_key(
    agent_id: UUID,
    db: DbSessionDep,
    org_id: OptionalOrgIdDep,
):
    """
    Regenerate an agent's API key.

    The old key is immediately invalidated. Use this if you suspect
    the key has been compromised or as part of regular key rotation.

    Returns the new API key - make sure to save it, as it won't be
    shown again in full.
    """
    from app.models.agents import generate_api_key

    # Get agent
    stmt = select(Agent).where(Agent.id == agent_id, Agent.is_deleted == False)
    agent = (await db.execute(stmt)).scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    await verify_resource_org(agent.organization_id, org_id)

    from datetime import datetime as dt, timezone as tz
    old_key_prefix = agent.api_key[:12] + "..."  # Log prefix only

    # Generate new key
    agent.api_key = generate_api_key()
    agent.api_key_last_used = None  # Reset last used
    agent.api_key_rotated_at = dt.now(tz.utc)

    # Audit log
    audit_log = AuditLog(
        action=AuditAction.API_KEY_ROTATED,
        severity=AuditSeverity.WARNING,
        agent_id=agent.id,
        message=f"API key rotated for agent '{agent.name}'",
        old_value={"api_key_prefix": old_key_prefix},
        new_value={"api_key_prefix": agent.api_key[:12] + "..."},
    )
    db.add(audit_log)

    await db.commit()
    asyncio.ensure_future(publish_from_audit_log(audit_log))
    await db.refresh(agent)

    logger.info(f"API key regenerated for agent: {agent_id}")

    return {
        "status": "success",
        "message": "API key regenerated successfully",
        "api_key": agent.api_key,
        "agent_id": str(agent.id),
        "agent_name": agent.name,
    }


@router.post("/{agent_id}/purge-pii", openapi_extra={"x-internal": True})
async def purge_agent_pii(
    agent_id: UUID,
    db: DbSessionDep,
    redis: RedisDep,
    org_id: OptionalOrgIdDep,
    confirm: bool = False,
):
    """
    Purge PII from an OpenClaw agent.

    This command triggers removal of:
    - Conversation history containing PII
    - Memory files (SOUL.md, MEMORY.md) with PII patterns
    - Vector database entries with PII
    - Cached session data

    PII patterns detected:
    - Names (first, last, full)
    - Addresses (street, city, zip)
    - Phone numbers
    - Email addresses
    - Payment info (credit cards, bank accounts)
    - Health info (medical records, conditions)
    - Government IDs (SSN, license, passport)

    Requires confirmation to execute.
    """
    if not confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="PII purge requires confirm=true. This action is irreversible.",
        )

    stmt = select(Agent).where(Agent.id == agent_id, Agent.is_deleted == False)
    agent = (await db.execute(stmt)).scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    await verify_resource_org(agent.organization_id, org_id)

    # PII patterns to search for and redact
    # Use comprehensive PII patterns (US, UK, Canada, Australia)
    from app.utils.pii_patterns import PII_PATTERNS_FULL
    pii_patterns = PII_PATTERNS_FULL

    purge_results = {
        "agent_id": str(agent_id),
        "agent_name": agent.name,
        "patterns_checked": list(pii_patterns.keys()),
        "actions_taken": [],
        "status": "completed",
    }

    # 1. Clear Redis cached data for this agent
    cache_keys = [
        f"agent:{agent_id}:*",
        f"session:{agent_id}:*",
        f"conversation:{agent_id}:*",
    ]
    for pattern in cache_keys:
        cursor = 0
        deleted_count = 0
        while True:
            cursor, keys = await redis.scan(cursor, match=pattern, count=100)
            for key in keys:
                await redis.delete(key)
                deleted_count += 1
            if cursor == 0:
                break
        if deleted_count > 0:
            purge_results["actions_taken"].append(f"Deleted {deleted_count} cached entries matching {pattern}")

    # 2. Clear any approval requests containing PII
    from app.routers.approvals import APPROVAL_PREFIX
    cursor = 0
    while True:
        cursor, keys = await redis.scan(cursor, match=f"{APPROVAL_PREFIX}*", count=100)
        for key in keys:
            data = await redis.get(key)
            if data and str(agent_id) in data:
                await redis.delete(key)
                purge_results["actions_taken"].append(f"Deleted approval request {key}")
        if cursor == 0:
            break

    # 3. Redact PII from audit logs (mark as redacted, don't delete for compliance)
    from app.models.audit_logs import AuditLog as AuditLogModel
    audit_stmt = select(AuditLogModel).where(AuditLogModel.agent_id == agent_id)
    audit_result = await db.execute(audit_stmt)
    audit_logs = audit_result.scalars().all()

    import re
    redacted_logs = 0
    for log in audit_logs:
        message_changed = False
        if log.message:
            for pii_type, pattern in pii_patterns.items():
                if re.search(pattern, log.message, re.IGNORECASE):
                    log.message = re.sub(pattern, f"[REDACTED-{pii_type.upper()}]", log.message, flags=re.IGNORECASE)
                    message_changed = True

        # Also check old_value and new_value JSON fields
        for field in [log.old_value, log.new_value]:
            if field:
                import json
                field_str = json.dumps(field)
                for pii_type, pattern in pii_patterns.items():
                    if re.search(pattern, field_str, re.IGNORECASE):
                        message_changed = True

        if message_changed:
            redacted_logs += 1

    if redacted_logs > 0:
        purge_results["actions_taken"].append(f"Redacted PII from {redacted_logs} audit log entries")

    # 4. Create audit log for purge action
    audit_log = AuditLog(
        action=AuditAction.SECURITY_ALERT,
        severity=AuditSeverity.WARNING,
        agent_id=agent.id,
        message=f"PII purge executed for agent '{agent.name}'",
        new_value=purge_results,
    )
    db.add(audit_log)
    await db.commit()
    asyncio.ensure_future(publish_from_audit_log(audit_log))

    logger.info(f"PII purge completed for agent {agent_id}: {len(purge_results['actions_taken'])} actions taken")

    return {
        "status": "success",
        "message": f"PII purge completed for agent {agent.name}",
        "results": purge_results,
        "note": "For complete PII removal from OpenClaw, also run: openclaw agent --purge-pii",
    }


@router.post("/{agent_id}/whitelist-ip", openapi_extra={"x-internal": True})
async def whitelist_ip(
    agent_id: UUID,
    ip_address: str,
    db: DbSessionDep,
    redis: RedisDep,
    org_id: OptionalOrgIdDep,
    ttl_hours: int = 24,
):
    """
    Whitelist an IP address for network egress.

    Use this after receiving an alert for a legitimate IP connection
    to prevent alert flooding. The whitelist entry expires after ttl_hours.
    """
    import re

    # Validate IP address format
    ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if not re.match(ip_pattern, ip_address):
        # Also allow domain names
        domain_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$"
        if not re.match(domain_pattern, ip_address):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid IP address or hostname format",
            )

    # Verify agent exists
    stmt = select(Agent).where(Agent.id == agent_id, Agent.is_deleted == False)
    agent = (await db.execute(stmt)).scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    await verify_resource_org(agent.organization_id, org_id)

    # Add to whitelist set in Redis with TTL
    whitelist_key = f"network_whitelist:{agent_id}"
    await redis.sadd(whitelist_key, ip_address)
    await redis.expire(whitelist_key, ttl_hours * 3600)

    # Create audit log
    audit_log = AuditLog(
        action=AuditAction.SECURITY_ALERT,
        severity=AuditSeverity.INFO,
        agent_id=agent.id,
        message=f"IP/host '{ip_address}' whitelisted for network egress",
        new_value={"ip_address": ip_address, "ttl_hours": ttl_hours},
    )
    db.add(audit_log)
    await db.commit()
    asyncio.ensure_future(publish_from_audit_log(audit_log))

    return {
        "status": "success",
        "message": f"IP {ip_address} whitelisted for agent {agent.name}",
        "expires_in_hours": ttl_hours,
    }


@router.delete("/{agent_id}/whitelist-ip")
async def remove_whitelisted_ip(
    agent_id: UUID,
    ip_address: str,
    db: DbSessionDep,
    redis: RedisDep,
    org_id: OptionalOrgIdDep,
):
    """Remove an IP address from the whitelist."""
    # Verify agent belongs to caller's org
    stmt = select(Agent).where(Agent.id == agent_id, Agent.is_deleted == False)
    agent = (await db.execute(stmt)).scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    await verify_resource_org(agent.organization_id, org_id)

    whitelist_key = f"network_whitelist:{agent_id}"
    removed = await redis.srem(whitelist_key, ip_address)

    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IP {ip_address} not found in whitelist",
        )

    return {"status": "success", "message": f"IP {ip_address} removed from whitelist"}


@router.get("/{agent_id}/whitelist-ip")
async def list_whitelisted_ips(
    agent_id: UUID,
    redis: RedisDep,
):
    """List all whitelisted IPs for an agent."""
    whitelist_key = f"network_whitelist:{agent_id}"
    ips = await redis.smembers(whitelist_key)
    ttl = await redis.ttl(whitelist_key)

    return {
        "agent_id": str(agent_id),
        "whitelisted_ips": list(ips) if ips else [],
        "expires_in_seconds": ttl if ttl > 0 else None,
    }


@router.post("/verify-key", openapi_extra={"x-internal": True})
async def verify_api_key(
    db: DbSessionDep,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    """
    Verify an agent's API key is valid.

    Returns agent info if the key matches, or 401 if invalid.
    Use this to detect key mismatches (e.g. after deploy.sh re-runs
    or key rotations) before they cause silent auth failures.
    """
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-API-Key header required",
        )

    stmt = select(Agent).where(
        Agent.api_key == x_api_key,
        Agent.is_deleted == False,
    )
    agent = (await db.execute(stmt)).scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    return {
        "valid": True,
        "agent_id": str(agent.id),
        "agent_name": agent.name,
        "external_id": agent.external_id,
        "status": agent.status,
    }


@router.post("/cleanup-test", openapi_extra={"x-internal": True})
async def cleanup_test_agents(
    db: DbSessionDep,
    confirm: bool = Query(False),
):
    """Hard-delete agents whose names match common test patterns.

    Requires confirm=true as a safety check. Intended for CI/CD teardown
    to remove orphaned E2E and unit-test agents from the database.
    """
    if not confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Requires confirm=true query parameter",
        )

    test_prefixes = (
        "E2E",
        "Test ",
        "Suspend Test",
        "Activate Test",
        "API Key",
        "Show Key",
        "Regen Key",
        "Quarantine Test",
        "Bulk Test",
        "Quick Test",
        "Delete Test",
        "Duplicate Test",
        "ThreatSim",
    )
    # Also match wizard agent names (created by setup wizard E2E tests)
    wizard_names = ("OpenClaw", "Claude Code", "Cursor", "Windsurf", "Cline")
    wizard_conditions = [Agent.name == n for n in wizard_names]

    # Find agents matching any test prefix or wizard name
    conditions = [Agent.name.ilike(f"{p}%") for p in test_prefixes]
    conditions.extend(wizard_conditions)
    stmt = select(Agent).where(or_(*conditions))
    result = await db.execute(stmt)
    agents = list(result.scalars().all())

    if not agents:
        return {"deleted": 0, "message": "No test agents found"}

    for agent in agents:
        await db.delete(agent)

    await db.commit()

    logger.info(f"Cleaned up {len(agents)} test agents")
    return {
        "deleted": len(agents),
        "names": [a.name for a in agents],
    }


@router.post("/{agent_id}/reset-trust")
async def reset_agent_trust(
    agent_id: UUID,
    db: DbSessionDep,
    redis: RedisDep,
    org_id: OptionalOrgIdDep,
):
    """
    Reset an agent's adaptive trust score to 1.0.

    Clears the Redis trust key and updates the database trust_score field.
    Use this when trust has degraded and you want a fresh start.
    """
    stmt = select(Agent).where(Agent.id == agent_id, Agent.is_deleted == False)
    agent = (await db.execute(stmt)).scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    await verify_resource_org(agent.organization_id, org_id)

    old_trust = agent.trust_score

    # Clear Redis trust key
    trust_key = f"trust:rate:{agent_id}"
    await redis.delete(trust_key)

    # Update database
    agent.trust_score = 1.0

    # Audit log
    audit_log = AuditLog(
        action=AuditAction.AGENT_UPDATED,
        severity=AuditSeverity.INFO,
        agent_id=agent.id,
        message=f"Trust score reset for agent '{agent.name}'",
        old_value={"trust_score": old_trust},
        new_value={"trust_score": 1.0},
    )
    db.add(audit_log)

    await db.commit()
    asyncio.ensure_future(publish_from_audit_log(audit_log))
    await db.refresh(agent)

    logger.info(f"Trust score reset for agent {agent_id}: {old_trust} -> 1.0")

    return {
        "trust_score": 1.0,
        "agent_id": str(agent.id),
        "agent_name": agent.name,
    }


@router.post("/{agent_id}/toggle-trust")
async def toggle_agent_trust(
    agent_id: UUID,
    db: DbSessionDep,
    org_id: OptionalOrgIdDep,
):
    """
    Toggle adaptive trust enforcement for an agent.

    When enabled (auto_adjust_trust=True), the trust score actively
    scales the agent's rate limit. When disabled, the trust score is
    still tracked for informational display but doesn't affect limits.
    """
    stmt = select(Agent).where(Agent.id == agent_id, Agent.is_deleted == False)
    agent = (await db.execute(stmt)).scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    await verify_resource_org(agent.organization_id, org_id)

    old_value = agent.auto_adjust_trust
    agent.auto_adjust_trust = not old_value

    audit_log = AuditLog(
        action=AuditAction.AGENT_UPDATED,
        severity=AuditSeverity.INFO,
        agent_id=agent.id,
        message=f"Trust enforcement {'enabled' if agent.auto_adjust_trust else 'disabled'} for agent '{agent.name}'",
        old_value={"auto_adjust_trust": old_value},
        new_value={"auto_adjust_trust": agent.auto_adjust_trust},
    )
    db.add(audit_log)

    await db.commit()
    asyncio.ensure_future(publish_from_audit_log(audit_log))
    await db.refresh(agent)

    return {
        "agent_id": str(agent.id),
        "agent_name": agent.name,
        "auto_adjust_trust": agent.auto_adjust_trust,
        "trust_score": agent.trust_score,
    }
