"""Threat detection API endpoints.

Provides read access to threat events, resolution workflow,
summary stats for the dashboard, and per-agent threat scores.
"""

import logging
import math
from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import DbSessionDep, OptionalOrgIdDep, RedisDep, default_rate_limit
from app.models.agents import Agent
from app.models.audit_logs import AuditAction, AuditLog, AuditSeverity
from app.models.threat_events import ThreatEvent
from app.schemas.threats import (
    AgentThreatScoreResponse,
    ThreatEventListResponse,
    ThreatEventResponse,
    ThreatResolveRequest,
    ThreatSummaryResponse,
)
from app.services.event_publisher import publish_from_audit_log

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/threats", dependencies=[Depends(default_rate_limit)])


# -----------------------------------------------------------------------
# List threat events
# -----------------------------------------------------------------------

@router.get("", response_model=ThreatEventListResponse)
async def list_threat_events(
    db: DbSessionDep,
    org_id: OptionalOrgIdDep = None,
    agent_id: Optional[UUID] = Query(None, description="Filter by agent"),
    severity: Optional[str] = Query(None, description="Filter by severity (critical, high, medium, low)"),
    threat_type: Optional[str] = Query(None, description="Filter by threat type"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (active, investigating, resolved, false_positive)"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
):
    """List threat events with filtering and pagination."""
    stmt = select(ThreatEvent).order_by(desc(ThreatEvent.created_at))

    # Org scoping
    if org_id:
        stmt = stmt.where(ThreatEvent.organization_id == org_id)

    if agent_id:
        stmt = stmt.where(ThreatEvent.agent_id == agent_id)
    if severity:
        stmt = stmt.where(ThreatEvent.severity == severity)
    if threat_type:
        stmt = stmt.where(ThreatEvent.threat_type == threat_type)
    if status_filter:
        stmt = stmt.where(ThreatEvent.status == status_filter)

    # Count total
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    # Paginate
    offset = (page - 1) * page_size
    stmt = stmt.offset(offset).limit(page_size)
    result = await db.execute(stmt)
    events = result.scalars().all()

    # Enrich with agent names
    agent_ids = {e.agent_id for e in events}
    agent_names = {}
    if agent_ids:
        agents_result = await db.execute(
            select(Agent.id, Agent.name).where(Agent.id.in_(agent_ids))
        )
        agent_names = {row.id: row.name for row in agents_result}

    items = []
    for event in events:
        item = ThreatEventResponse.model_validate(event)
        item.agent_name = agent_names.get(event.agent_id)
        items.append(item)

    return ThreatEventListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=math.ceil(total / page_size) if total > 0 else 0,
    )


# -----------------------------------------------------------------------
# Get single threat event
# -----------------------------------------------------------------------

@router.get("/summary", response_model=ThreatSummaryResponse)
async def get_threat_summary(
    db: DbSessionDep,
    org_id: OptionalOrgIdDep = None,
):
    """Get threat summary statistics for the dashboard widget."""
    base = select(ThreatEvent)
    if org_id:
        base = base.where(ThreatEvent.organization_id == org_id)

    # Active counts by severity
    active_base = base.where(ThreatEvent.status.in_(["active", "investigating"]))

    total_active = (await db.execute(
        select(func.count()).select_from(active_base.subquery())
    )).scalar() or 0

    critical = (await db.execute(
        select(func.count()).select_from(
            active_base.where(ThreatEvent.severity == "critical").subquery()
        )
    )).scalar() or 0

    high = (await db.execute(
        select(func.count()).select_from(
            active_base.where(ThreatEvent.severity == "high").subquery()
        )
    )).scalar() or 0

    medium = (await db.execute(
        select(func.count()).select_from(
            active_base.where(ThreatEvent.severity == "medium").subquery()
        )
    )).scalar() or 0

    low = (await db.execute(
        select(func.count()).select_from(
            active_base.where(ThreatEvent.severity == "low").subquery()
        )
    )).scalar() or 0

    # Resolved in last 24 hours
    since_24h = datetime.utcnow() - timedelta(hours=24)
    resolved_24h = (await db.execute(
        select(func.count()).select_from(
            base.where(
                ThreatEvent.status.in_(["resolved", "false_positive"]),
                ThreatEvent.resolved_at >= since_24h,
            ).subquery()
        )
    )).scalar() or 0

    # Unique agents affected (active threats)
    agents_affected = (await db.execute(
        select(func.count(func.distinct(ThreatEvent.agent_id))).select_from(
            active_base.subquery()
        )
    )).scalar() or 0

    # Top threat types
    type_counts = await db.execute(
        select(ThreatEvent.threat_type, func.count().label("count"))
        .where(ThreatEvent.status.in_(["active", "investigating"]))
        .group_by(ThreatEvent.threat_type)
        .order_by(desc("count"))
        .limit(5)
    )
    top_types = [
        {"threat_type": row.threat_type, "count": row.count}
        for row in type_counts
    ]

    return ThreatSummaryResponse(
        active_count=total_active,
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        resolved_24h=resolved_24h,
        agents_affected=agents_affected,
        top_threat_types=top_types,
    )


@router.get("/{threat_id}", response_model=ThreatEventResponse)
async def get_threat_event(
    threat_id: UUID,
    db: DbSessionDep,
):
    """Get a single threat event by ID."""
    event = (await db.execute(
        select(ThreatEvent).where(ThreatEvent.id == threat_id)
    )).scalar_one_or_none()

    if not event:
        raise HTTPException(status_code=404, detail="Threat event not found")

    # Enrich with agent name
    agent = (await db.execute(
        select(Agent.name).where(Agent.id == event.agent_id)
    )).scalar_one_or_none()

    item = ThreatEventResponse.model_validate(event)
    item.agent_name = agent
    return item


# -----------------------------------------------------------------------
# Resolve / mark false positive
# -----------------------------------------------------------------------

@router.post("/{threat_id}/resolve", response_model=ThreatEventResponse)
async def resolve_threat_event(
    threat_id: UUID,
    body: ThreatResolveRequest,
    db: DbSessionDep,
):
    """Mark a threat event as resolved or false positive."""
    event = (await db.execute(
        select(ThreatEvent).where(ThreatEvent.id == threat_id)
    )).scalar_one_or_none()

    if not event:
        raise HTTPException(status_code=404, detail="Threat event not found")

    if event.status in ("resolved", "false_positive"):
        raise HTTPException(status_code=400, detail=f"Threat already {event.status}")

    event.status = body.status
    event.resolved_at = datetime.utcnow()
    event.resolution_notes = body.resolution_notes

    # Audit log
    audit_action = (
        AuditAction.THREAT_RESOLVED
        if body.status == "resolved"
        else AuditAction.THREAT_FALSE_POSITIVE
    )
    audit = AuditLog(
        action=audit_action,
        severity=AuditSeverity.INFO,
        agent_id=event.agent_id,
        organization_id=event.organization_id,
        message=f"Threat event {body.status}: {event.threat_type} (score {event.threat_score})",
        details={
            "threat_id": str(event.id),
            "threat_type": event.threat_type,
            "resolution_notes": body.resolution_notes,
            "original_score": event.threat_score,
        },
    )
    db.add(audit)
    await db.commit()
    await db.refresh(event)

    # Publish to SIEM
    try:
        await publish_from_audit_log(audit)
    except Exception:
        pass

    # Enrich response
    agent = (await db.execute(
        select(Agent.name).where(Agent.id == event.agent_id)
    )).scalar_one_or_none()

    item = ThreatEventResponse.model_validate(event)
    item.agent_name = agent
    return item


# -----------------------------------------------------------------------
# Live threat scores (from Redis)
# -----------------------------------------------------------------------

@router.get("/scores/live", response_model=list[AgentThreatScoreResponse])
async def get_live_threat_scores(
    db: DbSessionDep,
    redis: RedisDep,
):
    """Get current live threat scores for all agents from Redis.

    Returns only agents with a non-zero threat score.
    """
    from app.services.threat_detector import classify_threat_level

    try:
        score_keys = await redis.keys("threat:score:*")
    except Exception:
        return []

    results = []
    agent_ids = []

    for key in score_keys:
        agent_id = key.replace("threat:score:", "")
        try:
            val = await redis.get(key)
            if val:
                score = float(val)
                if score > 0:
                    agent_ids.append(agent_id)
                    results.append({
                        "agent_id": agent_id,
                        "threat_score": score,
                        "threat_level": classify_threat_level(score),
                    })
        except Exception:
            continue

    # Enrich with agent names
    if agent_ids:
        try:
            agents_result = await db.execute(
                select(Agent.id, Agent.name).where(
                    Agent.id.in_([UUID(a) for a in agent_ids if len(a) == 36])
                )
            )
            name_map = {str(row.id): row.name for row in agents_result}
            for r in results:
                r["agent_name"] = name_map.get(r["agent_id"])
        except Exception:
            pass

    # Sort by score descending
    results.sort(key=lambda x: x["threat_score"], reverse=True)

    return [AgentThreatScoreResponse(**r) for r in results]
