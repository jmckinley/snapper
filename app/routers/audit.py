"""Audit and compliance API endpoints."""

import logging
from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import DbSessionDep, RedisDep, default_rate_limit
from app.models.audit_logs import (
    Alert,
    AuditAction,
    AuditLog,
    AuditSeverity,
    PolicyViolation,
)
from app.models.agents import Agent
from app.models.rules import Rule
from app.schemas.audit import (
    AlertAcknowledge,
    AlertListResponse,
    AlertResponse,
    AuditLogFilterRequest,
    AuditLogListResponse,
    AuditLogResponse,
    AuditStatsResponse,
    ComplianceReportResponse,
    DailyBreakdown,
    DailyStatsResponse,
    HourlyBreakdown,
    ViolationListResponse,
    ViolationResolve,
    ViolationResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/audit", dependencies=[Depends(default_rate_limit)])


@router.get("/stats", response_model=AuditStatsResponse)
async def get_audit_stats(
    db: DbSessionDep,
    hours: int = Query(24, ge=1, le=168),
):
    """Get aggregated audit stats for the dashboard.

    Returns total evaluations, allowed/denied/pending counts,
    and an hourly breakdown for chart rendering.
    """
    since = datetime.utcnow() - timedelta(hours=hours)

    # Count evaluations by action type
    count_stmt = (
        select(AuditLog.action, func.count().label("cnt"))
        .where(
            AuditLog.created_at >= since,
            AuditLog.action.in_([
                AuditAction.REQUEST_ALLOWED,
                AuditAction.REQUEST_DENIED,
                AuditAction.REQUEST_PENDING_APPROVAL,
            ]),
        )
        .group_by(AuditLog.action)
    )
    count_result = await db.execute(count_stmt)
    counts = {row.action: row.cnt for row in count_result}

    allowed_count = counts.get(AuditAction.REQUEST_ALLOWED, 0)
    denied_count = counts.get(AuditAction.REQUEST_DENIED, 0)
    pending_count = counts.get(AuditAction.REQUEST_PENDING_APPROVAL, 0)
    total_evaluations = allowed_count + denied_count + pending_count

    # Hourly breakdown using date_trunc
    hour_col = func.date_trunc("hour", AuditLog.created_at).label("hour")
    hourly_stmt = (
        select(
            hour_col,
            AuditLog.action,
            func.count().label("cnt"),
        )
        .where(
            AuditLog.created_at >= since,
            AuditLog.action.in_([
                AuditAction.REQUEST_ALLOWED,
                AuditAction.REQUEST_DENIED,
            ]),
        )
        .group_by(hour_col, AuditLog.action)
        .order_by(hour_col)
    )
    hourly_result = await db.execute(hourly_stmt)

    # Build a map of hour -> {allowed, denied}
    hourly_map: dict[str, dict[str, int]] = {}
    for row in hourly_result:
        hour_str = row.hour.strftime("%Y-%m-%dT%H:00")
        if hour_str not in hourly_map:
            hourly_map[hour_str] = {"allowed": 0, "denied": 0}
        if row.action == AuditAction.REQUEST_ALLOWED:
            hourly_map[hour_str]["allowed"] = row.cnt
        elif row.action == AuditAction.REQUEST_DENIED:
            hourly_map[hour_str]["denied"] = row.cnt

    hourly_breakdown = [
        HourlyBreakdown(hour=h, allowed=v["allowed"], denied=v["denied"])
        for h, v in sorted(hourly_map.items())
    ]

    return AuditStatsResponse(
        total_evaluations=total_evaluations,
        allowed_count=allowed_count,
        denied_count=denied_count,
        pending_count=pending_count,
        hourly_breakdown=hourly_breakdown,
    )


@router.get("/stats/daily", response_model=DailyStatsResponse)
async def get_daily_stats(
    db: DbSessionDep,
    days: int = Query(7, ge=1, le=30),
    agent_id: Optional[UUID] = None,
):
    """Get daily breakdown of allowed/denied/pending for the last N days.

    Optionally filter by agent_id for per-agent charts.
    """
    since = datetime.utcnow() - timedelta(days=days)

    day_col = func.date_trunc("day", AuditLog.created_at).label("day")
    stmt = (
        select(
            day_col,
            AuditLog.action,
            func.count().label("cnt"),
        )
        .where(
            AuditLog.created_at >= since,
            AuditLog.action.in_([
                AuditAction.REQUEST_ALLOWED,
                AuditAction.REQUEST_DENIED,
                AuditAction.REQUEST_PENDING_APPROVAL,
            ]),
        )
        .group_by(day_col, AuditLog.action)
        .order_by(day_col)
    )

    if agent_id:
        stmt = stmt.where(AuditLog.agent_id == agent_id)

    result = await db.execute(stmt)

    # Build map: date -> {allowed, denied, pending}
    daily_map: dict[str, dict[str, int]] = {}
    # Pre-fill all days so chart has no gaps
    for i in range(days):
        d = (datetime.utcnow() - timedelta(days=days - 1 - i)).strftime("%Y-%m-%d")
        daily_map[d] = {"allowed": 0, "denied": 0, "pending": 0}

    for row in result:
        day_str = row.day.strftime("%Y-%m-%d")
        if day_str not in daily_map:
            daily_map[day_str] = {"allowed": 0, "denied": 0, "pending": 0}
        if row.action == AuditAction.REQUEST_ALLOWED:
            daily_map[day_str]["allowed"] = row.cnt
        elif row.action == AuditAction.REQUEST_DENIED:
            daily_map[day_str]["denied"] = row.cnt
        elif row.action == AuditAction.REQUEST_PENDING_APPROVAL:
            daily_map[day_str]["pending"] = row.cnt

    daily_breakdown = [
        DailyBreakdown(date=d, **v) for d, v in sorted(daily_map.items())
    ]

    # Get agent name if filtering by agent
    agent_name = None
    if agent_id:
        agent_result = await db.execute(
            select(Agent.name).where(Agent.id == agent_id)
        )
        agent_name = agent_result.scalar_one_or_none()

    return DailyStatsResponse(
        days=days,
        agent_id=agent_id,
        agent_name=agent_name,
        daily_breakdown=daily_breakdown,
    )


@router.get("/logs", response_model=AuditLogListResponse)
async def list_audit_logs(
    db: DbSessionDep,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    agent_id: Optional[UUID] = None,
    rule_id: Optional[UUID] = None,
    action: Optional[AuditAction] = None,
    severity: Optional[AuditSeverity] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    request_id: Optional[str] = None,
):
    """List audit logs with filtering."""
    stmt = select(AuditLog)

    if agent_id:
        stmt = stmt.where(AuditLog.agent_id == agent_id)

    if rule_id:
        stmt = stmt.where(AuditLog.rule_id == rule_id)

    if action:
        stmt = stmt.where(AuditLog.action == action)

    if severity:
        stmt = stmt.where(AuditLog.severity == severity)

    if start_date:
        stmt = stmt.where(AuditLog.created_at >= start_date)

    if end_date:
        stmt = stmt.where(AuditLog.created_at <= end_date)

    if request_id:
        stmt = stmt.where(AuditLog.request_id == request_id)

    # Get total count
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    # Apply pagination
    stmt = stmt.order_by(AuditLog.created_at.desc())
    stmt = stmt.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(stmt)
    logs = list(result.scalars().all())

    return AuditLogListResponse(
        items=[AuditLogResponse.model_validate(log) for log in logs],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.get("/logs/stream")
async def stream_audit_logs(
    db: DbSessionDep,
    agent_id: Optional[UUID] = None,
    severity: Optional[AuditSeverity] = None,
):
    """
    Stream audit logs via Server-Sent Events.

    This provides real-time audit log updates.
    """
    import asyncio
    import json

    async def event_generator():
        last_id = None

        while True:
            # Query for new logs
            stmt = select(AuditLog).order_by(AuditLog.created_at.desc()).limit(10)

            if last_id:
                stmt = stmt.where(AuditLog.id > last_id)

            if agent_id:
                stmt = stmt.where(AuditLog.agent_id == agent_id)

            if severity:
                stmt = stmt.where(AuditLog.severity == severity)

            result = await db.execute(stmt)
            logs = list(result.scalars().all())

            for log in reversed(logs):  # Send oldest first
                data = {
                    "id": str(log.id),
                    "action": log.action,
                    "severity": log.severity,
                    "message": log.message,
                    "created_at": log.created_at.isoformat(),
                }
                yield f"data: {json.dumps(data)}\n\n"
                last_id = log.id

            await asyncio.sleep(2)  # Poll every 2 seconds

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )


@router.get("/violations", response_model=ViolationListResponse)
async def list_violations(
    db: DbSessionDep,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    agent_id: Optional[UUID] = None,
    severity: Optional[AuditSeverity] = None,
    is_resolved: Optional[bool] = None,
    violation_type: Optional[str] = None,
):
    """List policy violations."""
    stmt = select(PolicyViolation)

    if agent_id:
        stmt = stmt.where(PolicyViolation.agent_id == agent_id)

    if severity:
        stmt = stmt.where(PolicyViolation.severity == severity)

    if is_resolved is not None:
        stmt = stmt.where(PolicyViolation.is_resolved == is_resolved)

    if violation_type:
        stmt = stmt.where(PolicyViolation.violation_type == violation_type)

    # Get counts
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    unresolved_stmt = select(func.count()).select_from(PolicyViolation).where(
        PolicyViolation.is_resolved == False
    )
    unresolved_count = (await db.execute(unresolved_stmt)).scalar() or 0

    # Apply pagination
    stmt = stmt.order_by(
        PolicyViolation.is_resolved,
        PolicyViolation.severity,
        PolicyViolation.created_at.desc(),
    )
    stmt = stmt.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(stmt)
    violations = list(result.scalars().all())

    return ViolationListResponse(
        items=[ViolationResponse.model_validate(v) for v in violations],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
        unresolved_count=unresolved_count,
    )


@router.post("/violations/{violation_id}/resolve", response_model=ViolationResponse)
async def resolve_violation(
    violation_id: UUID,
    request: ViolationResolve,
    db: DbSessionDep,
):
    """Resolve a policy violation."""
    stmt = select(PolicyViolation).where(PolicyViolation.id == violation_id)
    violation = (await db.execute(stmt)).scalar_one_or_none()

    if not violation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Violation {violation_id} not found",
        )

    violation.is_resolved = True
    violation.resolved_at = datetime.utcnow()
    violation.resolution_notes = request.resolution_notes

    await db.commit()
    await db.refresh(violation)

    return ViolationResponse.model_validate(violation)


@router.get("/alerts", response_model=AlertListResponse)
async def list_alerts(
    db: DbSessionDep,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    agent_id: Optional[UUID] = None,
    severity: Optional[AuditSeverity] = None,
    is_acknowledged: Optional[bool] = None,
    alert_type: Optional[str] = None,
):
    """List security alerts."""
    stmt = select(Alert)

    if agent_id:
        stmt = stmt.where(Alert.agent_id == agent_id)

    if severity:
        stmt = stmt.where(Alert.severity == severity)

    if is_acknowledged is not None:
        stmt = stmt.where(Alert.is_acknowledged == is_acknowledged)

    if alert_type:
        stmt = stmt.where(Alert.alert_type == alert_type)

    # Get counts
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    unack_stmt = select(func.count()).select_from(Alert).where(
        Alert.is_acknowledged == False
    )
    unack_count = (await db.execute(unack_stmt)).scalar() or 0

    # Apply pagination
    stmt = stmt.order_by(
        Alert.is_acknowledged,
        Alert.severity,
        Alert.created_at.desc(),
    )
    stmt = stmt.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(stmt)
    alerts = list(result.scalars().all())

    return AlertListResponse(
        items=[AlertResponse.model_validate(a) for a in alerts],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
        unacknowledged_count=unack_count,
    )


@router.post("/alerts/{alert_id}/acknowledge", response_model=AlertResponse)
async def acknowledge_alert(
    alert_id: UUID,
    request: AlertAcknowledge,
    db: DbSessionDep,
):
    """Acknowledge a security alert."""
    stmt = select(Alert).where(Alert.id == alert_id)
    alert = (await db.execute(stmt)).scalar_one_or_none()

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found",
        )

    alert.is_acknowledged = True
    alert.acknowledged_at = datetime.utcnow()

    await db.commit()
    await db.refresh(alert)

    return AlertResponse.model_validate(alert)


@router.get("/reports/compliance", response_model=ComplianceReportResponse)
async def get_compliance_report(
    db: DbSessionDep,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
):
    """Generate compliance report."""
    now = datetime.utcnow()
    if not end_date:
        end_date = now
    if not start_date:
        start_date = now - timedelta(days=30)

    # Agent statistics
    total_agents = (
        await db.execute(select(func.count()).select_from(Agent).where(Agent.is_deleted == False))
    ).scalar() or 0

    active_agents = (
        await db.execute(
            select(func.count()).select_from(Agent).where(
                Agent.is_deleted == False,
                Agent.status == "active",
            )
        )
    ).scalar() or 0

    # Rule statistics
    total_rules = (
        await db.execute(select(func.count()).select_from(Rule).where(Rule.is_deleted == False))
    ).scalar() or 0

    active_rules = (
        await db.execute(
            select(func.count()).select_from(Rule).where(
                Rule.is_deleted == False,
                Rule.is_active == True,
            )
        )
    ).scalar() or 0

    # Enforcement statistics
    enforcement_stmt = select(AuditLog).where(
        AuditLog.created_at >= start_date,
        AuditLog.created_at <= end_date,
        AuditLog.action.in_([
            AuditAction.REQUEST_ALLOWED,
            AuditAction.REQUEST_DENIED,
            AuditAction.REQUEST_PENDING_APPROVAL,
        ]),
    )
    enforcement_result = await db.execute(enforcement_stmt)
    enforcement_logs = list(enforcement_result.scalars().all())

    total_evaluations = len(enforcement_logs)
    requests_allowed = sum(1 for l in enforcement_logs if l.action == AuditAction.REQUEST_ALLOWED)
    requests_denied = sum(1 for l in enforcement_logs if l.action == AuditAction.REQUEST_DENIED)
    requests_pending = sum(1 for l in enforcement_logs if l.action == AuditAction.REQUEST_PENDING_APPROVAL)

    # Violation statistics
    violations_stmt = select(PolicyViolation).where(
        PolicyViolation.created_at >= start_date,
        PolicyViolation.created_at <= end_date,
    )
    violations_result = await db.execute(violations_stmt)
    violations = list(violations_result.scalars().all())

    violations_by_severity = {}
    violations_by_type = {}
    for v in violations:
        violations_by_severity[v.severity] = violations_by_severity.get(v.severity, 0) + 1
        violations_by_type[v.violation_type] = violations_by_type.get(v.violation_type, 0) + 1

    unresolved_violations = sum(1 for v in violations if not v.is_resolved)

    # Alert statistics
    alerts_stmt = select(Alert).where(
        Alert.created_at >= start_date,
        Alert.created_at <= end_date,
    )
    alerts_result = await db.execute(alerts_stmt)
    alerts = list(alerts_result.scalars().all())

    alerts_by_severity = {}
    for a in alerts:
        alerts_by_severity[a.severity] = alerts_by_severity.get(a.severity, 0) + 1

    unacknowledged_alerts = sum(1 for a in alerts if not a.is_acknowledged)

    return ComplianceReportResponse(
        report_period_start=start_date,
        report_period_end=end_date,
        generated_at=now,
        total_agents=total_agents,
        active_agents=active_agents,
        total_rules=total_rules,
        active_rules=active_rules,
        total_evaluations=total_evaluations,
        requests_allowed=requests_allowed,
        requests_denied=requests_denied,
        requests_pending_approval=requests_pending,
        total_violations=len(violations),
        violations_by_severity=violations_by_severity,
        violations_by_type=violations_by_type,
        unresolved_violations=unresolved_violations,
        total_alerts=len(alerts),
        alerts_by_severity=alerts_by_severity,
        unacknowledged_alerts=unacknowledged_alerts,
        security_score_average=round(requests_allowed / max(total_evaluations, 1), 2),
        cves_mitigated=0,
        malicious_skills_blocked=0,
        top_violated_rules=[
            {"violation_type": v.violation_type, "severity": v.severity, "description": v.description[:100]}
            for v in sorted(violations, key=lambda x: x.created_at, reverse=True)[:5]
        ] if violations else [],
        top_violating_agents=[],
        enforcement_by_rule_type={
            "summary": {
                "denied": requests_denied,
                "allowed": requests_allowed,
                "pending_approval": requests_pending,
            },
        },
    )
