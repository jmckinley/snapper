"""Shadow AI detection API endpoints.

Provides CRUD for shadow AI detections, manual scan trigger,
and a multi-host report endpoint for enterprise discovery agents.
"""

import logging
from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func, and_

from app.config import get_settings
from app.dependencies import DbSessionDep, OptionalOrgIdDep
from app.models.audit_logs import AuditAction, AuditLog, AuditSeverity
from app.models.shadow_ai import ShadowAIDetection, ShadowAIStatus

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter(prefix="/shadow-ai")


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ShadowAIDetectionResponse(BaseModel):
    id: UUID
    detection_type: str
    process_name: Optional[str] = None
    pid: Optional[int] = None
    command_line: Optional[str] = None
    destination: Optional[str] = None
    container_id: Optional[str] = None
    container_image: Optional[str] = None
    host_identifier: str
    details: Optional[dict] = None
    status: str
    resolved_by: Optional[UUID] = None
    resolved_at: Optional[datetime] = None
    first_seen_at: datetime
    last_seen_at: datetime
    occurrence_count: int
    organization_id: Optional[UUID] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ShadowAIFindingInput(BaseModel):
    detection_type: str
    process_name: Optional[str] = None
    pid: Optional[int] = None
    command_line: Optional[str] = None
    destination: Optional[str] = None
    container_id: Optional[str] = None
    container_image: Optional[str] = None
    details: Optional[dict] = None


class ShadowAIReportRequest(BaseModel):
    host_identifier: str = Field(..., max_length=255)
    findings: List[ShadowAIFindingInput]


class ShadowAIStatsResponse(BaseModel):
    total: int
    active: int
    resolved: int
    false_positive: int
    by_type: dict
    by_host: dict


# ---------------------------------------------------------------------------
# List detections
# ---------------------------------------------------------------------------


@router.get("", response_model=List[ShadowAIDetectionResponse])
async def list_detections(
    db: DbSessionDep,
    org_id: OptionalOrgIdDep,
    status_filter: Optional[str] = Query(None, alias="status"),
    detection_type: Optional[str] = Query(None),
    host: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
):
    """List shadow AI detections with optional filters."""
    stmt = select(ShadowAIDetection)

    if org_id:
        stmt = stmt.where(ShadowAIDetection.organization_id == org_id)

    if status_filter:
        stmt = stmt.where(ShadowAIDetection.status == status_filter)
    if detection_type:
        stmt = stmt.where(ShadowAIDetection.detection_type == detection_type)
    if host:
        stmt = stmt.where(ShadowAIDetection.host_identifier == host)

    stmt = stmt.order_by(ShadowAIDetection.last_seen_at.desc()).offset(offset).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()


# ---------------------------------------------------------------------------
# Get single detection
# ---------------------------------------------------------------------------


@router.get("/stats", response_model=ShadowAIStatsResponse)
async def get_stats(
    db: DbSessionDep,
    org_id: OptionalOrgIdDep,
):
    """Get aggregate statistics for shadow AI detections."""
    base = select(ShadowAIDetection)
    if org_id:
        base = base.where(ShadowAIDetection.organization_id == org_id)

    # Total counts by status
    for_status = {}
    for s in ShadowAIStatus:
        count_q = select(func.count(ShadowAIDetection.id)).where(ShadowAIDetection.status == s)
        if org_id:
            count_q = count_q.where(ShadowAIDetection.organization_id == org_id)
        for_status[s.value] = (await db.execute(count_q)).scalar() or 0

    total = sum(for_status.values())

    # By type
    type_q = (
        select(ShadowAIDetection.detection_type, func.count(ShadowAIDetection.id))
        .where(ShadowAIDetection.status == ShadowAIStatus.ACTIVE)
    )
    if org_id:
        type_q = type_q.where(ShadowAIDetection.organization_id == org_id)
    type_q = type_q.group_by(ShadowAIDetection.detection_type)
    type_rows = (await db.execute(type_q)).all()
    by_type = {row[0]: row[1] for row in type_rows}

    # By host
    host_q = (
        select(ShadowAIDetection.host_identifier, func.count(ShadowAIDetection.id))
        .where(ShadowAIDetection.status == ShadowAIStatus.ACTIVE)
    )
    if org_id:
        host_q = host_q.where(ShadowAIDetection.organization_id == org_id)
    host_q = host_q.group_by(ShadowAIDetection.host_identifier)
    host_rows = (await db.execute(host_q)).all()
    by_host = {row[0]: row[1] for row in host_rows}

    return ShadowAIStatsResponse(
        total=total,
        active=for_status.get("active", 0),
        resolved=for_status.get("resolved", 0),
        false_positive=for_status.get("false_positive", 0),
        by_type=by_type,
        by_host=by_host,
    )


@router.get("/{detection_id}", response_model=ShadowAIDetectionResponse)
async def get_detection(
    detection_id: UUID,
    db: DbSessionDep,
    org_id: OptionalOrgIdDep,
):
    """Get a single shadow AI detection by ID."""
    detection = (
        await db.execute(
            select(ShadowAIDetection).where(ShadowAIDetection.id == detection_id)
        )
    ).scalar_one_or_none()

    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")

    return detection


# ---------------------------------------------------------------------------
# Resolve / mark false positive
# ---------------------------------------------------------------------------


@router.put("/{detection_id}/resolve", response_model=ShadowAIDetectionResponse)
async def resolve_detection(
    detection_id: UUID,
    db: DbSessionDep,
    org_id: OptionalOrgIdDep,
):
    """Mark a detection as resolved."""
    detection = (
        await db.execute(
            select(ShadowAIDetection).where(ShadowAIDetection.id == detection_id)
        )
    ).scalar_one_or_none()

    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")

    detection.status = ShadowAIStatus.RESOLVED
    detection.resolved_at = datetime.now(timezone.utc)

    audit = AuditLog(
        action=AuditAction.SHADOW_AI_RESOLVED,
        severity=AuditSeverity.INFO,
        organization_id=detection.organization_id,
        message=f"Shadow AI detection resolved: {detection.detection_type} on {detection.host_identifier}",
        details={"detection_id": str(detection.id)},
    )
    db.add(audit)
    await db.commit()
    await db.refresh(detection)

    return detection


@router.put("/{detection_id}/false-positive", response_model=ShadowAIDetectionResponse)
async def mark_false_positive(
    detection_id: UUID,
    db: DbSessionDep,
    org_id: OptionalOrgIdDep,
):
    """Mark a detection as a false positive."""
    detection = (
        await db.execute(
            select(ShadowAIDetection).where(ShadowAIDetection.id == detection_id)
        )
    ).scalar_one_or_none()

    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")

    detection.status = ShadowAIStatus.FALSE_POSITIVE
    detection.resolved_at = datetime.now(timezone.utc)

    audit = AuditLog(
        action=AuditAction.SHADOW_AI_RESOLVED,
        severity=AuditSeverity.INFO,
        organization_id=detection.organization_id,
        message=f"Shadow AI detection marked false positive: {detection.detection_type} on {detection.host_identifier}",
        details={"detection_id": str(detection.id), "status": "false_positive"},
    )
    db.add(audit)
    await db.commit()
    await db.refresh(detection)

    return detection


# ---------------------------------------------------------------------------
# Trigger manual scan
# ---------------------------------------------------------------------------


@router.post("/scan")
async def trigger_scan():
    """Trigger an immediate shadow AI scan."""
    if not settings.SHADOW_AI_DETECTION_ENABLED:
        raise HTTPException(
            status_code=400,
            detail="Shadow AI detection is disabled (set SHADOW_AI_DETECTION_ENABLED=true)",
        )

    from app.tasks.shadow_ai_scan import scan_for_shadow_ai
    task = scan_for_shadow_ai.delay()
    return {"status": "scan_queued", "task_id": str(task.id)}


# ---------------------------------------------------------------------------
# Multi-host report endpoint (enterprise discovery agents)
# ---------------------------------------------------------------------------


@router.post("/report")
async def report_findings(
    request: ShadowAIReportRequest,
    db: DbSessionDep,
    org_id: OptionalOrgIdDep,
):
    """Accept findings from a remote discovery agent.

    Remote agents (deployed on other hosts) POST their scan results here.
    Findings are upserted: existing active findings from the same host get
    their occurrence count incremented, new findings are created.
    """
    new_count = 0
    updated_count = 0

    for finding in request.findings:
        # Deduplication
        dedup_filters = [
            ShadowAIDetection.detection_type == finding.detection_type,
            ShadowAIDetection.host_identifier == request.host_identifier,
            ShadowAIDetection.status == ShadowAIStatus.ACTIVE,
        ]

        if finding.container_id:
            dedup_filters.append(ShadowAIDetection.container_id == finding.container_id)
        elif finding.destination:
            dedup_filters.append(ShadowAIDetection.destination == finding.destination)
        elif finding.process_name:
            dedup_filters.append(ShadowAIDetection.process_name == finding.process_name)

        existing = (
            await db.execute(
                select(ShadowAIDetection).where(and_(*dedup_filters))
            )
        ).scalar_one_or_none()

        if existing:
            existing.last_seen_at = datetime.now(timezone.utc)
            existing.occurrence_count += 1
            if finding.details:
                existing.details = finding.details
            updated_count += 1
        else:
            detection = ShadowAIDetection(
                detection_type=finding.detection_type,
                process_name=finding.process_name,
                pid=finding.pid,
                command_line=finding.command_line,
                destination=finding.destination,
                container_id=finding.container_id,
                container_image=finding.container_image,
                host_identifier=request.host_identifier,
                details=finding.details or {},
                status=ShadowAIStatus.ACTIVE,
                organization_id=org_id,
                first_seen_at=datetime.now(timezone.utc),
                last_seen_at=datetime.now(timezone.utc),
                occurrence_count=1,
            )
            db.add(detection)

            audit = AuditLog(
                action=AuditAction.SHADOW_AI_DETECTED,
                severity=AuditSeverity.WARNING,
                organization_id=org_id,
                message=(
                    f"Shadow AI reported by agent on {request.host_identifier}: "
                    f"{finding.detection_type} — "
                    f"{finding.process_name or finding.destination or finding.container_image or 'unknown'}"
                ),
            )
            db.add(audit)
            new_count += 1

    await db.commit()

    # Alert on new remote findings
    if new_count > 0:
        try:
            from app.tasks.alerts import send_alert
            send_alert.delay(
                title=f"Shadow AI: {new_count} New Remote Detection(s)",
                message=(
                    f"Host `{request.host_identifier}` reported {new_count} new finding(s).\n"
                    f"Updated {updated_count} existing finding(s).\n"
                    "Review in the Shadow AI dashboard."
                ),
                severity="warning",
                metadata={
                    "host": request.host_identifier,
                    "new_count": new_count,
                    "updated_count": updated_count,
                },
            )
        except Exception:
            pass

    return {"new": new_count, "updated": updated_count}
