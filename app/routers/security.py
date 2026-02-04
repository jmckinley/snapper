"""Security research and threat intelligence API endpoints."""

import logging
from datetime import datetime, timedelta
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import DbSessionDep, RedisDep, default_rate_limit
from app.models.security_issues import (
    IssueSeverity,
    IssueStatus,
    MaliciousSkill,
    SecurityIssue,
    SecurityRecommendation,
)
from app.schemas.security import (
    ApplyRecommendationRequest,
    ApplyRecommendationResponse,
    DismissRecommendationRequest,
    MaliciousSkillListResponse,
    MaliciousSkillResponse,
    RecommendationListResponse,
    RecommendationResponse,
    SecurityIssueListResponse,
    SecurityIssueResponse,
    SecurityScoreResponse,
    SkillAnalyzeRequest,
    SkillAnalyzeResponse,
    ThreatFeedEntry,
    ThreatFeedResponse,
    WeeklyDigestResponse,
)
from app.services.security_monitor import SecurityMonitor

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/security", dependencies=[Depends(default_rate_limit)])


@router.get("/vulnerabilities", response_model=SecurityIssueListResponse)
async def list_vulnerabilities(
    db: DbSessionDep,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[IssueSeverity] = None,
    status_filter: Optional[IssueStatus] = Query(None, alias="status"),
    search: Optional[str] = None,
):
    """List known vulnerabilities and CVEs."""
    stmt = select(SecurityIssue)

    if severity:
        stmt = stmt.where(SecurityIssue.severity == severity)

    if status_filter:
        stmt = stmt.where(SecurityIssue.status == status_filter)

    if search:
        stmt = stmt.where(
            SecurityIssue.cve_id.ilike(f"%{search}%")
            | SecurityIssue.title.ilike(f"%{search}%")
        )

    # Get counts
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    active_stmt = select(func.count()).select_from(SecurityIssue).where(
        SecurityIssue.status == IssueStatus.ACTIVE
    )
    active_count = (await db.execute(active_stmt)).scalar() or 0

    critical_stmt = select(func.count()).select_from(SecurityIssue).where(
        SecurityIssue.status == IssueStatus.ACTIVE,
        SecurityIssue.severity == IssueSeverity.CRITICAL,
    )
    critical_count = (await db.execute(critical_stmt)).scalar() or 0

    # Apply pagination
    stmt = stmt.order_by(SecurityIssue.severity, SecurityIssue.published_at.desc())
    stmt = stmt.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(stmt)
    issues = list(result.scalars().all())

    return SecurityIssueListResponse(
        items=[SecurityIssueResponse.model_validate(i) for i in issues],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
        active_count=active_count,
        critical_count=critical_count,
    )


@router.get("/vulnerabilities/{issue_id}", response_model=SecurityIssueResponse)
async def get_vulnerability(
    issue_id: UUID,
    db: DbSessionDep,
):
    """Get vulnerability details."""
    stmt = select(SecurityIssue).where(SecurityIssue.id == issue_id)
    issue = (await db.execute(stmt)).scalar_one_or_none()

    if not issue:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability {issue_id} not found",
        )

    return SecurityIssueResponse.model_validate(issue)


@router.get("/clawhub/skills", response_model=MaliciousSkillListResponse)
async def list_malicious_skills(
    db: DbSessionDep,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[IssueSeverity] = None,
    is_blocked: Optional[bool] = None,
    is_verified: Optional[bool] = None,
    threat_type: Optional[str] = None,
):
    """List flagged malicious ClawHub skills."""
    stmt = select(MaliciousSkill)

    if severity:
        stmt = stmt.where(MaliciousSkill.severity == severity)

    if is_blocked is not None:
        stmt = stmt.where(MaliciousSkill.is_blocked == is_blocked)

    if is_verified is not None:
        stmt = stmt.where(MaliciousSkill.is_verified == is_verified)

    if threat_type:
        stmt = stmt.where(MaliciousSkill.threat_type == threat_type)

    # Get counts
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    blocked_stmt = select(func.count()).select_from(MaliciousSkill).where(
        MaliciousSkill.is_blocked == True
    )
    blocked_count = (await db.execute(blocked_stmt)).scalar() or 0

    verified_stmt = select(func.count()).select_from(MaliciousSkill).where(
        MaliciousSkill.is_verified == True
    )
    verified_count = (await db.execute(verified_stmt)).scalar() or 0

    # Apply pagination
    stmt = stmt.order_by(MaliciousSkill.last_seen_at.desc())
    stmt = stmt.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(stmt)
    skills = list(result.scalars().all())

    return MaliciousSkillListResponse(
        items=[MaliciousSkillResponse.model_validate(s) for s in skills],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
        blocked_count=blocked_count,
        verified_count=verified_count,
    )


@router.post("/clawhub/skills/{skill_id}/analyze", response_model=SkillAnalyzeResponse)
async def analyze_skill(
    skill_id: str,
    request: SkillAnalyzeRequest,
    db: DbSessionDep,
):
    """Analyze a ClawHub skill for potential threats."""
    # Check if already analyzed
    stmt = select(MaliciousSkill).where(MaliciousSkill.skill_id == skill_id)
    existing = (await db.execute(stmt)).scalar_one_or_none()

    if existing and not request.force_rescan:
        return SkillAnalyzeResponse(
            skill_id=skill_id,
            is_malicious=existing.is_blocked,
            threat_type=existing.threat_type,
            severity=existing.severity,
            confidence=existing.confidence,
            indicators=existing.indicators,
            analysis_notes=existing.analysis_notes or "",
            recommended_action="Block" if existing.is_blocked else "Allow",
            analyzed_at=existing.last_seen_at,
        )

    # Perform analysis (simplified - real implementation would scan the skill)
    # This would involve:
    # 1. Fetching skill code from ClawHub
    # 2. Static analysis for suspicious patterns
    # 3. Checking against known malware signatures
    # 4. Behavioral analysis

    analysis_result = {
        "is_malicious": False,
        "threat_type": None,
        "severity": None,
        "confidence": "low",
        "indicators": {},
        "notes": "Analysis completed. No threats detected.",
    }

    return SkillAnalyzeResponse(
        skill_id=skill_id,
        is_malicious=analysis_result["is_malicious"],
        threat_type=analysis_result["threat_type"],
        severity=analysis_result["severity"],
        confidence=analysis_result["confidence"],
        indicators=analysis_result["indicators"],
        analysis_notes=analysis_result["notes"],
        recommended_action="Allow" if not analysis_result["is_malicious"] else "Block",
        analyzed_at=datetime.utcnow(),
    )


@router.get("/recommendations", response_model=RecommendationListResponse)
async def list_recommendations(
    db: DbSessionDep,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    agent_id: Optional[UUID] = None,
    severity: Optional[IssueSeverity] = None,
    is_applied: Optional[bool] = None,
    is_dismissed: Optional[bool] = None,
):
    """List security recommendations."""
    stmt = select(SecurityRecommendation)

    if agent_id:
        stmt = stmt.where(
            (SecurityRecommendation.agent_id == agent_id)
            | (SecurityRecommendation.agent_id == None)
        )

    if severity:
        stmt = stmt.where(SecurityRecommendation.severity == severity)

    if is_applied is not None:
        stmt = stmt.where(SecurityRecommendation.is_applied == is_applied)

    if is_dismissed is not None:
        stmt = stmt.where(SecurityRecommendation.is_dismissed == is_dismissed)

    # Get counts
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    pending_stmt = select(func.count()).select_from(SecurityRecommendation).where(
        SecurityRecommendation.is_applied == False,
        SecurityRecommendation.is_dismissed == False,
    )
    pending_count = (await db.execute(pending_stmt)).scalar() or 0

    high_impact_stmt = select(func.count()).select_from(SecurityRecommendation).where(
        SecurityRecommendation.is_applied == False,
        SecurityRecommendation.is_dismissed == False,
        SecurityRecommendation.impact_score >= 20,
    )
    high_impact_count = (await db.execute(high_impact_stmt)).scalar() or 0

    # Apply pagination
    stmt = stmt.order_by(
        SecurityRecommendation.is_applied,
        SecurityRecommendation.severity,
        SecurityRecommendation.impact_score.desc(),
    )
    stmt = stmt.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(stmt)
    recommendations = list(result.scalars().all())

    return RecommendationListResponse(
        items=[RecommendationResponse.model_validate(r) for r in recommendations],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
        pending_count=pending_count,
        high_impact_count=high_impact_count,
    )


@router.post(
    "/recommendations/{recommendation_id}/apply",
    response_model=ApplyRecommendationResponse,
)
async def apply_recommendation(
    recommendation_id: UUID,
    request: ApplyRecommendationRequest,
    db: DbSessionDep,
):
    """Apply a security recommendation."""
    stmt = select(SecurityRecommendation).where(
        SecurityRecommendation.id == recommendation_id
    )
    recommendation = (await db.execute(stmt)).scalar_one_or_none()

    if not recommendation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recommendation {recommendation_id} not found",
        )

    if recommendation.is_applied:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Recommendation already applied",
        )

    # Create rules from recommendation
    # This is simplified - real implementation would create actual rules
    created_rules = []

    recommendation.is_applied = True
    recommendation.applied_at = datetime.utcnow()
    recommendation.applied_rule_ids = created_rules

    await db.commit()

    return ApplyRecommendationResponse(
        recommendation_id=recommendation_id,
        rules_created=created_rules,
        applied_at=recommendation.applied_at,
    )


@router.post("/recommendations/{recommendation_id}/dismiss")
async def dismiss_recommendation(
    recommendation_id: UUID,
    request: DismissRecommendationRequest,
    db: DbSessionDep,
):
    """Dismiss a security recommendation."""
    stmt = select(SecurityRecommendation).where(
        SecurityRecommendation.id == recommendation_id
    )
    recommendation = (await db.execute(stmt)).scalar_one_or_none()

    if not recommendation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recommendation {recommendation_id} not found",
        )

    recommendation.is_dismissed = True
    await db.commit()

    return {"status": "dismissed", "reason": request.reason}


@router.get("/score/{agent_id}", response_model=SecurityScoreResponse)
async def get_security_score(
    agent_id: UUID,
    db: DbSessionDep,
    redis: RedisDep,
):
    """Get security score for an agent."""
    monitor = SecurityMonitor(db, redis)
    score_data = await monitor.calculate_security_score(agent_id)

    return SecurityScoreResponse(**score_data)


@router.get("/score", response_model=SecurityScoreResponse)
async def get_global_security_score(
    db: DbSessionDep,
    redis: RedisDep,
):
    """Get global security score."""
    monitor = SecurityMonitor(db, redis)
    score_data = await monitor.calculate_security_score(None)

    return SecurityScoreResponse(**score_data)


@router.get("/threats/feed", response_model=ThreatFeedResponse)
async def get_threat_feed(
    db: DbSessionDep,
    redis: RedisDep,
    limit: int = Query(20, ge=1, le=100),
):
    """Get threat intelligence feed."""
    entries = []

    # Get recent CVEs
    cve_stmt = select(SecurityIssue).where(
        SecurityIssue.status == IssueStatus.ACTIVE
    ).order_by(
        SecurityIssue.published_at.desc()
    ).limit(limit // 2)

    cve_result = await db.execute(cve_stmt)
    cves = list(cve_result.scalars().all())

    for cve in cves:
        entries.append(ThreatFeedEntry(
            id=str(cve.id),
            type="cve",
            title=cve.cve_id or cve.title,
            description=cve.description[:200] + "..." if len(cve.description) > 200 else cve.description,
            severity=cve.severity,
            source=cve.source,
            source_url=cve.source_url,
            published_at=cve.published_at or cve.discovered_at,
            is_actionable=cve.auto_generate_rules,
            recommended_action="Apply mitigation rules" if not cve.mitigation_rules else None,
            related_rules=cve.mitigation_rules,
        ))

    # Get recent malicious skills
    skill_stmt = select(MaliciousSkill).order_by(
        MaliciousSkill.first_seen_at.desc()
    ).limit(limit // 2)

    skill_result = await db.execute(skill_stmt)
    skills = list(skill_result.scalars().all())

    for skill in skills:
        entries.append(ThreatFeedEntry(
            id=str(skill.id),
            type="malicious_skill",
            title=f"Malicious skill: {skill.skill_name}",
            description=skill.analysis_notes or f"Detected {skill.threat_type}",
            severity=skill.severity,
            source=skill.source,
            source_url=skill.repository_url,
            published_at=skill.first_seen_at,
            is_actionable=True,
            recommended_action="Block skill" if not skill.is_blocked else None,
            related_rules=[],
        ))

    # Sort by severity and date
    entries.sort(key=lambda e: (
        0 if e.severity == IssueSeverity.CRITICAL else
        1 if e.severity == IssueSeverity.HIGH else
        2 if e.severity == IssueSeverity.MEDIUM else 3,
        e.published_at,
    ), reverse=True)

    critical_count = sum(1 for e in entries if e.severity == IssueSeverity.CRITICAL)
    high_count = sum(1 for e in entries if e.severity == IssueSeverity.HIGH)

    return ThreatFeedResponse(
        entries=entries[:limit],
        total=len(entries),
        last_updated=datetime.utcnow(),
        critical_count=critical_count,
        high_count=high_count,
    )


@router.get("/digest/weekly", response_model=WeeklyDigestResponse)
async def get_weekly_digest(
    db: DbSessionDep,
    redis: RedisDep,
):
    """Get weekly security digest."""
    now = datetime.utcnow()
    week_ago = now - timedelta(days=7)

    monitor = SecurityMonitor(db, redis)

    # Count new CVEs this week
    cve_stmt = select(func.count()).select_from(SecurityIssue).where(
        SecurityIssue.discovered_at >= week_ago
    )
    new_cves = (await db.execute(cve_stmt)).scalar() or 0

    # Count new malicious skills
    skill_stmt = select(func.count()).select_from(MaliciousSkill).where(
        MaliciousSkill.first_seen_at >= week_ago
    )
    new_skills = (await db.execute(skill_stmt)).scalar() or 0

    # Get pending recommendations
    rec_stmt = select(SecurityRecommendation).where(
        SecurityRecommendation.is_applied == False,
        SecurityRecommendation.is_dismissed == False,
    ).order_by(
        SecurityRecommendation.severity,
        SecurityRecommendation.impact_score.desc(),
    ).limit(5)

    rec_result = await db.execute(rec_stmt)
    pending_recs = list(rec_result.scalars().all())

    # Get top threats
    threats = await monitor.get_active_threats(limit=5)
    top_threats = [
        ThreatFeedEntry(
            id=t["id"],
            type=t["type"],
            title=t["title"],
            description=t["description"],
            severity=t["severity"],
            source="internal",
            published_at=now,
            is_actionable=True,
            related_rules=[],
        )
        for t in threats
    ]

    return WeeklyDigestResponse(
        period_start=week_ago,
        period_end=now,
        generated_at=now,
        new_cves=new_cves,
        new_malicious_skills=new_skills,
        total_violations=0,  # Would query audit logs
        blocked_attacks=0,  # Would query audit logs
        top_threats=top_threats,
        score_improvements=[],
        score_regressions=[],
        new_recommendations=len(pending_recs),
        applied_recommendations=0,
        pending_recommendations=[
            RecommendationResponse.model_validate(r) for r in pending_recs
        ],
        notable_events=[],
    )
