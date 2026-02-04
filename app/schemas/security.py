"""Pydantic schemas for security endpoints."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.security_issues import IssueSeverity, IssueStatus


class SecurityIssueResponse(BaseModel):
    """Schema for security issue/CVE response."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    cve_id: Optional[str] = None
    title: str
    description: str
    severity: IssueSeverity
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    status: IssueStatus
    affected_components: List[str] = Field(default_factory=list)
    affected_versions: List[str] = Field(default_factory=list)
    mitigation_rules: List[UUID] = Field(default_factory=list)
    auto_generate_rules: bool
    mitigation_notes: Optional[str] = None
    source: str
    source_url: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    published_at: Optional[datetime] = None
    discovered_at: datetime
    mitigated_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None


class SecurityIssueListResponse(BaseModel):
    """Schema for paginated security issue list."""

    items: List[SecurityIssueResponse]
    total: int
    page: int
    page_size: int
    pages: int
    active_count: int
    critical_count: int


class MaliciousSkillResponse(BaseModel):
    """Schema for malicious skill response."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    skill_id: str
    skill_name: str
    author: Optional[str] = None
    repository_url: Optional[str] = None
    threat_type: str
    severity: IssueSeverity
    confidence: str
    analysis_notes: Optional[str] = None
    indicators: Dict[str, Any] = Field(default_factory=dict)
    is_blocked: bool
    is_verified: bool
    reported_by: Optional[str] = None
    source: str
    first_seen_at: datetime
    last_seen_at: datetime


class MaliciousSkillListResponse(BaseModel):
    """Schema for paginated malicious skill list."""

    items: List[MaliciousSkillResponse]
    total: int
    page: int
    page_size: int
    pages: int
    blocked_count: int
    verified_count: int


class SkillAnalyzeRequest(BaseModel):
    """Schema for skill analysis request."""

    skill_id: str
    repository_url: Optional[str] = None
    force_rescan: bool = False


class SkillAnalyzeResponse(BaseModel):
    """Schema for skill analysis response."""

    skill_id: str
    is_malicious: bool
    threat_type: Optional[str] = None
    severity: Optional[IssueSeverity] = None
    confidence: str
    indicators: Dict[str, Any] = Field(default_factory=dict)
    analysis_notes: str
    recommended_action: str
    analyzed_at: datetime


class RecommendationResponse(BaseModel):
    """Schema for security recommendation response."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    agent_id: Optional[UUID] = None
    title: str
    description: str
    rationale: str
    severity: IssueSeverity
    impact_score: int
    recommended_rules: Dict[str, Any] = Field(default_factory=dict)
    is_one_click: bool
    is_applied: bool
    is_dismissed: bool
    applied_at: Optional[datetime] = None
    applied_rule_ids: List[UUID] = Field(default_factory=list)
    created_at: datetime
    expires_at: Optional[datetime] = None


class RecommendationListResponse(BaseModel):
    """Schema for paginated recommendation list."""

    items: List[RecommendationResponse]
    total: int
    page: int
    page_size: int
    pages: int
    pending_count: int
    high_impact_count: int


class ApplyRecommendationRequest(BaseModel):
    """Schema for applying a recommendation."""

    parameter_overrides: Dict[str, Any] = Field(default_factory=dict)


class ApplyRecommendationResponse(BaseModel):
    """Schema for apply recommendation response."""

    recommendation_id: UUID
    rules_created: List[UUID]
    applied_at: datetime


class DismissRecommendationRequest(BaseModel):
    """Schema for dismissing a recommendation."""

    reason: Optional[str] = Field(None, max_length=500)


class SecurityScoreResponse(BaseModel):
    """Schema for security score response."""

    agent_id: Optional[UUID] = None
    score: int = Field(..., ge=0, le=100)
    grade: str  # A+, A, B+, B, C+, C, D, F
    calculated_at: datetime

    # Score breakdown
    breakdown: Dict[str, int] = Field(default_factory=dict)
    # e.g., {"rule_coverage": 25, "cve_mitigation": 20, "skill_protection": 20, ...}

    # Factors affecting score
    positive_factors: List[str] = Field(default_factory=list)
    negative_factors: List[str] = Field(default_factory=list)

    # Comparison
    previous_score: Optional[int] = None
    score_change: int = 0
    percentile: Optional[int] = None  # Compared to other agents

    # Recommendations to improve
    improvement_suggestions: List[Dict[str, Any]] = Field(default_factory=list)


class ThreatFeedEntry(BaseModel):
    """Schema for threat feed entry."""

    id: str
    type: str  # cve, malicious_skill, advisory
    title: str
    description: str
    severity: IssueSeverity
    source: str
    source_url: Optional[str] = None
    published_at: datetime
    is_actionable: bool
    recommended_action: Optional[str] = None
    related_rules: List[UUID] = Field(default_factory=list)


class ThreatFeedResponse(BaseModel):
    """Schema for threat feed response."""

    entries: List[ThreatFeedEntry]
    total: int
    last_updated: datetime
    critical_count: int
    high_count: int


class WeeklyDigestResponse(BaseModel):
    """Schema for weekly security digest."""

    period_start: datetime
    period_end: datetime
    generated_at: datetime

    # Summary
    new_cves: int
    new_malicious_skills: int
    total_violations: int
    blocked_attacks: int

    # Top threats
    top_threats: List[ThreatFeedEntry]

    # Score changes
    score_improvements: List[Dict[str, Any]]
    score_regressions: List[Dict[str, Any]]

    # Recommendations
    new_recommendations: int
    applied_recommendations: int
    pending_recommendations: List[RecommendationResponse]

    # Notable events
    notable_events: List[Dict[str, Any]]
