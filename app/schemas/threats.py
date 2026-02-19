"""Pydantic schemas for threat detection endpoints."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ThreatEventResponse(BaseModel):
    """Schema for a single threat event."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    agent_id: UUID
    organization_id: Optional[UUID] = None
    threat_type: str
    severity: str
    threat_score: float
    kill_chain: Optional[str] = None
    signals: List[Dict[str, Any]] = Field(default_factory=list)
    description: str
    details: Dict[str, Any] = Field(default_factory=dict)
    status: str
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[UUID] = None
    resolution_notes: Optional[str] = None
    created_at: datetime

    # Enriched fields (populated by the router)
    agent_name: Optional[str] = None


class ThreatEventListResponse(BaseModel):
    """Schema for paginated threat event list."""

    items: List[ThreatEventResponse]
    total: int
    page: int
    page_size: int
    pages: int


class ThreatResolveRequest(BaseModel):
    """Schema for resolving a threat event."""

    status: str = Field(
        ...,
        pattern="^(resolved|false_positive)$",
        description="New status: 'resolved' or 'false_positive'",
    )
    resolution_notes: Optional[str] = Field(
        None,
        max_length=2000,
        description="Optional notes explaining the resolution",
    )


class ThreatSummaryResponse(BaseModel):
    """Summary statistics for the dashboard widget."""

    active_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    resolved_24h: int = 0
    agents_affected: int = 0
    top_threat_types: List[Dict[str, Any]] = Field(default_factory=list)


class AgentThreatScoreResponse(BaseModel):
    """Current threat score for an agent from Redis."""

    agent_id: str
    agent_name: Optional[str] = None
    threat_score: float
    threat_level: str
