"""Pydantic schemas for agent endpoints."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.agents import AgentStatus, TrustLevel


class AgentBase(BaseModel):
    """Base schema for agent data."""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    allowed_origins: List[str] = Field(default_factory=list)
    require_localhost_only: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    rate_limit_max_requests: Optional[int] = Field(None, ge=1)
    rate_limit_window_seconds: Optional[int] = Field(None, ge=1)


class AgentCreate(AgentBase):
    """Schema for creating an agent."""

    external_id: str = Field(..., min_length=1, max_length=255)
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    owner_chat_id: Optional[str] = Field(None, max_length=100, description="Telegram chat ID of agent owner")


class AgentUpdate(BaseModel):
    """Schema for updating an agent."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    status: Optional[AgentStatus] = None
    trust_level: Optional[TrustLevel] = None
    allowed_origins: Optional[List[str]] = None
    require_localhost_only: Optional[bool] = None
    metadata: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None
    rate_limit_max_requests: Optional[int] = Field(None, ge=1)
    rate_limit_window_seconds: Optional[int] = Field(None, ge=1)
    owner_chat_id: Optional[str] = None


class AgentResponse(AgentBase):
    """Schema for agent response."""

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: UUID
    external_id: str
    owner_chat_id: Optional[str] = None
    status: AgentStatus
    trust_level: TrustLevel
    api_key: str  # Agent's API key for authentication
    api_key_last_used: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    last_seen_at: Optional[datetime] = None
    last_rule_evaluation_at: Optional[datetime] = None
    is_deleted: bool = False
    trust_score: float = 1.0
    auto_adjust_trust: bool = False

    @model_validator(mode="before")
    @classmethod
    def map_agent_metadata(cls, data: Any) -> Any:
        """Map agent_metadata from SQLAlchemy model to metadata field."""
        if hasattr(data, "agent_metadata"):
            # It's an ORM object
            return {
                "id": data.id,
                "external_id": data.external_id,
                "owner_chat_id": data.owner_chat_id,
                "name": data.name,
                "description": data.description,
                "status": data.status,
                "trust_level": data.trust_level,
                "api_key": data.api_key,
                "api_key_last_used": data.api_key_last_used,
                "allowed_origins": data.allowed_origins,
                "require_localhost_only": data.require_localhost_only,
                "metadata": data.agent_metadata,
                "tags": data.tags,
                "rate_limit_max_requests": data.rate_limit_max_requests,
                "rate_limit_window_seconds": data.rate_limit_window_seconds,
                "created_at": data.created_at,
                "updated_at": data.updated_at,
                "last_seen_at": data.last_seen_at,
                "last_rule_evaluation_at": data.last_rule_evaluation_at,
                "is_deleted": data.is_deleted,
                "trust_score": data.trust_score,
                "auto_adjust_trust": data.auto_adjust_trust,
            }
        return data


class AgentStatusResponse(BaseModel):
    """Schema for real-time agent status."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    external_id: str
    name: str
    status: AgentStatus
    trust_level: TrustLevel
    is_active: bool
    last_seen_at: Optional[datetime] = None
    active_rules_count: int = 0
    recent_violations_count: int = 0
    rate_limit_remaining: Optional[int] = None


class AgentListResponse(BaseModel):
    """Schema for paginated agent list."""

    items: List[AgentResponse]
    total: int
    page: int
    page_size: int
    pages: int


class BulkAgentCreate(BaseModel):
    """Schema for bulk agent registration."""

    agents: List[AgentCreate] = Field(..., min_length=1, max_length=100)
    apply_default_rules: bool = True
    security_profile: str = Field(default="recommended", pattern="^(strict|recommended|permissive)$")


class BulkAgentResponse(BaseModel):
    """Schema for bulk agent registration response."""

    created: List[AgentResponse]
    failed: List[Dict[str, Any]]
    total_created: int
    total_failed: int
