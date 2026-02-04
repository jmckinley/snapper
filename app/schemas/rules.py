"""Pydantic schemas for rule endpoints."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.rules import RuleAction, RuleType


class RuleBase(BaseModel):
    """Base schema for rule data."""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    rule_type: RuleType
    action: RuleAction = RuleAction.DENY
    priority: int = Field(default=0, ge=-1000, le=1000)
    parameters: Dict[str, Any] = Field(default_factory=dict)
    is_active: bool = True
    tags: List[str] = Field(default_factory=list)


class RuleCreate(RuleBase):
    """Schema for creating a rule."""

    agent_id: Optional[UUID] = Field(
        None,
        description="Agent this rule applies to. Null for global rules."
    )
    source: Optional[str] = Field(None, max_length=100)
    source_reference: Optional[str] = Field(None, max_length=255)


class RuleUpdate(BaseModel):
    """Schema for updating a rule."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    action: Optional[RuleAction] = None
    priority: Optional[int] = Field(None, ge=-1000, le=1000)
    parameters: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None
    tags: Optional[List[str]] = None


class RuleResponse(RuleBase):
    """Schema for rule response."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    agent_id: Optional[UUID] = None
    source: Optional[str] = None
    source_reference: Optional[str] = None
    match_count: int = 0
    last_matched_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    is_deleted: bool = False
    is_global: bool = False


class RuleListResponse(BaseModel):
    """Schema for paginated rule list."""

    items: List[RuleResponse]
    total: int
    page: int
    page_size: int
    pages: int


class RuleTemplateResponse(BaseModel):
    """Schema for rule template."""

    id: str
    name: str
    description: str
    category: str
    severity: str
    rule_type: RuleType
    default_action: RuleAction
    default_parameters: Dict[str, Any]
    tags: List[str]
    is_recommended: bool = False


class RuleValidateRequest(BaseModel):
    """Schema for rule validation (dry run)."""

    rule: RuleCreate
    test_context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Test context for evaluation"
    )


class RuleValidateResponse(BaseModel):
    """Schema for rule validation response."""

    is_valid: bool
    would_match: bool
    action_result: RuleAction
    validation_errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    evaluation_details: Dict[str, Any] = Field(default_factory=dict)


class RuleImportRequest(BaseModel):
    """Schema for importing rules."""

    rules: List[RuleCreate]
    overwrite_existing: bool = False
    dry_run: bool = False


class RuleImportResponse(BaseModel):
    """Schema for import response."""

    imported: int
    skipped: int
    errors: List[Dict[str, Any]]
    rules: List[RuleResponse] = Field(default_factory=list)


class RuleExportRequest(BaseModel):
    """Schema for exporting rules."""

    rule_ids: Optional[List[UUID]] = None
    agent_id: Optional[UUID] = None
    include_global: bool = True
    format: str = Field(default="json", pattern="^(json|yaml)$")


class RuleExportResponse(BaseModel):
    """Schema for export response."""

    format: str
    rules_count: int
    data: str  # JSON or YAML string
    exported_at: datetime


class ApplyTemplateRequest(BaseModel):
    """Schema for applying a rule template."""

    agent_id: Optional[UUID] = None
    parameter_overrides: Dict[str, Any] = Field(default_factory=dict)
    activate_immediately: bool = True
