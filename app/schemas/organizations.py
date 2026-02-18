"""Pydantic schemas for organization endpoints."""

import re
from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.organizations import OrgRole


def _slugify(text: str) -> str:
    """Convert text to a URL-safe slug."""
    slug = text.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = slug.strip("-")
    return slug or "org"


# --- Organization schemas ---


class OrgCreate(BaseModel):
    """Schema for creating an organization."""

    name: str = Field(..., min_length=1, max_length=255)
    slug: Optional[str] = Field(
        None,
        min_length=1,
        max_length=100,
        description="URL-safe slug; auto-generated from name if omitted",
    )

    @field_validator("slug", mode="before")
    @classmethod
    def generate_slug(cls, v: Optional[str], info) -> Optional[str]:
        """If slug is not provided, leave it as None (router will auto-generate from name)."""
        if v is not None:
            v = v.strip().lower()
            if not re.match(r"^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$", v):
                raise ValueError(
                    "Slug must contain only lowercase letters, numbers, and hyphens, "
                    "and cannot start or end with a hyphen"
                )
        return v


class OrgUpdate(BaseModel):
    """Schema for updating an organization."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    settings: Optional[dict] = None


class OrgResponse(BaseModel):
    """Schema for organization response."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    slug: str
    plan_id: str
    is_active: bool
    created_at: datetime
    settings: dict = Field(default_factory=dict)
    feature_overrides: dict = Field(default_factory=dict)


class OrgDetailResponse(OrgResponse):
    """Schema for detailed organization response with resource counts."""

    member_count: int = 0
    agent_count: int = 0
    rule_count: int = 0


# --- Member schemas ---


class MemberResponse(BaseModel):
    """Schema for organization member response."""

    id: UUID
    user_id: UUID
    email: str
    username: str
    role: str
    accepted_at: Optional[datetime] = None
    created_at: datetime


# --- Invitation schemas ---


class InviteRequest(BaseModel):
    """Schema for inviting a member to an organization."""

    email: str = Field(..., min_length=1, max_length=255)
    role: str = Field(default="member")

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, v):
            raise ValueError("Invalid email format")
        return v

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        valid_roles = {r.value for r in OrgRole}
        if v not in valid_roles:
            raise ValueError(f"Invalid role '{v}'. Must be one of: {', '.join(sorted(valid_roles))}")
        return v


class InviteResponse(BaseModel):
    """Schema for invitation response."""

    id: UUID
    email: str
    role: str
    status: str
    expires_at: datetime


# --- Role update schema ---


class UpdateMemberRoleRequest(BaseModel):
    """Schema for updating a member's role."""

    role: str

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        valid_roles = {r.value for r in OrgRole}
        if v not in valid_roles:
            raise ValueError(f"Invalid role '{v}'. Must be one of: {', '.join(sorted(valid_roles))}")
        return v


# --- Usage / quota schemas ---


class UsageStat(BaseModel):
    """Usage statistic for a single resource type."""

    used: int
    limit: int
    is_unlimited: bool


class OrgSettingsUpdate(BaseModel):
    """Schema for updating org-level policy settings."""

    audit_retention_days: Optional[int] = Field(None, ge=7, le=3650)
    require_mfa: Optional[bool] = None
    max_login_attempts: Optional[int] = Field(None, ge=3, le=20)
    lockout_duration_minutes: Optional[int] = Field(None, ge=5, le=1440)
    session_timeout_minutes: Optional[int] = Field(None, ge=5, le=1440)


class OrgSettingsResponse(BaseModel):
    """Schema for org-level policy settings response."""

    audit_retention_days: int = 90
    require_mfa: bool = False
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 30
    session_timeout_minutes: int = 30


class UsageResponse(BaseModel):
    """Schema for organization usage / quota information."""

    plan_id: str
    plan_name: str
    agents: UsageStat
    rules: UsageStat
    vault_entries: UsageStat
    team_members: UsageStat
    teams: UsageStat
    features: dict = Field(default_factory=dict)
