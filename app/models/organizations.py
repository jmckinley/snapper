"""Organization, Team, Membership, Invitation, and Plan models for multi-tenancy."""

import secrets
import uuid
from datetime import datetime
from enum import Enum
from typing import List, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class OrgRole(str, Enum):
    """Roles within an organization."""

    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class InvitationStatus(str, Enum):
    """Status of an organization invitation."""

    PENDING = "pending"
    ACCEPTED = "accepted"
    EXPIRED = "expired"


class Plan(Base):
    """
    Subscription plan definition.

    Reference table seeded via migration with free/pro/enterprise tiers.
    """

    __tablename__ = "plans"

    id: Mapped[str] = mapped_column(
        String(50),
        primary_key=True,
        comment="Plan identifier: free, pro, enterprise",
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    stripe_price_id_monthly: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    stripe_price_id_yearly: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )

    # Quantity limits (-1 = unlimited)
    max_agents: Mapped[int] = mapped_column(default=1, nullable=False)
    max_rules: Mapped[int] = mapped_column(default=10, nullable=False)
    max_vault_entries: Mapped[int] = mapped_column(default=5, nullable=False)
    max_team_members: Mapped[int] = mapped_column(default=1, nullable=False)
    max_teams: Mapped[int] = mapped_column(default=1, nullable=False)

    # Feature flags
    features: Mapped[dict] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        comment="Feature flags: slack_integration, oauth_login, sso, audit_export",
    )

    # Pricing
    price_monthly_cents: Mapped[int] = mapped_column(default=0, nullable=False)
    price_yearly_cents: Mapped[int] = mapped_column(default=0, nullable=False)

    def __repr__(self) -> str:
        return f"<Plan(id={self.id}, name={self.name})>"


class Organization(Base):
    """
    Multi-tenant organization.

    All agents, rules, vault entries, and audit logs are scoped to an organization.
    """

    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )

    # Plan
    plan_id: Mapped[str] = mapped_column(
        String(50),
        ForeignKey("plans.id"),
        default="free",
        nullable=False,
    )

    # Stripe
    stripe_customer_id: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, unique=True
    )
    stripe_subscription_id: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    subscription_status: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        comment="active, past_due, canceled, trialing",
    )
    plan_period_end: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Overrides and settings
    feature_overrides: Mapped[dict] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        comment="Per-org feature flag overrides",
    )
    settings: Mapped[dict] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    deleted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    plan: Mapped["Plan"] = relationship("Plan", lazy="joined")
    memberships: Mapped[List["OrganizationMembership"]] = relationship(
        "OrganizationMembership",
        back_populates="organization",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    teams: Mapped[List["Team"]] = relationship(
        "Team",
        back_populates="organization",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (
        Index("ix_organizations_active", "is_active", "deleted_at"),
    )

    def __repr__(self) -> str:
        return f"<Organization(id={self.id}, name={self.name}, plan={self.plan_id})>"


class Team(Base):
    """
    Team within an organization for grouping agents.
    """

    __tablename__ = "teams"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    organization: Mapped["Organization"] = relationship(
        "Organization", back_populates="teams"
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "slug", name="uq_teams_org_slug"),
    )

    def __repr__(self) -> str:
        return f"<Team(id={self.id}, name={self.name})>"


class OrganizationMembership(Base):
    """
    User membership in an organization with role.
    """

    __tablename__ = "organization_memberships"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role: Mapped[OrgRole] = mapped_column(
        String(20),
        default=OrgRole.MEMBER,
        nullable=False,
    )
    invited_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    invited_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    accepted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    organization: Mapped["Organization"] = relationship(
        "Organization", back_populates="memberships"
    )

    __table_args__ = (
        UniqueConstraint("user_id", "organization_id", name="uq_membership_user_org"),
    )

    def __repr__(self) -> str:
        return f"<OrganizationMembership(user={self.user_id}, org={self.organization_id}, role={self.role})>"


class Invitation(Base):
    """
    Organization invitation sent to an email address.
    """

    __tablename__ = "invitations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    role: Mapped[OrgRole] = mapped_column(
        String(20),
        default=OrgRole.MEMBER,
        nullable=False,
    )
    token: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        default=lambda: secrets.token_urlsafe(32),
    )
    invited_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=False,
    )
    status: Mapped[InvitationStatus] = mapped_column(
        String(20),
        default=InvitationStatus.PENDING,
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        Index("ix_invitations_pending", "status", "expires_at"),
    )

    def __repr__(self) -> str:
        return f"<Invitation(email={self.email}, org={self.organization_id}, status={self.status})>"
