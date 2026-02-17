"""User model for authentication and authorization."""

import uuid
from datetime import datetime
from enum import Enum
from typing import List, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class UserRole(str, Enum):
    """User role levels."""

    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


class User(Base):
    """
    User account for Rules Manager.

    Users can manage agents, rules, and view security information
    based on their role permissions.
    """

    __tablename__ = "users"

    # Primary key
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Authentication
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )
    username: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )
    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    # Profile
    full_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )

    # Authorization
    role: Mapped[UserRole] = mapped_column(
        String(20),
        default=UserRole.VIEWER,
        nullable=False,
    )
    permissions: Mapped[List[str]] = mapped_column(
        ARRAY(String),
        default=list,
        nullable=False,
        comment="Additional granular permissions",
    )

    # Status
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    is_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    # Security
    failed_login_attempts: Mapped[int] = mapped_column(
        default=0,
        nullable=False,
    )
    locked_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_password_change: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    require_password_change: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    # MFA / TOTP
    totp_secret: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="Encrypted TOTP secret key",
    )
    totp_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    totp_backup_codes: Mapped[Optional[list]] = mapped_column(
        JSONB,
        nullable=True,
        comment="Hashed one-time backup codes",
    )

    # Preferences
    preferences: Mapped[dict] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )

    # Activity tracking
    last_login_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_login_ip: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Organization
    default_organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="User's default organization context",
    )

    # OAuth
    oauth_provider: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        comment="OAuth provider: github, google",
    )
    oauth_provider_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="User ID from OAuth provider",
    )

    # Password reset
    email_verification_token: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    password_reset_token: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    password_reset_expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Soft delete
    deleted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        Index("ix_users_active", "is_active", "role"),
        Index("ix_users_oauth", "oauth_provider", "oauth_provider_id"),
    )

    def __repr__(self) -> str:
        return f"<User(id={self.id}, username={self.username}, role={self.role})>"

    @property
    def is_admin(self) -> bool:
        """Check if user has admin role."""
        return self.role == UserRole.ADMIN

    @property
    def is_locked(self) -> bool:
        """Check if account is locked."""
        if self.locked_until is None:
            return False
        return datetime.now(self.locked_until.tzinfo) < self.locked_until

    def has_permission(self, permission: str) -> bool:
        """Check if user has specific permission."""
        if self.is_admin:
            return True
        return permission in self.permissions


# Role-based permission definitions
ROLE_PERMISSIONS = {
    UserRole.ADMIN: [
        "agents:read",
        "agents:write",
        "agents:delete",
        "rules:read",
        "rules:write",
        "rules:delete",
        "audit:read",
        "security:read",
        "security:write",
        "users:read",
        "users:write",
        "users:delete",
        "settings:read",
        "settings:write",
    ],
    UserRole.OPERATOR: [
        "agents:read",
        "agents:write",
        "rules:read",
        "rules:write",
        "audit:read",
        "security:read",
        "settings:read",
    ],
    UserRole.VIEWER: [
        "agents:read",
        "rules:read",
        "audit:read",
        "security:read",
    ],
}
