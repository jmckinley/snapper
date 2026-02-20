"""Pydantic schemas for authentication and authorization."""

import re
from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator, model_validator


class RegisterRequest(BaseModel):
    """Registration request with email, username, and password."""

    email: str
    username: str
    password: str
    password_confirm: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, v):
            raise ValueError("Invalid email format")
        return v

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 3:
            raise ValueError("Username must be at least 3 characters")
        if len(v) > 50:
            raise ValueError("Username must be at most 50 characters")
        if not re.match(r"^[a-zA-Z0-9_.@+%-]+$", v):
            raise ValueError(
                "Username can only contain letters, numbers, underscores, hyphens, dots, and @"
            )
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v

    @model_validator(mode="after")
    def passwords_match(self) -> "RegisterRequest":
        if self.password != self.password_confirm:
            raise ValueError("Passwords do not match")
        return self


class LoginRequest(BaseModel):
    """Login request with email and password."""

    email: str
    password: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.strip().lower()


class TokenResponse(BaseModel):
    """JWT token pair response."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    """Public user information response."""

    id: UUID
    email: str
    username: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    is_verified: bool
    is_meta_admin: bool = False
    default_organization_id: Optional[UUID] = None
    locked_until: Optional[datetime] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OrgMembershipInfo(BaseModel):
    """Organization membership summary for user context."""

    org_id: UUID
    org_name: str
    org_slug: str
    role: str
    plan_id: str


class UserWithOrgsResponse(BaseModel):
    """User response with all organization memberships."""

    user: UserResponse
    organizations: List[OrgMembershipInfo]


class ForgotPasswordRequest(BaseModel):
    """Forgot password request."""

    email: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.strip().lower()


class ResetPasswordRequest(BaseModel):
    """Password reset completion request."""

    token: str
    new_password: str
    password_confirm: str

    @field_validator("new_password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v

    @model_validator(mode="after")
    def passwords_match(self) -> "ResetPasswordRequest":
        if self.new_password != self.password_confirm:
            raise ValueError("Passwords do not match")
        return self


class SwitchOrgRequest(BaseModel):
    """Request to switch active organization context."""

    organization_id: UUID


class MFASetupResponse(BaseModel):
    """Response for MFA setup with provisioning URI and QR code."""

    provisioning_uri: str
    qr_code_base64: str
    secret: str


class MFAVerifyRequest(BaseModel):
    """Request to verify a TOTP code."""

    code: str

    @field_validator("code")
    @classmethod
    def validate_code(cls, v: str) -> str:
        v = v.strip()
        if not v.isdigit() or len(v) != 6:
            raise ValueError("TOTP code must be 6 digits")
        return v


class MFAVerifySetupResponse(BaseModel):
    """Response after verifying MFA setup, includes backup codes."""

    enabled: bool
    backup_codes: List[str]


class MFALoginRequest(BaseModel):
    """Request to complete MFA login."""

    mfa_token: str
    code: str

    @field_validator("code")
    @classmethod
    def validate_code(cls, v: str) -> str:
        v = v.strip()
        if len(v) != 6 and len(v) != 8:
            raise ValueError("Enter a 6-digit TOTP code or 8-character backup code")
        return v


class MFALoginResponse(BaseModel):
    """Response when MFA is required during login."""

    requires_mfa: bool = True
    mfa_token: str


class ChangePasswordRequest(BaseModel):
    """Request to change password for a logged-in user."""

    current_password: str
    new_password: str
    password_confirm: str

    @field_validator("new_password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v

    @model_validator(mode="after")
    def passwords_match(self) -> "ChangePasswordRequest":
        if self.new_password != self.password_confirm:
            raise ValueError("Passwords do not match")
        return self


class UpdateProfileRequest(BaseModel):
    """Request to update user profile."""

    full_name: Optional[str] = None
    username: Optional[str] = None

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if len(v) < 3:
                raise ValueError("Username must be at least 3 characters")
            if len(v) > 50:
                raise ValueError("Username must be at most 50 characters")
            if not re.match(r"^[a-zA-Z0-9_.@+%-]+$", v):
                raise ValueError(
                    "Username can only contain letters, numbers, underscores, hyphens, dots, and @"
                )
        return v


class SessionResponse(BaseModel):
    """Active session information."""

    session_id: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: str
    last_active: str
    is_current: bool = False
