"""Authentication service for user management and JWT tokens."""

import logging
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import ExpiredSignatureError, JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.organizations import (
    Organization,
    OrganizationMembership,
    OrgRole,
    Team,
)
from app.models.users import User

logger = logging.getLogger(__name__)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a password using bcrypt via passlib."""
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    return pwd_context.verify(plain, hashed)


def create_access_token(
    user_id: uuid.UUID, org_id: uuid.UUID, role: str
) -> str:
    """
    Create a JWT access token.

    Payload includes user ID, organization ID, role, expiration, and token type.
    """
    settings = get_settings()
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload = {
        "sub": str(user_id),
        "org": str(org_id),
        "role": role,
        "exp": expire,
        "type": "access",
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(user_id: uuid.UUID) -> str:
    """
    Create a JWT refresh token.

    Longer-lived token used to obtain new access tokens.
    """
    settings = get_settings()
    expire = datetime.now(timezone.utc) + timedelta(
        days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS
    )
    payload = {
        "sub": str(user_id),
        "exp": expire,
        "type": "refresh",
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def verify_token(token: str) -> dict:
    """
    Decode and verify a JWT token.

    Returns the token payload dict on success.
    Raises ValueError on invalid or expired tokens.
    """
    settings = get_settings()
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        return payload
    except ExpiredSignatureError:
        raise ValueError("Token has expired")
    except JWTError as e:
        raise ValueError(f"Invalid token: {e}")


def _slugify(text: str) -> str:
    """Convert text to a URL-safe slug."""
    slug = text.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = slug.strip("-")
    return slug or "org"


async def create_user(
    db: AsyncSession, email: str, username: str, password: str
) -> User:
    """
    Create a new user with a personal organization.

    Steps:
    1. Hash the password
    2. Create the User record
    3. Create a personal Organization (name="{username}'s Organization", plan="free")
    4. Create a default Team within the organization
    5. Create an OrganizationMembership with role=OWNER
    6. Set user.default_organization_id
    7. Return the user
    """
    # Hash password
    password_hashed = hash_password(password)

    # Create user (without default_organization_id for now)
    user = User(
        id=uuid.uuid4(),
        email=email.lower().strip(),
        username=username.strip(),
        password_hash=password_hashed,
        is_active=True,
        is_verified=False,
    )
    db.add(user)
    await db.flush()  # Get user.id assigned

    # Create personal organization
    org_slug = _slugify(username)
    # Ensure slug uniqueness by appending random suffix if needed
    existing = await db.execute(
        select(Organization).where(Organization.slug == org_slug)
    )
    if existing.scalar_one_or_none():
        org_slug = f"{org_slug}-{secrets.token_hex(3)}"

    org = Organization(
        id=uuid.uuid4(),
        name=f"{username}'s Organization",
        slug=org_slug,
        plan_id="free",
        is_active=True,
    )
    db.add(org)
    await db.flush()

    # Create default team
    team = Team(
        id=uuid.uuid4(),
        organization_id=org.id,
        name="Default",
        slug="default",
        is_default=True,
    )
    db.add(team)

    # Create membership
    membership = OrganizationMembership(
        id=uuid.uuid4(),
        user_id=user.id,
        organization_id=org.id,
        role=OrgRole.OWNER,
        accepted_at=datetime.now(timezone.utc),
    )
    db.add(membership)

    # Set default organization
    user.default_organization_id = org.id
    await db.flush()

    logger.info(
        f"Created user {user.id} ({email}) with org {org.id} ({org.name})"
    )
    return user


async def authenticate_user(
    db: AsyncSession, email: str, password: str
) -> User:
    """
    Authenticate a user by email and password.

    Checks account lockout, increments failed attempts on bad password,
    locks account after MAX_LOGIN_ATTEMPTS failures (30-min lockout),
    and resets on success. Updates last_login_at on success.
    Raises ValueError if credentials are invalid or account is locked.
    """
    settings = get_settings()
    stmt = select(User).where(
        User.email == email.lower().strip(),
        User.deleted_at.is_(None),
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise ValueError("Invalid email or password")

    # Check account lockout
    if user.is_locked:
        raise ValueError("Account is locked due to too many failed login attempts")

    if not verify_password(password, user.password_hash):
        # Increment failed attempts
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= settings.MAX_LOGIN_ATTEMPTS:
            user.locked_until = datetime.now(timezone.utc) + timedelta(
                minutes=settings.LOCKOUT_DURATION_MINUTES
            )
            logger.warning(
                f"Account locked for user {user.id} ({user.email}) "
                f"after {user.failed_login_attempts} failed attempts"
            )
        await db.flush()
        raise ValueError("Invalid email or password")

    if not user.is_active:
        raise ValueError("Account is disabled")

    # Reset failed attempts on success
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = datetime.now(timezone.utc)
    await db.flush()

    return user


async def initiate_password_reset(
    db: AsyncSession, email: str
) -> Optional[str]:
    """
    Generate a password reset token for the given email.

    Returns the token string if the user exists, None otherwise.
    Token expires in 1 hour.
    """
    stmt = select(User).where(
        User.email == email.lower().strip(),
        User.deleted_at.is_(None),
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        return None

    token = secrets.token_urlsafe(32)
    user.password_reset_token = token
    user.password_reset_expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    await db.flush()

    logger.info(f"Password reset initiated for user {user.id}")
    return token


async def complete_password_reset(
    db: AsyncSession, token: str, new_password: str
) -> bool:
    """
    Complete a password reset using the token.

    Finds the user by token, validates expiry, updates password, and clears
    the reset token fields.

    Returns True on success, False if token is invalid or expired.
    """
    stmt = select(User).where(
        User.password_reset_token == token,
        User.deleted_at.is_(None),
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        return False

    # Check expiry
    if user.password_reset_expires_at is None:
        return False

    now = datetime.now(timezone.utc)
    expires_at = user.password_reset_expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if now > expires_at:
        return False

    # Update password
    user.password_hash = hash_password(new_password)
    user.password_reset_token = None
    user.password_reset_expires_at = None
    user.last_password_change = now
    await db.flush()

    logger.info(f"Password reset completed for user {user.id}")
    return True
