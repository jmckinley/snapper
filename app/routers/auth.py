"""Authentication router for user registration, login, and session management."""

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from app.config import get_settings
from app.database import get_db
from app.models.organizations import Organization, OrganizationMembership
from app.models.users import User
from app.schemas.auth import (
    ForgotPasswordRequest,
    LoginRequest,
    OrgMembershipInfo,
    RegisterRequest,
    ResetPasswordRequest,
    SwitchOrgRequest,
    UserResponse,
    UserWithOrgsResponse,
)
from app.services.auth import (
    authenticate_user,
    complete_password_reset,
    create_access_token,
    create_refresh_token,
    create_user,
    initiate_password_reset,
    verify_token,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


def _set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    """Set httponly authentication cookies on the response."""
    settings = get_settings()
    secure = not settings.DEBUG

    response.set_cookie(
        key="snapper_access_token",
        value=access_token,
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
        max_age=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    response.set_cookie(
        key="snapper_refresh_token",
        value=refresh_token,
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
        max_age=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 86400,
    )


def _delete_auth_cookies(response: Response) -> None:
    """Delete authentication cookies from the response."""
    settings = get_settings()
    secure = not settings.DEBUG

    response.delete_cookie(
        key="snapper_access_token",
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
    )
    response.delete_cookie(
        key="snapper_refresh_token",
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
    )


async def _get_user_org_memberships(
    db: AsyncSession, user_id: UUID
) -> list[OrgMembershipInfo]:
    """Load all organization memberships for a user."""
    stmt = (
        select(OrganizationMembership)
        .options(joinedload(OrganizationMembership.organization).joinedload(Organization.plan))
        .where(OrganizationMembership.user_id == user_id)
    )
    result = await db.execute(stmt)
    memberships = result.unique().scalars().all()

    org_infos = []
    for m in memberships:
        org = m.organization
        if org and not org.deleted_at:
            org_infos.append(
                OrgMembershipInfo(
                    org_id=org.id,
                    org_name=org.name,
                    org_slug=org.slug,
                    role=m.role.value if hasattr(m.role, "value") else str(m.role),
                    plan_id=org.plan_id,
                )
            )
    return org_infos


async def _get_current_user(request: Request, db: AsyncSession) -> User:
    """
    Extract and validate the current user from the access token cookie.

    Used by endpoints that require authentication.
    """
    user_id = getattr(request.state, "user_id", None)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    stmt = select(User).where(User.id == UUID(user_id), User.deleted_at.is_(None))
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    return user


@router.post("/register", response_model=UserResponse)
async def register(
    request: Request,
    response: Response,
    body: RegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Register a new user account.

    Creates a user, personal organization, default team, and membership.
    Sets authentication cookies on success.
    """
    settings = get_settings()

    if not settings.REGISTRATION_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registration is currently disabled",
        )

    # Check for existing email
    existing_email = await db.execute(
        select(User).where(User.email == body.email.lower().strip())
    )
    if existing_email.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )

    # Check for existing username
    existing_username = await db.execute(
        select(User).where(User.username == body.username.strip())
    )
    if existing_username.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This username is already taken",
        )

    try:
        user = await create_user(db, body.email, body.username, body.password)
    except Exception as e:
        logger.error(f"Failed to create user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create account",
        )

    # Get the user's default org membership for the token
    memberships = await _get_user_org_memberships(db, user.id)
    default_membership = next(
        (m for m in memberships if m.org_id == user.default_organization_id), None
    )

    org_id = user.default_organization_id or memberships[0].org_id if memberships else None
    role = default_membership.role if default_membership else "owner"

    # Create tokens
    access_token = create_access_token(user.id, org_id, role)
    refresh_token = create_refresh_token(user.id)

    # Set cookies
    _set_auth_cookies(response, access_token, refresh_token)

    logger.info(f"User registered: {user.email} ({user.id})")
    return UserResponse.model_validate(user)


@router.post("/login", response_model=UserResponse)
async def login(
    request: Request,
    response: Response,
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticate user and create session.

    Validates credentials, creates JWT tokens, and sets httponly cookies.
    """
    try:
        user = await authenticate_user(db, body.email, body.password)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )

    # Get default org membership
    memberships = await _get_user_org_memberships(db, user.id)
    default_membership = next(
        (m for m in memberships if m.org_id == user.default_organization_id), None
    )

    if not default_membership and memberships:
        default_membership = memberships[0]

    org_id = default_membership.org_id if default_membership else user.default_organization_id
    role = default_membership.role if default_membership else "member"

    # Create tokens
    access_token = create_access_token(user.id, org_id, role)
    refresh_token = create_refresh_token(user.id)

    # Set cookies
    _set_auth_cookies(response, access_token, refresh_token)

    logger.info(f"User logged in: {user.email} ({user.id})")
    return UserResponse.model_validate(user)


@router.post("/logout")
async def logout(response: Response):
    """
    Log out the current user by clearing authentication cookies.
    """
    _delete_auth_cookies(response)
    return {"message": "Logged out"}


@router.post("/refresh")
async def refresh(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    """
    Refresh the access token using the refresh token cookie.

    Reads the refresh token from cookies, validates it, and issues
    a new access token.
    """
    refresh_token = request.cookies.get("snapper_refresh_token")
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token",
        )

    try:
        payload = verify_token(refresh_token)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )

    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    # Load user
    stmt = select(User).where(User.id == UUID(user_id), User.deleted_at.is_(None))
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or disabled",
        )

    # Get default org membership for new access token
    memberships = await _get_user_org_memberships(db, user.id)
    default_membership = next(
        (m for m in memberships if m.org_id == user.default_organization_id), None
    )
    if not default_membership and memberships:
        default_membership = memberships[0]

    org_id = default_membership.org_id if default_membership else user.default_organization_id
    role = default_membership.role if default_membership else "member"

    # Create new access token
    new_access_token = create_access_token(user.id, org_id, role)

    # Set the new access token cookie
    settings = get_settings()
    response.set_cookie(
        key="snapper_access_token",
        value=new_access_token,
        httponly=True,
        secure=not settings.DEBUG,
        samesite="lax",
        path="/",
        max_age=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )

    return {"access_token": new_access_token}


@router.get("/me", response_model=UserWithOrgsResponse)
async def get_me(request: Request, db: AsyncSession = Depends(get_db)):
    """
    Get the current authenticated user's profile and organization memberships.
    """
    user = await _get_current_user(request, db)
    memberships = await _get_user_org_memberships(db, user.id)

    return UserWithOrgsResponse(
        user=UserResponse.model_validate(user),
        organizations=memberships,
    )


@router.post("/forgot-password")
async def forgot_password(
    body: ForgotPasswordRequest, db: AsyncSession = Depends(get_db)
):
    """
    Initiate a password reset.

    Always returns the same message regardless of whether the email exists
    to prevent email enumeration.
    """
    token = await initiate_password_reset(db, body.email)

    # In a real deployment, send the token via email here.
    # For now, we log it (would be replaced by email service).
    if token:
        logger.info(f"Password reset token generated for {body.email}")

    return {"message": "If that email exists, a password reset link has been sent"}


@router.post("/reset-password")
async def reset_password(
    body: ResetPasswordRequest, db: AsyncSession = Depends(get_db)
):
    """
    Complete a password reset using the reset token.
    """
    success = await complete_password_reset(db, body.token, body.new_password)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    return {"message": "Password has been reset successfully"}


@router.post("/switch-org")
async def switch_org(
    request: Request,
    response: Response,
    body: SwitchOrgRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Switch the user's active organization context.

    Verifies membership, creates a new access token scoped to the target
    organization, and updates the cookie.
    """
    user = await _get_current_user(request, db)

    # Verify user is a member of the target organization
    stmt = select(OrganizationMembership).where(
        OrganizationMembership.user_id == user.id,
        OrganizationMembership.organization_id == body.organization_id,
    )
    result = await db.execute(stmt)
    membership = result.scalar_one_or_none()

    if not membership:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not a member of this organization",
        )

    # Update user's default org
    user.default_organization_id = body.organization_id
    await db.flush()

    role = membership.role.value if hasattr(membership.role, "value") else str(membership.role)

    # Create new access token with new org context
    new_access_token = create_access_token(user.id, body.organization_id, role)

    # Set the new access token cookie
    settings = get_settings()
    response.set_cookie(
        key="snapper_access_token",
        value=new_access_token,
        httponly=True,
        secure=not settings.DEBUG,
        samesite="lax",
        path="/",
        max_age=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )

    return {
        "message": "Switched organization",
        "organization_id": str(body.organization_id),
    }
