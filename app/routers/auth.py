"""Authentication router for user registration, login, and session management."""

import hashlib
import logging
import secrets
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from app.config import get_settings
from app.database import get_db
from app.models.audit_logs import AuditAction, AuditLog, AuditSeverity
from app.models.organizations import Organization, OrganizationMembership
from app.models.users import User
from app.schemas.auth import (
    ForgotPasswordRequest,
    LoginRequest,
    MFALoginRequest,
    MFALoginResponse,
    MFASetupResponse,
    MFAVerifyRequest,
    MFAVerifySetupResponse,
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


def _create_audit_log(
    action: AuditAction,
    message: str,
    request: Request,
    user_id: UUID = None,
    org_id: UUID = None,
    severity: AuditSeverity = AuditSeverity.INFO,
    details: dict = None,
) -> AuditLog:
    """Create an audit log entry with request context."""
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent", "")[:500]
    return AuditLog(
        action=action,
        severity=severity,
        message=message,
        user_id=user_id,
        organization_id=org_id,
        ip_address=ip_address,
        user_agent=user_agent,
        endpoint=str(request.url.path),
        method=request.method,
        details=details or {},
    )

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

    # Audit log
    db.add(_create_audit_log(
        AuditAction.USER_REGISTERED,
        f"User registered: {user.email}",
        request, user_id=user.id, org_id=org_id,
    ))

    logger.info(f"User registered: {user.email} ({user.id})")
    return UserResponse.model_validate(user)


@router.post("/login")
async def login(
    request: Request,
    response: Response,
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticate user and create session.

    Validates credentials. If MFA is enabled, returns a temporary MFA token
    instead of full session tokens. Otherwise creates JWT tokens and sets cookies.
    """
    try:
        user = await authenticate_user(db, body.email, body.password)
    except ValueError as e:
        # Audit failed login
        db.add(_create_audit_log(
            AuditAction.USER_LOGIN_FAILED,
            f"Login failed for {body.email}: {e}",
            request, severity=AuditSeverity.WARNING,
            details={"email": body.email},
        ))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )

    # If MFA is enabled, issue a temporary MFA token instead
    if user.totp_enabled:
        settings = get_settings()
        from datetime import datetime, timedelta, timezone
        from jose import jwt
        expire = datetime.now(timezone.utc) + timedelta(minutes=5)
        mfa_payload = {
            "sub": str(user.id),
            "exp": expire,
            "type": "mfa_challenge",
        }
        mfa_token = jwt.encode(mfa_payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
        return MFALoginResponse(requires_mfa=True, mfa_token=mfa_token)

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

    # Audit log
    db.add(_create_audit_log(
        AuditAction.USER_LOGIN,
        f"User logged in: {user.email}",
        request, user_id=user.id, org_id=org_id,
    ))

    logger.info(f"User logged in: {user.email} ({user.id})")
    return UserResponse.model_validate(user)


@router.post("/logout")
async def logout(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    """
    Log out the current user by clearing authentication cookies.
    """
    _delete_auth_cookies(response)

    user_id = getattr(request.state, "user_id", None)
    if user_id:
        db.add(_create_audit_log(
            AuditAction.USER_LOGOUT,
            "User logged out",
            request, user_id=UUID(user_id),
        ))

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

    if token:
        from app.services.email import send_password_reset

        base_url = str(body.base_url) if hasattr(body, "base_url") else ""
        sent = send_password_reset(body.email, token, base_url=base_url)
        if not sent:
            logger.info(f"Password reset token generated for {body.email} (email not sent — SMTP not configured)")

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

    # Audit log
    db.add(_create_audit_log(
        AuditAction.ORG_SWITCHED,
        f"Switched to organization {body.organization_id}",
        request, user_id=user.id, org_id=body.organization_id,
    ))

    return {
        "message": "Switched organization",
        "organization_id": str(body.organization_id),
    }


# ---------------------------------------------------------------------------
# MFA / TOTP endpoints
# ---------------------------------------------------------------------------


@router.post("/mfa/setup", response_model=MFASetupResponse)
async def mfa_setup(request: Request, db: AsyncSession = Depends(get_db)):
    """
    Generate a TOTP secret and return the provisioning URI + QR code.

    The secret is stored but MFA is not yet enabled until verify-setup is called.
    """
    user = await _get_current_user(request, db)

    if user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled. Disable it first to re-setup.",
        )

    import pyotp
    import qrcode
    import io
    import base64

    secret = pyotp.random_base32()
    user.totp_secret = secret
    await db.flush()

    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name="Snapper",
    )

    # Generate QR code as base64 PNG
    qr = qrcode.QRCode(version=1, box_size=6, border=2)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    qr_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

    return MFASetupResponse(
        provisioning_uri=provisioning_uri,
        qr_code_base64=qr_base64,
        secret=secret,
    )


@router.post("/mfa/verify-setup", response_model=MFAVerifySetupResponse)
async def mfa_verify_setup(
    request: Request,
    body: MFAVerifyRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Verify the first TOTP code to enable MFA.

    Returns backup codes that should be saved securely.
    """
    user = await _get_current_user(request, db)

    if user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled",
        )

    if not user.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Call /auth/mfa/setup first",
        )

    import pyotp
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(body.code, valid_window=1):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP code",
        )

    # Generate backup codes
    backup_codes = [secrets.token_hex(4) for _ in range(8)]
    hashed_codes = [hashlib.sha256(c.encode()).hexdigest() for c in backup_codes]

    user.totp_enabled = True
    user.totp_backup_codes = hashed_codes
    await db.flush()

    # Audit log
    db.add(_create_audit_log(
        AuditAction.MFA_ENABLED,
        f"MFA enabled for {user.email}",
        request, user_id=user.id,
    ))

    return MFAVerifySetupResponse(enabled=True, backup_codes=backup_codes)


@router.post("/mfa/verify")
async def mfa_verify(
    request: Request,
    response: Response,
    body: MFALoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Complete MFA verification during login flow.

    Accepts the temporary MFA token + TOTP code, returns full session on success.
    """
    settings = get_settings()

    try:
        payload = verify_token(body.mfa_token)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )

    if payload.get("type") != "mfa_challenge":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA token type",
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA token",
        )

    stmt = select(User).where(User.id == UUID(user_id), User.deleted_at.is_(None))
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or MFA not enabled",
        )

    # Try TOTP code
    import pyotp
    totp = pyotp.TOTP(user.totp_secret)
    code_valid = totp.verify(body.code, valid_window=1)

    # Try backup code if TOTP fails
    if not code_valid and user.totp_backup_codes:
        code_hash = hashlib.sha256(body.code.encode()).hexdigest()
        if code_hash in user.totp_backup_codes:
            code_valid = True
            # Remove used backup code
            user.totp_backup_codes = [c for c in user.totp_backup_codes if c != code_hash]

    if not code_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid TOTP code",
        )

    # Get default org membership and issue full session
    memberships = await _get_user_org_memberships(db, user.id)
    default_membership = next(
        (m for m in memberships if m.org_id == user.default_organization_id), None
    )
    if not default_membership and memberships:
        default_membership = memberships[0]

    org_id = default_membership.org_id if default_membership else user.default_organization_id
    role = default_membership.role if default_membership else "member"

    access_token = create_access_token(user.id, org_id, role)
    refresh_token = create_refresh_token(user.id)
    _set_auth_cookies(response, access_token, refresh_token)

    # Audit log
    db.add(_create_audit_log(
        AuditAction.USER_LOGIN,
        f"User logged in with MFA: {user.email}",
        request, user_id=user.id, org_id=org_id,
    ))

    return UserResponse.model_validate(user)


@router.post("/mfa/disable")
async def mfa_disable(
    request: Request,
    body: MFAVerifyRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Disable MFA. Requires a valid TOTP code for confirmation.
    """
    user = await _get_current_user(request, db)

    if not user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled",
        )

    import pyotp
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(body.code, valid_window=1):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP code",
        )

    user.totp_enabled = False
    user.totp_secret = None
    user.totp_backup_codes = None
    await db.flush()

    # Audit log
    db.add(_create_audit_log(
        AuditAction.MFA_DISABLED,
        f"MFA disabled for {user.email}",
        request, user_id=user.id, severity=AuditSeverity.WARNING,
    ))

    return {"message": "MFA has been disabled"}
