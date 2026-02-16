"""SAML 2.0 SSO endpoints.

Provides Service Provider metadata, login redirect, and Assertion Consumer Service.
Per-org SAML configuration stored in Organization.settings.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.models.organizations import Organization, OrganizationMembership

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/saml", tags=["saml"])


def _get_base_url(request: Request) -> str:
    """Extract base URL from request for SP entity ID construction."""
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", ""))
    return f"{scheme}://{host}"


async def _get_org_by_slug(db: AsyncSession, slug: str) -> Organization:
    """Load organization by slug, raise 404 if not found."""
    stmt = select(Organization).where(
        Organization.slug == slug,
        Organization.is_active == True,
        Organization.deleted_at.is_(None),
    )
    result = await db.execute(stmt)
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org


@router.get("/metadata/{org_slug}")
async def saml_metadata(
    org_slug: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Return SAML SP metadata XML for the organization."""
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
        from onelogin.saml2.settings import OneLogin_Saml2_Settings
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="python3-saml not installed. Add 'python3-saml' to requirements.",
        )

    org = await _get_org_by_slug(db, org_slug)

    from app.services.saml import get_saml_settings, is_saml_configured

    if not is_saml_configured(org):
        raise HTTPException(status_code=404, detail="SAML not configured for this organization")

    base_url = _get_base_url(request)
    settings_dict = get_saml_settings(org, base_url)
    saml_settings = OneLogin_Saml2_Settings(settings_dict, sp_validation_only=True)
    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata)

    if errors:
        raise HTTPException(status_code=500, detail=f"Metadata validation errors: {errors}")

    return Response(content=metadata, media_type="application/xml")


@router.get("/login/{org_slug}")
async def saml_login(
    org_slug: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    relay_state: Optional[str] = None,
):
    """Redirect user to IdP for SAML authentication."""
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
    except ImportError:
        raise HTTPException(status_code=501, detail="python3-saml not installed")

    org = await _get_org_by_slug(db, org_slug)

    from app.services.saml import get_saml_settings, is_saml_configured

    if not is_saml_configured(org):
        raise HTTPException(status_code=404, detail="SAML not configured for this organization")

    base_url = _get_base_url(request)
    settings_dict = get_saml_settings(org, base_url)

    # Build request info for python3-saml
    req = _prepare_saml_request(request)
    auth = OneLogin_Saml2_Auth(req, settings_dict)
    sso_url = auth.login(return_to=relay_state or "/")

    return RedirectResponse(url=sso_url, status_code=302)


@router.post("/acs/{org_slug}")
async def saml_acs(
    org_slug: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """SAML Assertion Consumer Service — processes IdP response.

    On successful assertion validation:
    1. Extracts email and name from SAML attributes
    2. JIT provisions user if needed
    3. Creates JWT session cookies
    4. Redirects to dashboard
    """
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
    except ImportError:
        raise HTTPException(status_code=501, detail="python3-saml not installed")

    org = await _get_org_by_slug(db, org_slug)

    from app.services.saml import (
        create_session_tokens,
        get_saml_settings,
        is_saml_configured,
        jit_provision_user,
    )

    if not is_saml_configured(org):
        raise HTTPException(status_code=404, detail="SAML not configured")

    base_url = _get_base_url(request)
    settings_dict = get_saml_settings(org, base_url)

    req = await _prepare_saml_request_post(request)
    auth = OneLogin_Saml2_Auth(req, settings_dict)
    auth.process_response()
    errors = auth.get_errors()

    if errors:
        logger.warning(f"SAML ACS errors for org {org.slug}: {errors}")
        raise HTTPException(
            status_code=400, detail=f"SAML authentication failed: {', '.join(errors)}"
        )

    if not auth.is_authenticated():
        raise HTTPException(status_code=401, detail="SAML authentication failed")

    # Extract user info from assertion
    name_id = auth.get_nameid()  # Usually email
    attributes = auth.get_attributes()
    email = name_id or attributes.get("email", [None])[0] or attributes.get(
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", [None]
    )[0]

    if not email:
        raise HTTPException(status_code=400, detail="No email in SAML assertion")

    full_name = (
        attributes.get("displayName", [None])[0]
        or attributes.get(
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", [None]
        )[0]
    )

    # JIT provision
    user, created = await jit_provision_user(
        db=db,
        org=org,
        email=email,
        full_name=full_name,
        attributes=attributes,
    )

    # Get membership for token creation
    stmt = select(OrganizationMembership).where(
        OrganizationMembership.user_id == user.id,
        OrganizationMembership.organization_id == org.id,
    )
    result = await db.execute(stmt)
    membership = result.scalar_one()

    # Create session tokens
    access_token, refresh_token = create_session_tokens(user, org, membership)

    # Build redirect with cookies
    app_settings = get_settings()
    relay_state = auth.get_last_request_id() or "/"
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(
        key="snapper_access_token",
        value=access_token,
        httponly=True,
        secure=not app_settings.DEBUG,
        samesite="lax",
        path="/",
        max_age=app_settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    response.set_cookie(
        key="snapper_refresh_token",
        value=refresh_token,
        httponly=True,
        secure=not app_settings.DEBUG,
        samesite="lax",
        path="/",
        max_age=app_settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 86400,
    )

    logger.info(
        f"SAML login: user={user.id} email={email} org={org.slug} "
        f"created={created}"
    )
    return response


def _prepare_saml_request(request: Request) -> dict:
    """Build the request dict that python3-saml expects (GET)."""
    return {
        "https": "on" if request.url.scheme == "https" else "off",
        "http_host": request.headers.get("host", ""),
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": {},
    }


async def _prepare_saml_request_post(request: Request) -> dict:
    """Build the request dict that python3-saml expects (POST)."""
    form_data = await request.form()
    return {
        "https": "on" if request.headers.get("x-forwarded-proto", request.url.scheme) == "https" else "off",
        "http_host": request.headers.get("host", ""),
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": dict(form_data),
    }
