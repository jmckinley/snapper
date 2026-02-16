"""OpenID Connect authentication endpoints.

Provides OIDC authorization code flow with per-org provider configuration.
Supports Okta, Entra ID, Google, and any generic OIDC provider.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.models.organizations import Organization, OrganizationMembership
from app.redis_client import redis_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/oidc", tags=["oidc"])


def _get_base_url(request: Request) -> str:
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", ""))
    return f"{scheme}://{host}"


async def _get_org_by_slug(db: AsyncSession, slug: str) -> Organization:
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


@router.get("/login/{org_slug}")
async def oidc_login(
    org_slug: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Initiate OIDC authorization code flow — redirects to provider."""
    from app.services.oidc import (
        build_authorization_url,
        discover_oidc_endpoints,
        generate_state_and_nonce,
        is_oidc_configured,
    )

    org = await _get_org_by_slug(db, org_slug)
    if not is_oidc_configured(org):
        raise HTTPException(status_code=404, detail="OIDC not configured for this organization")

    config = org.settings or {}
    issuer = config.get("oidc_issuer", "")

    # Discover endpoints
    endpoints = await discover_oidc_endpoints(issuer)

    # Generate state and nonce
    state, nonce = generate_state_and_nonce()

    # Store state in Redis for CSRF verification (5 min TTL)
    await redis_client.set(
        f"oidc_state:{state}",
        f"{org_slug}:{nonce}",
        ex=300,
    )

    base_url = _get_base_url(request)
    redirect_uri = f"{base_url}/auth/oidc/callback"

    auth_url = build_authorization_url(
        org=org,
        redirect_uri=redirect_uri,
        state=state,
        nonce=nonce,
        endpoints=endpoints,
    )

    return RedirectResponse(url=auth_url, status_code=302)


@router.get("/callback")
async def oidc_callback(
    request: Request,
    code: str = "",
    state: str = "",
    error: str = "",
    error_description: str = "",
    db: AsyncSession = Depends(get_db),
):
    """OIDC callback — exchanges code for tokens, provisions user, creates session."""
    if error:
        raise HTTPException(
            status_code=400,
            detail=f"OIDC error: {error} — {error_description}",
        )

    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code or state parameter")

    # Verify state (CSRF protection)
    stored = await redis_client.get(f"oidc_state:{state}")
    if not stored:
        raise HTTPException(status_code=400, detail="Invalid or expired state")

    # Consume state (one-time use)
    await redis_client.delete(f"oidc_state:{state}")

    org_slug, nonce = stored.split(":", 1)

    org = await _get_org_by_slug(db, org_slug)

    from app.services.oidc import (
        decode_id_token_unverified,
        discover_oidc_endpoints,
        exchange_code_for_tokens,
        get_oidc_config,
        get_userinfo,
    )
    from app.services.saml import create_session_tokens, jit_provision_user

    config = get_oidc_config(org)
    issuer = config["issuer"]

    # Discover endpoints
    endpoints = await discover_oidc_endpoints(issuer)

    base_url = _get_base_url(request)
    redirect_uri = f"{base_url}/auth/oidc/callback"

    # Exchange code for tokens
    token_response = await exchange_code_for_tokens(
        org=org,
        code=code,
        redirect_uri=redirect_uri,
        endpoints=endpoints,
    )

    id_token = token_response.get("id_token", "")
    access_token = token_response.get("access_token", "")

    # Extract user info from ID token
    email = None
    full_name = None

    if id_token:
        claims = decode_id_token_unverified(id_token)
        email = claims.get("email")
        full_name = claims.get("name")

        # Verify nonce
        if claims.get("nonce") != nonce:
            raise HTTPException(status_code=400, detail="Nonce mismatch")

    # Fallback to userinfo endpoint
    if not email and access_token:
        userinfo = await get_userinfo(access_token, endpoints)
        email = userinfo.get("email")
        full_name = full_name or userinfo.get("name")

    if not email:
        raise HTTPException(status_code=400, detail="Could not determine user email from OIDC")

    # JIT provision user (reuse SAML's JIT logic)
    user, created = await jit_provision_user(
        db=db,
        org=org,
        email=email,
        full_name=full_name,
    )

    # Update oauth provider info
    if not user.oauth_provider:
        user.oauth_provider = config.get("provider", "oidc")
    await db.flush()

    # Get membership
    stmt = select(OrganizationMembership).where(
        OrganizationMembership.user_id == user.id,
        OrganizationMembership.organization_id == org.id,
    )
    result = await db.execute(stmt)
    membership = result.scalar_one()

    # Create session tokens
    jwt_access, jwt_refresh = create_session_tokens(user, org, membership)

    # Redirect to dashboard with cookies
    app_settings = get_settings()
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(
        key="snapper_access_token",
        value=jwt_access,
        httponly=True,
        secure=not app_settings.DEBUG,
        samesite="lax",
        path="/",
        max_age=app_settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    response.set_cookie(
        key="snapper_refresh_token",
        value=jwt_refresh,
        httponly=True,
        secure=not app_settings.DEBUG,
        samesite="lax",
        path="/",
        max_age=app_settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 86400,
    )

    logger.info(
        f"OIDC login: user={user.id} email={email} org={org.slug} "
        f"provider={config.get('provider', 'oidc')} created={created}"
    )
    return response
