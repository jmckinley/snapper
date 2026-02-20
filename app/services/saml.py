"""SAML 2.0 Service Provider implementation.

Handles SAML metadata generation, assertion parsing, and JIT user provisioning.
Per-org SAML configuration is stored in Organization.settings JSONB.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.organizations import Organization, OrganizationMembership, OrgRole, Team
from app.models.users import User
from app.services.auth import create_access_token, create_refresh_token, hash_password

logger = logging.getLogger(__name__)


def get_saml_settings(org: Organization, request_url: str) -> Dict[str, Any]:
    """Build python3-saml settings dict from org SAML config.

    Organization.settings should contain:
        saml_idp_entity_id: str
        saml_idp_sso_url: str
        saml_idp_x509_cert: str
        saml_idp_slo_url: str (optional)
    """
    app_settings = get_settings()
    saml_config = org.settings or {}

    # Determine SP base URL from the request
    sp_base = request_url.rstrip("/")

    return {
        "strict": True,
        "debug": app_settings.DEBUG,
        "sp": {
            "entityId": f"{sp_base}/auth/saml/metadata/{org.slug}",
            "assertionConsumerService": {
                "url": f"{sp_base}/auth/saml/acs/{org.slug}",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "singleLogoutService": {
                "url": f"{sp_base}/auth/saml/sls/{org.slug}",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
        "idp": {
            "entityId": saml_config.get("saml_idp_entity_id", ""),
            "singleSignOnService": {
                "url": saml_config.get("saml_idp_sso_url", ""),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "singleLogoutService": {
                "url": saml_config.get("saml_idp_slo_url", ""),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": saml_config.get("saml_idp_x509_cert", ""),
        },
    }


def is_saml_configured(org: Organization) -> bool:
    """Check if an organization has SAML SSO configured."""
    s = org.settings or {}
    return bool(
        s.get("saml_idp_entity_id")
        and s.get("saml_idp_sso_url")
        and s.get("saml_idp_x509_cert")
    )


async def jit_provision_user(
    db: AsyncSession,
    org: Organization,
    email: str,
    full_name: Optional[str] = None,
    attributes: Optional[Dict[str, Any]] = None,
) -> Tuple[User, bool]:
    """Just-In-Time provision a user from SAML/OIDC assertion.

    If the user already exists and belongs to the org, returns them.
    If the user exists but isn't in the org, adds membership.
    If the user doesn't exist, creates them with a random password.

    Returns (user, created) tuple.
    """
    email = email.lower().strip()

    # Check if user exists
    stmt = select(User).where(User.email == email, User.deleted_at.is_(None))
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    created = False
    if not user:
        # Create user with random password (SSO users don't need passwords)
        username = email.split("@")[0]
        # Ensure username uniqueness
        existing = await db.execute(
            select(User).where(User.username == username)
        )
        if existing.scalar_one_or_none():
            username = f"{username}-{uuid.uuid4().hex[:6]}"

        user = User(
            id=uuid.uuid4(),
            email=email,
            username=username,
            password_hash=hash_password(uuid.uuid4().hex),
            full_name=full_name,
            is_active=True,
            is_verified=True,
            oauth_provider="saml",
            default_organization_id=org.id,
        )
        db.add(user)
        await db.flush()
        created = True
        logger.info(f"JIT provisioned user {user.id} ({email}) for org {org.id}")

    # Ensure membership exists
    stmt = select(OrganizationMembership).where(
        OrganizationMembership.user_id == user.id,
        OrganizationMembership.organization_id == org.id,
    )
    result = await db.execute(stmt)
    membership = result.scalar_one_or_none()

    if not membership:
        # Default role for SSO-provisioned users
        default_role = (org.settings or {}).get("saml_default_role", OrgRole.MEMBER)
        membership = OrganizationMembership(
            id=uuid.uuid4(),
            user_id=user.id,
            organization_id=org.id,
            role=default_role,
            accepted_at=datetime.now(timezone.utc),
        )
        db.add(membership)
        await db.flush()
        logger.info(f"Added membership for user {user.id} to org {org.id}")

    # Update user info if provided
    if full_name and not user.full_name:
        user.full_name = full_name
    user.last_login_at = datetime.now(timezone.utc)
    if not user.default_organization_id:
        user.default_organization_id = org.id
    await db.flush()

    return user, created


def create_session_tokens(
    user: User, org: Organization, membership: OrganizationMembership
) -> Tuple[str, str]:
    """Create JWT access and refresh tokens for an SSO user."""
    access_token = create_access_token(
        user_id=user.id,
        org_id=org.id,
        role=membership.role if isinstance(membership.role, str) else membership.role.value,
    )
    refresh_token = create_refresh_token(user_id=user.id)
    return access_token, refresh_token
