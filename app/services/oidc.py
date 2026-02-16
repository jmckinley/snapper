"""OpenID Connect client implementation.

Handles authorization code flow with support for any OIDC-compliant provider.
Per-org configuration stored in Organization.settings JSONB.
"""

import logging
import secrets
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlencode

import httpx

from app.config import get_settings
from app.models.organizations import Organization

logger = logging.getLogger(__name__)

# Well-known provider configurations (issuer → discovery URL)
KNOWN_PROVIDERS = {
    "okta": "{domain}/.well-known/openid-configuration",
    "entra": "https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration",
    "google": "https://accounts.google.com/.well-known/openid-configuration",
}


def is_oidc_configured(org: Organization) -> bool:
    """Check if an organization has OIDC configured."""
    s = org.settings or {}
    return bool(
        s.get("oidc_issuer") and s.get("oidc_client_id") and s.get("oidc_client_secret")
    )


def get_oidc_config(org: Organization) -> Dict[str, Any]:
    """Extract OIDC configuration from organization settings."""
    s = org.settings or {}
    return {
        "issuer": s.get("oidc_issuer", ""),
        "client_id": s.get("oidc_client_id", ""),
        "client_secret": s.get("oidc_client_secret", ""),
        "scopes": s.get("oidc_scopes", "openid email profile"),
        "provider": s.get("oidc_provider", "generic"),
    }


async def discover_oidc_endpoints(issuer: str) -> Dict[str, str]:
    """Fetch OIDC discovery document to get authorization and token endpoints."""
    discovery_url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(discovery_url)
        response.raise_for_status()
        doc = response.json()

    return {
        "authorization_endpoint": doc["authorization_endpoint"],
        "token_endpoint": doc["token_endpoint"],
        "userinfo_endpoint": doc.get("userinfo_endpoint", ""),
        "jwks_uri": doc.get("jwks_uri", ""),
        "end_session_endpoint": doc.get("end_session_endpoint", ""),
    }


def build_authorization_url(
    org: Organization,
    redirect_uri: str,
    state: str,
    nonce: str,
    endpoints: Dict[str, str],
) -> str:
    """Build the OIDC authorization URL for redirect."""
    config = get_oidc_config(org)
    params = {
        "client_id": config["client_id"],
        "response_type": "code",
        "scope": config["scopes"],
        "redirect_uri": redirect_uri,
        "state": state,
        "nonce": nonce,
    }
    return f"{endpoints['authorization_endpoint']}?{urlencode(params)}"


async def exchange_code_for_tokens(
    org: Organization,
    code: str,
    redirect_uri: str,
    endpoints: Dict[str, str],
) -> Dict[str, Any]:
    """Exchange authorization code for ID token and access token."""
    config = get_oidc_config(org)

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            endpoints["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": config["client_id"],
                "client_secret": config["client_secret"],
            },
            headers={"Accept": "application/json"},
        )
        response.raise_for_status()
        return response.json()


async def get_userinfo(
    access_token: str,
    endpoints: Dict[str, str],
) -> Dict[str, Any]:
    """Fetch user information from the OIDC provider."""
    userinfo_url = endpoints.get("userinfo_endpoint")
    if not userinfo_url:
        return {}

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            userinfo_url,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        response.raise_for_status()
        return response.json()


def decode_id_token_unverified(id_token: str) -> Dict[str, Any]:
    """Decode ID token claims without cryptographic verification.

    In production, you should verify the token signature against the JWKS.
    This is acceptable when the token was just received directly from the
    token endpoint over HTTPS (no intermediary).
    """
    import base64
    import json

    parts = id_token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    # Decode payload (second part)
    payload = parts[1]
    # Add padding
    payload += "=" * (4 - len(payload) % 4)
    decoded = base64.urlsafe_b64decode(payload)
    return json.loads(decoded)


def generate_state_and_nonce() -> Tuple[str, str]:
    """Generate cryptographically secure state and nonce values."""
    return secrets.token_urlsafe(32), secrets.token_urlsafe(32)
