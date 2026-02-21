"""Extension config sync service — builds and caches config bundles per org.

The browser extension periodically fetches this bundle to stay updated with
service registry changes, blocked services, and feature flags without
requiring a new extension release.
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.organizations import Organization
from app.redis_client import RedisClient
from app.routers.shadow_ai import _KNOWN_AI_SERVICES

logger = logging.getLogger(__name__)
settings = get_settings()

# Redis cache key prefix and TTL
_CACHE_PREFIX = "ext_config"
_CACHE_TTL = 86400  # 24 hours

# Default feature flags
_DEFAULT_FEATURE_FLAGS = {
    "pii_scanning": True,
    "clipboard_monitoring": True,
    "shadow_ai_tracking": True,
    "pii_blocking_mode": "warn",
}


def _build_service_registry() -> list:
    """Merge backend known services with tier/category info from the static extension registry."""
    # Backend _KNOWN_AI_SERVICES already has: source, label, domains, risk, category, data_residency
    # We add tier classification based on the extension's tier system
    _TIER1 = {"chatgpt", "claude", "gemini", "copilot", "grok", "deepseek", "perplexity", "github_copilot"}
    _TIER3 = {
        "together", "cohere", "anyscale", "fireworks", "groq", "openrouter",
        "replicate", "stability", "photoroom", "canva_ai", "adobe_firefly",
        "descript", "otter_ai", "coda_ai", "tome", "gamma", "beautiful_ai",
        "tabnine", "codeium", "sourcegraph", "amazon_q", "windsurf", "phind",
        "you", "pi", "character_ai", "inflection",
    }

    registry = []
    for svc in _KNOWN_AI_SERVICES:
        entry = {**svc}
        src = svc["source"]
        if src in _TIER1:
            entry["tier"] = 1
        elif src in _TIER3:
            entry["tier"] = 3
        else:
            entry["tier"] = 2
        registry.append(entry)
    return registry


def _extract_visit_domains(registry: list) -> list:
    """Extract flat list of domains from Tier 3 services for visit tracking."""
    domains = []
    for svc in registry:
        if svc.get("tier") == 3:
            domains.extend(svc.get("domains", []))
    return sorted(set(domains))


async def build_config_bundle(db: AsyncSession, org_id: Optional[UUID] = None) -> Dict[str, Any]:
    """Build a complete extension config bundle.

    If org_id is provided, merges org-level overrides (blocked_services, feature_flags, etc.).
    Otherwise returns global defaults.
    """
    registry = _build_service_registry()
    visit_domains = _extract_visit_domains(registry)

    bundle: Dict[str, Any] = {
        "config_version": datetime.now(timezone.utc).isoformat(),
        "sync_interval_seconds": settings.EXTENSION_SYNC_INTERVAL_SECONDS,
        "service_registry": registry,
        "blocked_services": [],
        "feature_flags": {**_DEFAULT_FEATURE_FLAGS},
        "visit_domains": visit_domains,
    }

    # Merge org-level overrides if available
    if org_id:
        result = await db.execute(
            select(Organization).where(
                Organization.id == org_id,
                Organization.deleted_at.is_(None),
            )
        )
        org = result.scalar_one_or_none()
        if org and org.settings:
            ext_config = org.settings.get("extension_config", {})
            if ext_config.get("blocked_services"):
                bundle["blocked_services"] = ext_config["blocked_services"]
            if ext_config.get("feature_flags"):
                bundle["feature_flags"].update(ext_config["feature_flags"])
            if ext_config.get("sync_interval_seconds"):
                bundle["sync_interval_seconds"] = ext_config["sync_interval_seconds"]

    return bundle


def compute_etag(bundle: Dict[str, Any]) -> str:
    """Compute a deterministic ETag from the bundle content.

    Excludes config_version (timestamp) so the ETag only changes
    when actual content changes.
    """
    # Copy without volatile fields
    stable = {k: v for k, v in bundle.items() if k != "config_version"}
    content = json.dumps(stable, sort_keys=True, default=str)
    return hashlib.sha256(content.encode()).hexdigest()[:16]


async def cache_bundle(org_id: Optional[UUID], bundle: Dict[str, Any], redis: RedisClient) -> str:
    """Cache the bundle in Redis and return the ETag."""
    etag = compute_etag(bundle)
    key = f"{_CACHE_PREFIX}:{org_id or 'global'}"
    payload = json.dumps({"bundle": bundle, "etag": etag})
    await redis.set(key, payload, expire=_CACHE_TTL)
    return etag


async def get_or_build_bundle(
    db: AsyncSession, org_id: Optional[UUID], redis: RedisClient
) -> Tuple[Dict[str, Any], str]:
    """Return cached bundle or build a fresh one.

    Returns (bundle_dict, etag_str).
    """
    key = f"{_CACHE_PREFIX}:{org_id or 'global'}"
    cached = await redis.get(key)
    if cached:
        try:
            data = json.loads(cached)
            return data["bundle"], data["etag"]
        except (json.JSONDecodeError, KeyError):
            pass

    bundle = await build_config_bundle(db, org_id)
    etag = await cache_bundle(org_id, bundle, redis)
    return bundle, etag


async def invalidate_bundle(org_id: Optional[UUID], redis: RedisClient) -> None:
    """Delete cached bundle so the next GET rebuilds it."""
    key = f"{_CACHE_PREFIX}:{org_id or 'global'}"
    await redis.delete(key)
