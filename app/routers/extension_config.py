"""Extension config sync endpoints.

GET  /extension/config  — Return config bundle with ETag caching
PUT  /extension/config  — Admin: update org extension settings
"""

import json
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.config import get_settings
from app.dependencies import DbSessionDep, OptionalOrgIdDep, RedisDep, require_manage_org
from app.models.organizations import Organization
from app.services.extension_config import get_or_build_bundle, invalidate_bundle

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter(prefix="/extension")


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ExtensionConfigUpdate(BaseModel):
    blocked_services: Optional[List[str]] = None
    feature_flags: Optional[Dict[str, Any]] = None
    sync_interval_seconds: Optional[int] = Field(None, ge=60, le=86400)


# ---------------------------------------------------------------------------
# GET /extension/config
# ---------------------------------------------------------------------------


@router.get("/config")
async def get_extension_config(
    request: Request,
    db: DbSessionDep,
    org_id: OptionalOrgIdDep,
    redis: RedisDep,
):
    """Return the extension config bundle with ETag support.

    Supports conditional requests via If-None-Match header.
    Unauthenticated requests receive global defaults.
    """
    bundle, etag = await get_or_build_bundle(db, org_id, redis)

    # Check If-None-Match for conditional 304
    if_none_match = request.headers.get("if-none-match", "").strip('" ')
    if if_none_match and if_none_match == etag:
        return Response(status_code=304, headers={
            "ETag": f'"{etag}"',
            "Cache-Control": "private, max-age=300",
        })

    return Response(
        content=json.dumps(bundle),
        media_type="application/json",
        headers={
            "ETag": f'"{etag}"',
            "Cache-Control": "private, max-age=300",
        },
    )


# ---------------------------------------------------------------------------
# PUT /extension/config
# ---------------------------------------------------------------------------


@router.put("/config", dependencies=[Depends(require_manage_org)])
async def update_extension_config(
    body: ExtensionConfigUpdate,
    db: DbSessionDep,
    org_id: OptionalOrgIdDep,
    redis: RedisDep,
):
    """Update organization-level extension config (admin only).

    Merges into org.settings['extension_config'] and invalidates cache.
    """
    if not org_id:
        raise HTTPException(status_code=400, detail="Organization context required")

    result = await db.execute(
        select(Organization).where(
            Organization.id == org_id,
            Organization.deleted_at.is_(None),
        )
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Merge updates into extension_config
    current_settings = dict(org.settings or {})
    ext_config = current_settings.get("extension_config", {})

    if body.blocked_services is not None:
        ext_config["blocked_services"] = body.blocked_services
    if body.feature_flags is not None:
        ext_config["feature_flags"] = body.feature_flags
    if body.sync_interval_seconds is not None:
        ext_config["sync_interval_seconds"] = body.sync_interval_seconds

    current_settings["extension_config"] = ext_config
    org.settings = current_settings
    await db.commit()

    # Invalidate cached bundle
    await invalidate_bundle(org_id, redis)

    return {"status": "updated", "extension_config": ext_config}
