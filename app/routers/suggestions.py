"""Smart suggestions API endpoints.

Surfaces contextual recommendations on the dashboard based on
system state — uncovered traffic, disabled features, security gaps.
"""

import logging
from typing import List

from fastapi import APIRouter, Depends, Request

from app.dependencies import DbSessionDep, RedisDep

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/suggestions", tags=["suggestions"])


@router.get("", tags=["Core"])
async def list_suggestions(
    request: Request,
    db: DbSessionDep,
    redis: RedisDep,
):
    """Return prioritized suggestions for the current user/org."""
    from app.services.suggestions import generate_suggestions

    org_id = getattr(request.state, "org_id", None)
    org_key = str(org_id) if org_id else "default"

    suggestions = await generate_suggestions(db=db, redis=redis, org_key=org_key)
    return [s.to_dict() for s in suggestions]


@router.post("/{suggestion_id}/dismiss", tags=["Core"])
async def dismiss_suggestion(
    suggestion_id: str,
    request: Request,
    redis: RedisDep,
):
    """Dismiss a suggestion for 30 days."""
    from app.services.suggestions import dismiss_suggestion as _dismiss

    org_id = getattr(request.state, "org_id", None)
    org_key = str(org_id) if org_id else "default"

    await _dismiss(redis=redis, org_key=org_key, suggestion_id=suggestion_id)
    return {"status": "dismissed", "id": suggestion_id}
