"""Quota enforcement dependency for resource-creating endpoints."""

from uuid import UUID

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.services.plans import check_quota


class QuotaChecker:
    """
    FastAPI dependency that checks plan quotas before resource creation.

    Usage:
        @router.post("/agents", dependencies=[Depends(QuotaChecker("agents"))])
        async def create_agent(...):
            ...

    When SELF_HOSTED is True or no organization context exists on the request,
    the check is silently skipped for backward compatibility.
    """

    def __init__(self, resource_type: str):
        self.resource_type = resource_type

    async def __call__(
        self, request: Request, db: AsyncSession = Depends(get_db)
    ) -> None:
        settings = get_settings()
        if settings.SELF_HOSTED:
            return  # No limits in self-hosted mode

        org_id = getattr(request.state, "org_id", None)
        if not org_id:
            return  # No org context = no quota check (backward compat)

        await check_quota(db, UUID(str(org_id)), self.resource_type)
