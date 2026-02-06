"""API Key authentication for Snapper agents."""

import logging
from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.models.agents import Agent

logger = logging.getLogger(__name__)
settings = get_settings()


async def get_api_key(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
) -> Optional[str]:
    """
    Extract API key from headers.

    Supports two formats:
    - X-API-Key: snp_xxx
    - Authorization: Bearer snp_xxx
    """
    if x_api_key:
        return x_api_key

    if authorization and authorization.startswith("Bearer "):
        return authorization[7:]

    return None


async def get_current_agent(
    api_key: Optional[str] = Depends(get_api_key),
    db: AsyncSession = Depends(get_db),
) -> Optional[Agent]:
    """
    Get the authenticated agent from API key.

    Returns None if:
    - No API key provided and REQUIRE_API_KEY is False
    - API key is invalid

    Raises HTTPException if:
    - No API key provided and REQUIRE_API_KEY is True
    - API key is for a suspended/deleted agent
    """
    if not api_key:
        if settings.REQUIRE_API_KEY:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key required. Provide X-API-Key header or Authorization: Bearer <key>",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return None

    # Validate API key format
    if not api_key.startswith("snp_"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key format. Keys must start with 'snp_'",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Look up agent by API key
    stmt = select(Agent).where(
        Agent.api_key == api_key,
        Agent.is_deleted == False,
    )
    result = await db.execute(stmt)
    agent = result.scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check agent status
    if agent.status == "suspended":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Agent is suspended",
        )

    if agent.status == "quarantined":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Agent is quarantined due to security violations",
        )

    # Update last used timestamp (async, non-blocking)
    await db.execute(
        update(Agent)
        .where(Agent.id == agent.id)
        .values(api_key_last_used=datetime.utcnow())
    )

    return agent


async def require_agent(
    agent: Optional[Agent] = Depends(get_current_agent),
) -> Agent:
    """
    Require an authenticated agent.

    Use this dependency when an endpoint requires authentication.
    """
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return agent


async def optional_agent(
    agent: Optional[Agent] = Depends(get_current_agent),
) -> Optional[Agent]:
    """
    Optionally authenticate an agent.

    Use this dependency when authentication is optional but
    provides additional context if present.
    """
    return agent
