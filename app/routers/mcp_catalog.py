"""MCP Server Catalog API — browse, search, and sync the catalog.

Provides endpoints for discovering MCP servers from the enriched catalog,
viewing tool definitions, and triggering manual sync.
"""

import logging
from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, select, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user
from app.models.mcp_catalog import MCPCatalogSyncState, MCPServerCatalog

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/mcp-catalog", tags=["MCP Catalog"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class CatalogServerResponse(BaseModel):
    id: UUID
    name: str
    normalized_name: str
    description: Optional[str] = None
    tools_count: int = 0
    trust_tier: str = "unknown"
    auth_type: Optional[str] = None
    popularity_score: int = 0
    categories: list = []
    is_official: bool = False
    source: str
    repository: Optional[str] = None
    homepage: Optional[str] = None
    security_category: str = "general"


class CatalogServerDetail(CatalogServerResponse):
    tools: list = []
    security_metadata: dict = {}
    pulsemcp_id: Optional[str] = None
    glama_id: Optional[str] = None
    last_synced_at: Optional[datetime] = None
    suggested_rules_preview: list = []


class CatalogStatsResponse(BaseModel):
    total_servers: int
    by_trust_tier: dict
    by_auth_type: dict
    by_source: dict
    last_sync_time: Optional[datetime] = None
    tools_enriched_count: int = 0


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/servers")
async def list_catalog_servers(
    db: AsyncSession = Depends(get_db),
    search: Optional[str] = Query(None, min_length=1, max_length=200),
    category: Optional[str] = None,
    security_category: Optional[str] = None,
    auth_type: Optional[str] = None,
    trust_tier: Optional[str] = None,
    sort_by: str = Query("popularity", regex="^(popularity|name|tools_count)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    """Browse and search the MCP server catalog.

    Supports filtering by category, auth_type, trust_tier, and full-text search.
    """
    query = select(MCPServerCatalog)

    if search:
        search_term = f"%{search.lower()}%"
        query = query.where(
            or_(
                MCPServerCatalog.normalized_name.ilike(search_term),
                MCPServerCatalog.name.ilike(search_term),
                MCPServerCatalog.description.ilike(search_term),
            )
        )

    if category:
        # Categories is a JSONB array — check if it contains the value
        query = query.where(MCPServerCatalog.categories.contains([category]))

    if security_category:
        query = query.where(MCPServerCatalog.security_category == security_category)

    if auth_type:
        query = query.where(MCPServerCatalog.auth_type == auth_type)

    if trust_tier:
        query = query.where(MCPServerCatalog.trust_tier == trust_tier)

    # Count total before pagination
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Sort
    if sort_by == "popularity":
        query = query.order_by(MCPServerCatalog.popularity_score.desc(), MCPServerCatalog.name)
    elif sort_by == "name":
        query = query.order_by(MCPServerCatalog.name)
    elif sort_by == "tools_count":
        query = query.order_by(MCPServerCatalog.tools_count.desc(), MCPServerCatalog.name)

    # Paginate
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    result = await db.execute(query)
    servers = result.scalars().all()

    return {
        "servers": [
            CatalogServerResponse(
                id=s.id,
                name=s.name,
                normalized_name=s.normalized_name,
                description=s.description,
                tools_count=s.tools_count,
                trust_tier=s.trust_tier,
                auth_type=s.auth_type,
                popularity_score=s.popularity_score,
                categories=s.categories or [],
                is_official=s.is_official,
                source=s.source,
                repository=s.repository,
                homepage=s.homepage,
                security_category=s.security_category,
            ).model_dump()
            for s in servers
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size if page_size > 0 else 0,
    }


@router.get("/servers/{server_id}")
async def get_catalog_server(
    server_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get full details for a catalog server including tools and suggested rules."""
    server = (
        await db.execute(
            select(MCPServerCatalog).where(MCPServerCatalog.id == server_id)
        )
    ).scalar_one_or_none()

    if not server:
        raise HTTPException(status_code=404, detail="Server not found in catalog")

    # Generate suggested rules preview
    suggested_rules = []
    try:
        from app.services.catalog_rule_generator import generate_rules_from_catalog
        rules = await generate_rules_from_catalog(db, server.normalized_name)
        if rules:
            suggested_rules = rules
        else:
            from app.services.traffic_discovery import generate_rules_for_server
            suggested_rules = await generate_rules_for_server(server.normalized_name, db=db)
    except Exception as e:
        logger.debug(f"Failed to generate rule preview: {e}")

    return CatalogServerDetail(
        id=server.id,
        name=server.name,
        normalized_name=server.normalized_name,
        description=server.description,
        tools=server.tools or [],
        tools_count=server.tools_count,
        trust_tier=server.trust_tier,
        auth_type=server.auth_type,
        popularity_score=server.popularity_score,
        categories=server.categories or [],
        is_official=server.is_official,
        source=server.source,
        repository=server.repository,
        homepage=server.homepage,
        security_metadata=server.security_metadata or {},
        security_category=server.security_category,
        pulsemcp_id=server.pulsemcp_id,
        glama_id=server.glama_id,
        last_synced_at=server.last_synced_at,
        suggested_rules_preview=suggested_rules,
    ).model_dump()


@router.get("/stats")
async def get_catalog_stats(
    db: AsyncSession = Depends(get_db),
):
    """Aggregate catalog statistics."""
    # Total
    total = (await db.execute(select(func.count(MCPServerCatalog.id)))).scalar() or 0

    # By trust tier
    tier_result = await db.execute(
        select(MCPServerCatalog.trust_tier, func.count(MCPServerCatalog.id))
        .group_by(MCPServerCatalog.trust_tier)
    )
    by_tier = {row[0]: row[1] for row in tier_result.all()}

    # By auth type
    auth_result = await db.execute(
        select(MCPServerCatalog.auth_type, func.count(MCPServerCatalog.id))
        .group_by(MCPServerCatalog.auth_type)
    )
    by_auth = {(row[0] or "unknown"): row[1] for row in auth_result.all()}

    # By source
    source_result = await db.execute(
        select(MCPServerCatalog.source, func.count(MCPServerCatalog.id))
        .group_by(MCPServerCatalog.source)
    )
    by_source = {row[0]: row[1] for row in source_result.all()}

    # Last sync time
    sync_result = await db.execute(
        select(func.max(MCPCatalogSyncState.last_synced_at))
    )
    last_sync = sync_result.scalar()

    # Tools enriched count
    tools_enriched = (await db.execute(
        select(func.count(MCPServerCatalog.id)).where(MCPServerCatalog.tools_count > 0)
    )).scalar() or 0

    return CatalogStatsResponse(
        total_servers=total,
        by_trust_tier=by_tier,
        by_auth_type=by_auth,
        by_source=by_source,
        last_sync_time=last_sync,
        tools_enriched_count=tools_enriched,
    ).model_dump()


@router.get("/categories")
async def list_security_categories(
    db: AsyncSession = Depends(get_db),
):
    """List security categories with server counts.

    Returns all 13 security categories with the number of servers
    classified into each one, plus template rule info.
    """
    from app.data.category_rule_templates import get_all_categories

    # Get server counts per category
    count_result = await db.execute(
        select(MCPServerCatalog.security_category, func.count(MCPServerCatalog.id))
        .group_by(MCPServerCatalog.security_category)
    )
    counts = {row[0]: row[1] for row in count_result.all()}

    categories = get_all_categories()
    for cat in categories:
        cat["server_count"] = counts.get(cat["category"], 0)

    return {
        "categories": categories,
        "total_servers": sum(counts.values()),
    }


@router.get("/categories/{category}/rules")
async def preview_category_rules(
    category: str,
):
    """Preview the template rules for a security category.

    Shows what rules would be created for a server in this category,
    using placeholder server name.
    """
    from app.data.category_rule_templates import (
        CATEGORY_RULE_TEMPLATES,
        generate_rules_from_category,
    )

    if category not in CATEGORY_RULE_TEMPLATES:
        raise HTTPException(status_code=404, detail=f"Category '{category}' not found")

    rules = generate_rules_from_category(
        category=category,
        server_key="example_server",
        server_display="Example Server",
    )
    template = CATEGORY_RULE_TEMPLATES[category]

    return {
        "category": category,
        "name": template["name"],
        "posture": template["posture"],
        "rules": rules,
    }


@router.post("/sync")
async def trigger_catalog_sync(
    force_full: bool = Query(False),
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a manual catalog sync (admin only).

    Returns a task ID for tracking progress.
    """
    # Check admin permission
    if not user.get("permissions", {}).get("can_manage_rules", False):
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        from app.tasks.mcp_catalog_sync import sync_mcp_catalog
        task = sync_mcp_catalog.delay(force_full=force_full)
        return {
            "message": "Catalog sync started",
            "task_id": str(task.id),
            "force_full": force_full,
        }
    except Exception as e:
        logger.error(f"Failed to start catalog sync: {e}")
        raise HTTPException(status_code=500, detail="Failed to start sync task")
