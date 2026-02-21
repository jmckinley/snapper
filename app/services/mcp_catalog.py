"""MCP Server Catalog: auto-profile servers from public registries.

Fetches server listings from public MCP registries (Smithery, NPM,
awesome-mcp-servers, PulseMCP, Glama) and merges tool/capability metadata
into Snapper's known-server registry for auto-generated rule packs.

Source priority (higher overwrites core fields):
  pulsemcp (5) > smithery (4) > glama (3) > npm (2) > awesome-mcp-servers (1)

Designed to run as a daily Celery task. Network failures are tolerated
gracefully — the catalog is additive and stale data is harmless.
"""

import asyncio
import logging
import math
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy import select

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Public registry endpoints
SMITHERY_API = "https://registry.smithery.ai/servers"
NPM_SEARCH = "https://registry.npmjs.org/-/v1/search"
AWESOME_MCP_RAW = (
    "https://raw.githubusercontent.com/punkpeye/awesome-mcp-servers/"
    "main/README.md"
)
PULSEMCP_API = "https://api.pulsemcp.com/v0.1/servers"
GLAMA_API = "https://glama.ai/api/mcp/v1/servers"

# Timeout for external fetches
FETCH_TIMEOUT = 20.0

# Source priorities (higher wins for field overwrites)
SOURCE_PRIORITY = {
    "pulsemcp": 5,
    "smithery": 4,
    "glama": 3,
    "npm": 2,
    "awesome-mcp-servers": 1,
}


# ---------------------------------------------------------------------------
# Fetchers
# ---------------------------------------------------------------------------

async def fetch_pulsemcp_servers(
    updated_since: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fetch server listings from PulseMCP (richest data source).

    Returns tool definitions, auth type, popularity, categories.
    Supports incremental sync via updated_since parameter.
    """
    if not settings.PULSEMCP_API_KEY:
        logger.debug("Skipping PulseMCP: no API key configured")
        return []

    results: List[Dict[str, Any]] = []
    headers = {"X-API-Key": settings.PULSEMCP_API_KEY}
    if settings.PULSEMCP_TENANT_ID:
        headers["X-Tenant-ID"] = settings.PULSEMCP_TENANT_ID

    try:
        async with httpx.AsyncClient(timeout=FETCH_TIMEOUT) as client:
            cursor = None
            pages_fetched = 0
            max_pages = 20  # Safety limit

            while pages_fetched < max_pages:
                params: Dict[str, Any] = {"version": "latest", "limit": 100}
                if cursor:
                    params["cursor"] = cursor
                if updated_since:
                    params["updated_since"] = updated_since

                resp = await client.get(PULSEMCP_API, params=params, headers=headers)
                if resp.status_code != 200:
                    logger.debug(f"PulseMCP returned {resp.status_code}")
                    break

                data = resp.json()
                servers = data.get("servers", data.get("results", []))
                if not servers:
                    break

                for srv in servers:
                    if not isinstance(srv, dict):
                        continue

                    # Extract tools with full definitions
                    tools = []
                    for tool in srv.get("tools", []):
                        if isinstance(tool, dict):
                            tools.append({
                                "name": tool.get("name", ""),
                                "description": tool.get("description", ""),
                                "inputSchema": tool.get("inputSchema"),
                            })
                        elif isinstance(tool, str):
                            tools.append({"name": tool})

                    # Compute popularity from visitor stats (log-scale 0-100)
                    visitors = srv.get("monthly_visitors") or srv.get("visitors") or 0
                    popularity = _compute_popularity(visitors)

                    results.append({
                        "name": srv.get("name") or srv.get("title", "unknown"),
                        "description": (srv.get("description") or "")[:500],
                        "tools": tools,
                        "repository": srv.get("repository", {}).get("url") if isinstance(srv.get("repository"), dict) else srv.get("repository"),
                        "homepage": srv.get("homepage") or srv.get("url"),
                        "source": "pulsemcp",
                        "pulsemcp_id": srv.get("id") or srv.get("slug"),
                        "auth_type": srv.get("auth_type") or srv.get("authentication", {}).get("type") if isinstance(srv.get("authentication"), dict) else None,
                        "is_official": bool(srv.get("is_official") or srv.get("official")),
                        "categories": srv.get("categories", []),
                        "popularity_score": popularity,
                        "security_metadata": {
                            k: v for k, v in {
                                "license": srv.get("license"),
                                "auth_options": srv.get("authentication"),
                                "security_grade": srv.get("security_grade"),
                            }.items() if v is not None
                        },
                    })

                cursor = data.get("next_cursor") or data.get("cursor")
                if not cursor:
                    break
                pages_fetched += 1

                # Respect rate limit: 200 req/min → 0.3s between pages
                await asyncio.sleep(0.3)

    except Exception as e:
        logger.debug(f"PulseMCP fetch failed: {e}")
    return results


async def fetch_glama_servers(max_entries: int = 20000) -> List[Dict[str, Any]]:
    """Fetch server listings from Glama (breadth source, ~17,600 servers).

    No auth required. Tools are always empty in the API.
    Glama API returns ~10 items per page regardless of limit param,
    so we paginate aggressively with a high max_pages ceiling.
    Capped at max_entries to avoid runaway fetches.
    """
    if not settings.GLAMA_CATALOG_ENABLED:
        logger.debug("Skipping Glama: disabled in config")
        return []

    results: List[Dict[str, Any]] = []
    try:
        async with httpx.AsyncClient(timeout=FETCH_TIMEOUT) as client:
            cursor = None
            pages_fetched = 0
            # Glama returns ~10 per page, so we need many pages
            max_pages = max_entries // 10 + 1

            while pages_fetched < max_pages and len(results) < max_entries:
                params: Dict[str, Any] = {"limit": 100}
                if cursor:
                    params["after"] = cursor

                resp = await client.get(GLAMA_API, params=params)
                if resp.status_code != 200:
                    logger.debug(f"Glama returned {resp.status_code}")
                    break

                data = resp.json()
                servers = data.get("servers", data.get("data", data.get("results", [])))
                if not servers:
                    break

                for srv in servers:
                    if not isinstance(srv, dict):
                        continue

                    name = srv.get("name") or srv.get("slug", "")
                    namespace = srv.get("namespace", "")
                    full_name = f"{namespace}/{name}" if namespace else name

                    repo_url = None
                    repo = srv.get("repository")
                    if isinstance(repo, dict):
                        repo_url = repo.get("url")
                    elif isinstance(repo, str):
                        repo_url = repo

                    results.append({
                        "name": full_name or "unknown",
                        "description": (srv.get("description") or "")[:500],
                        "tools": [],  # Glama API doesn't include tools
                        "repository": repo_url,
                        "homepage": srv.get("homepage"),
                        "source": "glama",
                        "glama_id": srv.get("id") or srv.get("slug"),
                        "security_metadata": {
                            k: v for k, v in {
                                "license": srv.get("license"),
                            }.items() if v is not None
                        },
                    })

                # Cursor-based pagination
                page_info = data.get("pageInfo", {})
                cursor = page_info.get("endCursor")
                if not cursor or not page_info.get("hasNextPage", False):
                    break
                pages_fetched += 1

                # Log progress every 100 pages
                if pages_fetched % 100 == 0:
                    logger.info(f"Glama fetch progress: {len(results)} servers, page {pages_fetched}")

                await asyncio.sleep(0.2)

    except Exception as e:
        logger.debug(f"Glama fetch failed: {e}")
    return results


async def fetch_smithery_servers(max_entries: int = 5000) -> List[Dict[str, Any]]:
    """Fetch server listings from the Smithery registry (~3,500+ servers).

    Uses page-based pagination. API returns ~10 items per page.
    """
    results: List[Dict[str, Any]] = []
    try:
        async with httpx.AsyncClient(timeout=FETCH_TIMEOUT) as client:
            page = 1
            max_pages = max_entries // 10 + 1

            while page <= max_pages and len(results) < max_entries:
                resp = await client.get(SMITHERY_API, params={"page": page, "pageSize": 100})
                if resp.status_code != 200:
                    logger.debug(f"Smithery returned {resp.status_code}")
                    break

                data = resp.json()
                servers = data.get("servers", data.get("results", []))
                if not servers:
                    break

                for srv in servers:
                    if not isinstance(srv, dict):
                        continue
                    results.append({
                        "name": srv.get("qualifiedName") or srv.get("displayName") or srv.get("name", "unknown"),
                        "description": (srv.get("description") or "")[:500],
                        "tools": srv.get("tools", []),
                        "repository": srv.get("repository", {}).get("url") if isinstance(srv.get("repository"), dict) else srv.get("repository"),
                        "homepage": srv.get("homepage"),
                        "source": "smithery",
                        "is_official": bool(srv.get("verified")),
                        "popularity_score": _compute_popularity(srv.get("useCount", 0)),
                    })

                # Check pagination
                pagination = data.get("pagination", {})
                total_pages = pagination.get("totalPages", 1)
                if page >= total_pages:
                    break
                page += 1

                if page % 50 == 0:
                    logger.info(f"Smithery fetch progress: {len(results)} servers, page {page}")

                await asyncio.sleep(0.2)

    except Exception as e:
        logger.debug(f"Smithery fetch failed: {e}")
    return results


async def fetch_npm_mcp_packages(limit: int = 100) -> List[Dict[str, Any]]:
    """Search NPM for MCP server packages."""
    results: List[Dict[str, Any]] = []
    queries = ["@modelcontextprotocol", "mcp-server"]

    try:
        async with httpx.AsyncClient(timeout=FETCH_TIMEOUT) as client:
            for query in queries:
                resp = await client.get(
                    NPM_SEARCH,
                    params={"text": query, "size": min(limit, 50)},
                )
                if resp.status_code != 200:
                    continue

                data = resp.json()
                for obj in data.get("objects", []):
                    pkg = obj.get("package", {})
                    name = pkg.get("name", "")
                    if not name:
                        continue

                    results.append({
                        "name": name,
                        "description": (pkg.get("description") or "")[:500],
                        "tools": [],  # NPM doesn't list tools
                        "repository": (pkg.get("links", {}).get("repository")),
                        "homepage": pkg.get("links", {}).get("homepage"),
                        "source": "npm",
                    })
    except Exception as e:
        logger.debug(f"NPM fetch failed: {e}")
    return results


async def fetch_awesome_mcp_servers() -> List[Dict[str, Any]]:
    """Parse the awesome-mcp-servers README for server names."""
    results: List[Dict[str, Any]] = []
    try:
        async with httpx.AsyncClient(timeout=FETCH_TIMEOUT) as client:
            resp = await client.get(AWESOME_MCP_RAW)
            if resp.status_code != 200:
                return results

            text = resp.text
            pattern = re.compile(r"\[([^\]]+)\]\((https://github\.com/[^\)]+)\)")
            seen = set()

            for match in pattern.finditer(text):
                name = match.group(1).strip()
                url = match.group(2).strip()

                if url in seen:
                    continue
                seen.add(url)

                if len(name) < 3 or len(name) > 100:
                    continue

                results.append({
                    "name": name,
                    "description": "",
                    "tools": [],
                    "repository": url,
                    "homepage": None,
                    "source": "awesome-mcp-servers",
                })
    except Exception as e:
        logger.debug(f"awesome-mcp-servers fetch failed: {e}")
    return results


# ---------------------------------------------------------------------------
# Sync orchestrator
# ---------------------------------------------------------------------------

async def sync_catalog(db, force_full: bool = False) -> Dict[str, int]:
    """Fetch from all registries and upsert into mcp_server_catalog.

    Source priority determines which fields win on conflict:
      pulsemcp (5) > smithery (4) > glama (3) > npm (2) > awesome-mcp-servers (1)

    Returns counts: {"new": N, "updated": N, "sources_checked": N, "tools_enriched": N}
    """
    from app.models.mcp_catalog import MCPCatalogSyncState, MCPServerCatalog
    from app.services.traffic_discovery import KNOWN_MCP_SERVERS

    # Load sync state for incremental sync
    sync_states: Dict[str, MCPCatalogSyncState] = {}
    result = await db.execute(select(MCPCatalogSyncState))
    for state in result.scalars().all():
        sync_states[state.source] = state

    # Determine if PulseMCP can use incremental
    pulsemcp_since = None
    if not force_full and "pulsemcp" in sync_states and sync_states["pulsemcp"].last_synced_at:
        pulsemcp_since = sync_states["pulsemcp"].last_synced_at.isoformat()

    # Fetch from all sources in parallel
    results = await asyncio.gather(
        fetch_pulsemcp_servers(updated_since=pulsemcp_since),
        fetch_smithery_servers(),
        fetch_glama_servers(),
        fetch_npm_mcp_packages(),
        fetch_awesome_mcp_servers(),
        return_exceptions=True,
    )

    source_names = ["pulsemcp", "smithery", "glama", "npm", "awesome-mcp-servers"]
    sources_checked = 0
    # Group servers by source with their priority
    all_servers_by_source: Dict[str, List[Dict[str, Any]]] = {}

    for i, result_item in enumerate(results):
        source_name = source_names[i]
        if isinstance(result_item, list):
            all_servers_by_source[source_name] = result_item
            sources_checked += 1

            # Update sync state
            state = sync_states.get(source_name)
            if not state:
                state = MCPCatalogSyncState(source=source_name)
                db.add(state)
                sync_states[source_name] = state
            state.last_synced_at = datetime.now(timezone.utc)
            state.entries_count = len(result_item)

        elif isinstance(result_item, Exception):
            logger.warning(f"Catalog source {source_name} failed: {result_item}")

    # Merge all servers: process in priority order (lowest first so highest overwrites)
    sorted_sources = sorted(
        all_servers_by_source.keys(),
        key=lambda s: SOURCE_PRIORITY.get(s, 0),
    )

    # Track: normalized_name → {best_source_priority, merged_data}
    merged: Dict[str, Dict[str, Any]] = {}

    for source_name in sorted_sources:
        priority = SOURCE_PRIORITY.get(source_name, 0)
        for srv in all_servers_by_source[source_name]:
            name = srv.get("name", "").strip()
            if not name:
                continue

            normalized = name.lower().replace(" ", "-")

            if normalized not in merged:
                merged[normalized] = {
                    "name": name,
                    "priority": priority,
                    "tools": [],
                    **srv,
                }
            else:
                existing = merged[normalized]
                # Higher-priority source overwrites core fields
                if priority >= existing["priority"]:
                    for field in ["name", "description", "repository", "homepage",
                                  "auth_type", "is_official", "popularity_score",
                                  "pulsemcp_id", "glama_id", "security_metadata",
                                  "categories"]:
                        if srv.get(field):
                            existing[field] = srv[field]
                    existing["source"] = source_name
                    existing["priority"] = priority

                # Merge tools additively (deduplicate by name)
                existing_tool_names = {
                    (t.get("name") if isinstance(t, dict) else t)
                    for t in existing.get("tools", [])
                }
                for tool in srv.get("tools", []):
                    tool_name = tool.get("name") if isinstance(tool, dict) else tool
                    if tool_name and tool_name not in existing_tool_names:
                        existing["tools"].append(tool)
                        existing_tool_names.add(tool_name)

    # Determine trust tiers
    known_names = set()
    for key in KNOWN_MCP_SERVERS:
        known_names.add(key.lower())

    # Upsert into database
    new_count = 0
    updated_count = 0
    tools_enriched = 0

    for normalized, data in merged.items():
        # Determine trust tier
        trust_tier = "community"
        name_lower = normalized.replace("-", "_")
        if name_lower in known_names or normalized in known_names:
            trust_tier = "curated"
        elif data.get("is_official"):
            trust_tier = "verified"

        tools = data.get("tools", [])
        tools_count = len(tools)

        existing = (
            await db.execute(
                select(MCPServerCatalog).where(
                    MCPServerCatalog.normalized_name == normalized
                )
            )
        ).scalar_one_or_none()

        if existing:
            # Update fields from higher-priority source
            if data.get("description") and (not existing.description or SOURCE_PRIORITY.get(data.get("source", ""), 0) >= SOURCE_PRIORITY.get(existing.source, 0)):
                existing.description = data["description"]
            if tools and (not existing.tools or len(tools) > len(existing.tools or [])):
                existing.tools = tools
                tools_enriched += 1
            if data.get("repository") and not existing.repository:
                existing.repository = data["repository"]
            if data.get("homepage") and not existing.homepage:
                existing.homepage = data["homepage"]

            # Always update enrichment fields from higher-priority
            if SOURCE_PRIORITY.get(data.get("source", ""), 0) >= SOURCE_PRIORITY.get(existing.source, 0):
                existing.source = data.get("source", existing.source)

            existing.trust_tier = trust_tier
            existing.tools_count = max(tools_count, existing.tools_count)
            if data.get("auth_type"):
                existing.auth_type = data["auth_type"]
            if data.get("popularity_score"):
                existing.popularity_score = max(data["popularity_score"], existing.popularity_score)
            if data.get("categories"):
                existing.categories = data["categories"]
            if data.get("is_official"):
                existing.is_official = True
            if data.get("pulsemcp_id"):
                existing.pulsemcp_id = data["pulsemcp_id"]
            if data.get("glama_id"):
                existing.glama_id = data["glama_id"]
            if data.get("security_metadata"):
                merged_meta = {**(existing.security_metadata or {}), **data["security_metadata"]}
                existing.security_metadata = merged_meta

            existing.last_synced_at = datetime.now(timezone.utc)
            updated_count += 1
        else:
            entry = MCPServerCatalog(
                name=data.get("name", normalized),
                normalized_name=normalized,
                description=data.get("description", ""),
                tools=tools,
                repository=data.get("repository"),
                homepage=data.get("homepage"),
                source=data.get("source", "unknown"),
                trust_tier=trust_tier,
                auth_type=data.get("auth_type"),
                popularity_score=data.get("popularity_score", 0),
                tools_count=tools_count,
                categories=data.get("categories", []),
                is_official=data.get("is_official", False),
                pulsemcp_id=data.get("pulsemcp_id"),
                glama_id=data.get("glama_id"),
                security_metadata=data.get("security_metadata", {}),
                last_synced_at=datetime.now(timezone.utc),
            )
            db.add(entry)
            new_count += 1
            if tools_count > 0:
                tools_enriched += 1

    await db.commit()
    total_entries = sum(len(s) for s in all_servers_by_source.values())
    logger.info(
        f"MCP catalog sync: {new_count} new, {updated_count} updated, "
        f"{tools_enriched} tools-enriched from {sources_checked} source(s) "
        f"({total_entries} total entries)"
    )
    return {
        "new": new_count,
        "updated": updated_count,
        "sources_checked": sources_checked,
        "tools_enriched": tools_enriched,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _compute_popularity(visitors: int) -> int:
    """Convert raw visitor count to normalized 0-100 score (log scale).

    Roughly: 0 visitors = 0, 10 = 20, 100 = 40, 1000 = 60, 10000 = 80, 100000 = 100.
    """
    if visitors <= 0:
        return 0
    score = int(20 * math.log10(max(visitors, 1)))
    return min(score, 100)
