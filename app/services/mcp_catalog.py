"""MCP Server Catalog: auto-profile servers from public registries.

Fetches server listings from public MCP registries (Smithery, NPM,
awesome-mcp-servers) and merges tool/capability metadata into Snapper's
known-server registry for auto-generated rule packs.

Designed to run as a daily Celery task. Network failures are tolerated
gracefully — the catalog is additive and stale data is harmless.
"""

import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

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

# Timeout for external fetches
FETCH_TIMEOUT = 15.0


async def fetch_smithery_servers(limit: int = 200) -> List[Dict[str, Any]]:
    """Fetch server listings from the Smithery registry.

    Returns a list of dicts with keys:
      name, description, tools, repository, homepage
    """
    results: List[Dict[str, Any]] = []
    try:
        async with httpx.AsyncClient(timeout=FETCH_TIMEOUT) as client:
            resp = await client.get(SMITHERY_API, params={"limit": limit})
            if resp.status_code != 200:
                logger.debug(f"Smithery returned {resp.status_code}")
                return results

            data = resp.json()
            servers = data if isinstance(data, list) else data.get("servers", data.get("results", []))

            for srv in servers:
                if not isinstance(srv, dict):
                    continue
                results.append({
                    "name": srv.get("qualifiedName") or srv.get("name", "unknown"),
                    "description": (srv.get("description") or "")[:500],
                    "tools": srv.get("tools", []),
                    "repository": srv.get("repository", {}).get("url") if isinstance(srv.get("repository"), dict) else srv.get("repository"),
                    "homepage": srv.get("homepage"),
                    "source": "smithery",
                })
    except Exception as e:
        logger.debug(f"Smithery fetch failed: {e}")
    return results


async def fetch_npm_mcp_packages(limit: int = 100) -> List[Dict[str, Any]]:
    """Search NPM for MCP server packages.

    Searches for packages with ``@modelcontextprotocol/`` scope or
    ``mcp-server`` in name/keywords.
    """
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
    """Parse the awesome-mcp-servers README for server names.

    This is a best-effort heuristic parse — the README uses Markdown
    tables/lists with links to repos.
    """
    results: List[Dict[str, Any]] = []
    try:
        async with httpx.AsyncClient(timeout=FETCH_TIMEOUT) as client:
            resp = await client.get(AWESOME_MCP_RAW)
            if resp.status_code != 200:
                return results

            text = resp.text
            # Match markdown links: [name](url)
            pattern = re.compile(r"\[([^\]]+)\]\((https://github\.com/[^\)]+)\)")
            seen = set()

            for match in pattern.finditer(text):
                name = match.group(1).strip()
                url = match.group(2).strip()

                # Deduplicate
                if url in seen:
                    continue
                seen.add(url)

                # Skip non-server entries (categories, badges, etc.)
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


async def sync_catalog(db) -> Dict[str, int]:
    """Fetch from all registries and upsert into mcp_server_catalog.

    Returns counts: {"new": N, "updated": N, "sources_checked": N}
    """
    from app.models.mcp_catalog import MCPServerCatalog
    from sqlalchemy import select

    all_servers: List[Dict[str, Any]] = []

    # Fetch from all sources in parallel
    import asyncio
    results = await asyncio.gather(
        fetch_smithery_servers(),
        fetch_npm_mcp_packages(),
        fetch_awesome_mcp_servers(),
        return_exceptions=True,
    )

    sources_checked = 0
    for result in results:
        if isinstance(result, list):
            all_servers.extend(result)
            sources_checked += 1
        elif isinstance(result, Exception):
            logger.warning(f"Catalog source failed: {result}")

    new_count = 0
    updated_count = 0

    for srv in all_servers:
        name = srv.get("name", "").strip()
        if not name:
            continue

        # Normalize name for dedup
        normalized = name.lower().replace(" ", "-")

        existing = (
            await db.execute(
                select(MCPServerCatalog).where(
                    MCPServerCatalog.normalized_name == normalized
                )
            )
        ).scalar_one_or_none()

        if existing:
            # Update if we have more data
            if srv.get("description") and not existing.description:
                existing.description = srv["description"]
            if srv.get("tools") and not existing.tools:
                existing.tools = srv["tools"]
            if srv.get("repository") and not existing.repository:
                existing.repository = srv["repository"]
            existing.last_synced_at = datetime.now(timezone.utc)
            updated_count += 1
        else:
            entry = MCPServerCatalog(
                name=name,
                normalized_name=normalized,
                description=srv.get("description", ""),
                tools=srv.get("tools", []),
                repository=srv.get("repository"),
                homepage=srv.get("homepage"),
                source=srv.get("source", "unknown"),
                last_synced_at=datetime.now(timezone.utc),
            )
            db.add(entry)
            new_count += 1

    await db.commit()
    logger.info(
        f"MCP catalog sync: {new_count} new, {updated_count} updated "
        f"from {sources_checked} source(s) ({len(all_servers)} total entries)"
    )
    return {"new": new_count, "updated": updated_count, "sources_checked": sources_checked}
