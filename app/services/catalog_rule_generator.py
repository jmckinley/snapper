"""Catalog Rule Generator — tailored rules from MCP catalog tool definitions.

Instead of generic verb-guessing rules, generates rules that reference
the server's **actual tool names** from the catalog. Falls back gracefully
when no catalog data is available.
"""

import logging
import re
from typing import Optional

from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.mcp_catalog import MCPServerCatalog
from app.services.tool_classifier import classify_tools

logger = logging.getLogger(__name__)


async def generate_rules_from_catalog(
    db: AsyncSession,
    server_name: str,
) -> Optional[list[dict]]:
    """Generate tailored rules from catalog tool definitions.

    1. Look up server in mcp_server_catalog by normalized name
    2. If no tools data → return None (caller falls back to generic)
    3. Classify all tools into read/write/delete categories
    4. Generate rules with exact tool name patterns
    5. Add a catch-all require_approval for unknown tools

    Returns None if no catalog data available (caller should fall back).
    """
    if not server_name or not server_name.strip():
        return None

    sn = server_name.strip().lower().replace(" ", "-")
    sn_underscore = sn.replace("-", "_")

    # Look up in catalog — exact match first, then partial
    server = (
        await db.execute(
            select(MCPServerCatalog).where(
                or_(
                    MCPServerCatalog.normalized_name == sn,
                    MCPServerCatalog.normalized_name == sn_underscore,
                )
            )
        )
    ).scalar_one_or_none()

    if not server:
        # Try LIKE partial match
        result = await db.execute(
            select(MCPServerCatalog)
            .where(MCPServerCatalog.normalized_name.ilike(f"%{sn}%"))
            .order_by(MCPServerCatalog.popularity_score.desc())
            .limit(1)
        )
        server = result.scalar_one_or_none()

    if not server or not server.tools:
        return None

    # Classify tools
    classified = classify_tools(server.tools)
    if not classified:
        return None

    # Group by category
    read_tools = [t.name for t in classified if t.category == "read"]
    write_tools = [t.name for t in classified if t.category == "write"]
    delete_tools = [t.name for t in classified if t.category == "delete"]
    unknown_tools = [t.name for t in classified if t.category == "unknown"]

    display = server.name or sn.replace("-", " ").title()
    trust_label = f" [{server.trust_tier}]" if server.trust_tier != "unknown" else ""
    auth_label = f" (auth: {server.auth_type})" if server.auth_type else ""

    rules = []

    # Rule 1: Allow read operations (exact tool names)
    if read_tools:
        tool_pattern = _build_tool_pattern(sn_underscore, sn, read_tools)
        rules.append({
            "id": f"{sn_underscore}-catalog-allow-reads",
            "name": f"{display} - Allow Read Operations (catalog)",
            "description": f"Allow read-only tools for {display}{trust_label}{auth_label}. "
                           f"Tools: {', '.join(read_tools[:10])}{'...' if len(read_tools) > 10 else ''}",
            "rule_type": "command_allowlist",
            "action": "allow",
            "priority": 100,
            "parameters": {"patterns": [tool_pattern]},
        })

    # Rule 2: Approve write operations (exact tool names)
    if write_tools:
        tool_pattern = _build_tool_pattern(sn_underscore, sn, write_tools)
        rules.append({
            "id": f"{sn_underscore}-catalog-approve-writes",
            "name": f"{display} - Approve Write Operations (catalog)",
            "description": f"Require approval for write tools on {display}{trust_label}{auth_label}. "
                           f"Tools: {', '.join(write_tools[:10])}{'...' if len(write_tools) > 10 else ''}",
            "rule_type": "command_allowlist",
            "action": "require_approval",
            "priority": 90,
            "parameters": {"patterns": [tool_pattern]},
        })

    # Rule 3: Deny destructive operations (exact tool names)
    if delete_tools:
        tool_pattern = _build_tool_pattern(sn_underscore, sn, delete_tools)
        rules.append({
            "id": f"{sn_underscore}-catalog-deny-destructive",
            "name": f"{display} - Block Destructive Operations (catalog)",
            "description": f"Block destructive tools on {display}{trust_label}{auth_label}. "
                           f"Tools: {', '.join(delete_tools[:10])}{'...' if len(delete_tools) > 10 else ''}",
            "rule_type": "command_denylist",
            "action": "deny",
            "priority": 200,
            "parameters": {"patterns": [tool_pattern]},
        })

    # Rule 4: Catch-all require_approval for any unclassified or future tools
    all_known_names = read_tools + write_tools + delete_tools + unknown_tools
    if all_known_names:
        # Match anything from this server NOT in the known tools
        known_escaped = "|".join(re.escape(t) for t in all_known_names)
        catchall_pattern = (
            f"^mcp__(?:{re.escape(sn_underscore)}|{re.escape(sn)})__"
            f"(?!(?:{known_escaped})$).+"
        )
        rules.append({
            "id": f"{sn_underscore}-catalog-catchall",
            "name": f"{display} - Approve Unknown Tools (catalog)",
            "description": f"Require approval for any {display} tools not in the catalog. "
                           f"Safety net for tools added after last sync.",
            "rule_type": "command_allowlist",
            "action": "require_approval",
            "priority": 80,
            "parameters": {"patterns": [catchall_pattern]},
        })

    # If unknown tools exist, add them to the write-approval bucket
    if unknown_tools and not write_tools:
        # No writes classified but we have unknowns — treat as writes
        tool_pattern = _build_tool_pattern(sn_underscore, sn, unknown_tools)
        rules.append({
            "id": f"{sn_underscore}-catalog-approve-unknown",
            "name": f"{display} - Approve Unclassified Tools (catalog)",
            "description": f"Require approval for unclassified tools on {display}",
            "rule_type": "command_allowlist",
            "action": "require_approval",
            "priority": 85,
            "parameters": {"patterns": [tool_pattern]},
        })
    elif unknown_tools:
        # Add unknowns to existing write pattern
        all_write_pattern = _build_tool_pattern(sn_underscore, sn, write_tools + unknown_tools)
        # Update the write rule pattern
        for rule in rules:
            if rule["id"] == f"{sn_underscore}-catalog-approve-writes":
                rule["parameters"]["patterns"] = [all_write_pattern]
                break

    if not rules:
        return None

    return rules


def _build_tool_pattern(sn_underscore: str, sn_hyphen: str, tool_names: list[str]) -> str:
    """Build a regex pattern matching specific tool names for an MCP server.

    Matches both:
      - mcp__server__tool_name  (Claude-style)
      - server_tool_name        (OpenClaw-style)
    """
    escaped = "|".join(re.escape(t) for t in tool_names)
    return (
        f"^(?:mcp__(?:{re.escape(sn_underscore)}|{re.escape(sn_hyphen)})__"
        f"|{re.escape(sn_underscore)}_)"
        f"(?:{escaped})$"
    )
