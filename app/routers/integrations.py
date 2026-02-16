"""API routes for traffic discovery and rule pack management.

Discovery-first approach: rules come from live traffic detection or manual
"Add MCP Server" input. No template catalog browsing.
"""

import asyncio
import logging
import re
from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.data.rule_packs import RULE_PACKS, get_rule_pack
from app.database import get_db
from app.dependencies import OptionalOrgIdDep
from app.models.audit_logs import AuditLog, AuditAction, AuditSeverity
from app.models.rules import Rule, RuleType, RuleAction
from app.services.traffic_discovery import (
    discover_traffic,
    check_coverage,
    generate_rule_from_command,
    generate_rules_for_server,
    parse_tool_name,
    _insights_to_dict,
    KNOWN_MCP_SERVERS,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/integrations", tags=["integrations"])


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class CreateRuleFromTrafficRequest(BaseModel):
    """Request to create a rule from discovered traffic."""
    command: str
    action: str = "allow"  # allow | deny | require_approval
    agent_id: Optional[UUID] = None
    pattern_mode: str = "prefix"  # prefix | exact | verb
    name: Optional[str] = None


class CreateRulesForServerRequest(BaseModel):
    """Request to create default rules for an MCP server."""
    server_name: str
    agent_id: Optional[UUID] = None


class DisableServerRulesRequest(BaseModel):
    """Request to disable all rules for a server."""
    server_name: str
    agent_id: Optional[UUID] = None


class ActivePackInfo(BaseModel):
    """Information about an active rule pack group."""
    pack_id: str | None
    display_name: str
    icon: str
    source_reference: str
    rule_count: int
    rules: list[dict]


# ---------------------------------------------------------------------------
# Traffic discovery endpoints (unchanged)
# ---------------------------------------------------------------------------

@router.get("/traffic/insights")
async def get_traffic_insights(
    db: AsyncSession = Depends(get_db),
    agent_id: Optional[UUID] = None,
    hours: int = Query(default=168, ge=1, le=720),
):
    """Discover MCP servers and tools from live audit traffic.

    Analyses recent evaluate requests, groups commands by detected service,
    checks rule coverage, and links to available rule packs.
    """
    try:
        from app.redis_client import redis_client
        redis = redis_client
    except Exception:
        redis = None

    insights = await discover_traffic(
        db,
        agent_id=str(agent_id) if agent_id else None,
        hours=hours,
        redis_client=redis,
    )
    return _insights_to_dict(insights)


@router.get("/traffic/coverage")
async def get_traffic_coverage(
    command: str = Query(..., min_length=1),
    db: AsyncSession = Depends(get_db),
    agent_id: Optional[UUID] = None,
):
    """Check if a specific command is covered by any active rule."""
    result = await check_coverage(
        db, command, agent_id=str(agent_id) if agent_id else None
    )
    # Also include the parsed tool name info
    parsed = parse_tool_name(command)
    result["parsed"] = {
        "server_key": parsed.server_key,
        "tool_name": parsed.tool_name,
        "display_name": parsed.display_name,
        "icon": parsed.icon,
        "source_type": parsed.source_type,
        "template_id": parsed.template_id,
    }
    return result


@router.post("/traffic/create-rule")
async def create_rule_from_traffic(
    request: CreateRuleFromTrafficRequest,
    db: AsyncSession = Depends(get_db),
    org_id: OptionalOrgIdDep = None,
):
    """Create a rule from a discovered command/tool name.

    Auto-generates pattern and name from the command.
    """
    if not request.command.strip():
        raise HTTPException(status_code=400, detail="command must not be empty")

    if request.action not in ("allow", "deny", "require_approval"):
        raise HTTPException(status_code=400, detail="action must be allow, deny, or require_approval")

    rule_def = generate_rule_from_command(
        command=request.command,
        action=request.action,
        pattern_mode=request.pattern_mode,
        name=request.name,
    )

    rule = Rule(
        name=rule_def["name"],
        description=rule_def["description"],
        rule_type=RuleType(rule_def["rule_type"]),
        action=RuleAction(rule_def["action"]),
        priority=rule_def["priority"],
        parameters=rule_def["parameters"],
        agent_id=request.agent_id,
        organization_id=org_id,
        is_active=True,
        source="traffic_discovery",
        source_reference=request.command,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)

    logger.info(f"Created rule from traffic: {rule.name} for command '{request.command}'")

    return {
        "id": str(rule.id),
        "name": rule.name,
        "rule_type": rule.rule_type.value if hasattr(rule.rule_type, "value") else rule.rule_type,
        "action": rule.action.value if hasattr(rule.action, "value") else rule.action,
        "priority": rule.priority,
        "parameters": rule.parameters,
    }


@router.post("/traffic/create-server-rules")
async def create_rules_for_server(
    request: CreateRulesForServerRequest,
    db: AsyncSession = Depends(get_db),
    org_id: OptionalOrgIdDep = None,
):
    """Create rules for an MCP server.

    For known servers with a curated rule pack, creates the full curated set.
    For unknown servers, creates 3 generic defaults (allow reads, approve writes, deny destructive).
    """
    if not request.server_name.strip():
        raise HTTPException(status_code=400, detail="server_name must not be empty")

    rule_defs = generate_rules_for_server(request.server_name)

    # Determine source based on whether curated pack was used
    sn = request.server_name.strip().lower().replace("-", "_")
    info = KNOWN_MCP_SERVERS.get(sn, {})
    template_id = info.get("template_id")
    pack = get_rule_pack(template_id) if template_id else None
    is_curated = pack is not None and pack.get("rules")

    source = "rule_pack" if is_curated else "traffic_discovery"
    source_ref = template_id if is_curated else f"mcp_server:{request.server_name}"

    created = []
    for rule_def in rule_defs:
        rule = Rule(
            name=rule_def["name"],
            description=rule_def.get("description", ""),
            rule_type=RuleType(rule_def["rule_type"]),
            action=RuleAction(rule_def["action"]),
            priority=rule_def.get("priority", 0),
            parameters=rule_def.get("parameters", {}),
            agent_id=request.agent_id,
            organization_id=org_id,
            is_active=True,
            source=source,
            source_reference=source_ref,
        )
        db.add(rule)
        created.append(rule)

    await db.commit()

    logger.info(f"Created {len(created)} rules for MCP server '{request.server_name}' (source={source})")

    return {
        "server_name": request.server_name,
        "rules_created": len(created),
        "source": source,
        "rules": [
            {
                "id": str(r.id),
                "name": r.name,
                "action": r.action.value if hasattr(r.action, "value") else r.action,
            }
            for r in created
        ],
    }


@router.get("/traffic/known-servers")
async def list_known_servers():
    """List all known MCP server names for autocomplete/validation."""
    servers = {}
    for key, info in KNOWN_MCP_SERVERS.items():
        display = info["display"]
        if display not in servers:
            servers[display] = {
                "display": display,
                "icon": info["icon"],
                "category": info["category"],
                "keys": [],
                "template_id": info.get("template_id"),
            }
        servers[display]["keys"].append(key)
    return list(servers.values())


# ---------------------------------------------------------------------------
# Active packs & disable endpoints (new)
# ---------------------------------------------------------------------------

@router.get("/active-packs")
async def get_active_packs(
    db: AsyncSession = Depends(get_db),
    agent_id: Optional[UUID] = None,
):
    """Get active rule groups by source_reference.

    Returns rule packs and traffic-discovered server rules that are currently active.
    """
    query = select(Rule).where(
        Rule.is_active == True,
        Rule.is_deleted == False,
        Rule.source.in_(["rule_pack", "traffic_discovery"]),
    )
    if agent_id:
        query = query.where(
            or_(Rule.agent_id == agent_id, Rule.agent_id.is_(None))
        )

    result = await db.execute(query)
    rules = result.scalars().all()

    # Group by source_reference
    groups: dict[str, dict] = {}
    for rule in rules:
        ref = rule.source_reference or "unknown"
        if ref not in groups:
            # Determine display info
            pack_id = None
            display_name = ref
            icon = "🔧"

            if rule.source == "rule_pack" and rule.source_reference:
                pack_id = rule.source_reference
                pack = get_rule_pack(pack_id)
                if pack:
                    display_name = pack["name"]
                    icon = pack["icon"]
            elif rule.source == "traffic_discovery" and ref.startswith("mcp_server:"):
                server_name = ref.replace("mcp_server:", "")
                sn = server_name.lower().replace("-", "_")
                info = KNOWN_MCP_SERVERS.get(sn, {})
                display_name = info.get("display", server_name.replace("_", " ").title())
                icon = info.get("icon", "🔧")

            groups[ref] = {
                "pack_id": pack_id,
                "display_name": display_name,
                "icon": icon,
                "source_reference": ref,
                "rule_count": 0,
                "rules": [],
            }

        groups[ref]["rule_count"] += 1
        groups[ref]["rules"].append({
            "id": str(rule.id),
            "name": rule.name,
            "rule_type": rule.rule_type.value if hasattr(rule.rule_type, "value") else rule.rule_type,
            "action": rule.action.value if hasattr(rule.action, "value") else rule.action,
            "priority": rule.priority,
        })

    return list(groups.values())


@router.post("/traffic/disable-server-rules")
async def disable_server_rules(
    request: DisableServerRulesRequest,
    db: AsyncSession = Depends(get_db),
):
    """Soft-delete all rules for a server name.

    Matches rules by source_reference (rule_pack ID, or mcp_server:<name>).
    """
    if not request.server_name.strip():
        raise HTTPException(status_code=400, detail="server_name must not be empty")

    sn = request.server_name.strip()

    # Build source_reference candidates
    # Could be a pack_id directly, or mcp_server:<name>
    refs = [sn, f"mcp_server:{sn}"]
    # Also try normalized form
    sn_normalized = sn.lower().replace("-", "_")
    if sn_normalized != sn:
        refs.extend([sn_normalized, f"mcp_server:{sn_normalized}"])

    query = select(Rule).where(
        Rule.is_deleted == False,
        Rule.source.in_(["rule_pack", "traffic_discovery"]),
        Rule.source_reference.in_(refs),
    )
    if request.agent_id:
        query = query.where(Rule.agent_id == request.agent_id)

    result = await db.execute(query)
    existing_rules = result.scalars().all()

    if not existing_rules:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No active rules found for server '{sn}'",
        )

    rules_deleted = 0
    now = datetime.utcnow()
    for rule in existing_rules:
        rule.is_active = False
        rule.is_deleted = True
        rule.deleted_at = now
        rules_deleted += 1

    audit_entry = AuditLog(
        action=AuditAction.RULE_DEACTIVATED,
        severity=AuditSeverity.INFO,
        agent_id=request.agent_id,
        message=f"Disabled server rules for '{sn}', soft-deleted {rules_deleted} rules",
        details={
            "server_name": sn,
            "rules_deleted": rules_deleted,
            "rule_ids": [str(rule.id) for rule in existing_rules],
        },
    )
    db.add(audit_entry)

    await db.commit()
    try:
        from app.services.event_publisher import publish_from_audit_log
        asyncio.ensure_future(publish_from_audit_log(audit_entry))
    except Exception:
        pass

    try:
        from app.redis_client import redis_client
        from app.services.rule_engine import RuleEngine
        engine = RuleEngine(db, redis_client)
        await engine.invalidate_cache(request.agent_id)
    except Exception as e:
        logger.warning(f"Failed to invalidate rule cache after disabling server rules: {e}")

    logger.info(f"Disabled server rules for '{sn}', soft-deleted {rules_deleted} rules")

    return {
        "server_name": sn,
        "rules_deleted": rules_deleted,
        "message": f"Disabled {rules_deleted} rules for {sn}",
    }
