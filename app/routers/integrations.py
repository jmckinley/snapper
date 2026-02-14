"""API routes for managing integration templates and traffic discovery."""

import logging
import re
from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.data.integration_templates import (
    INTEGRATION_TEMPLATES,
    INTEGRATION_CATEGORIES,
    get_templates_by_category,
    get_template,
)
from app.database import get_db
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

class IntegrationInfo(BaseModel):
    """Information about an integration."""
    id: str
    name: str
    description: str
    icon: str
    category: str
    mcp_matcher: str
    enabled: bool
    rule_count: int


class CategoryInfo(BaseModel):
    """Information about an integration category."""
    id: str
    name: str
    description: str
    icon: str
    integrations: list[IntegrationInfo]


class EnableIntegrationRequest(BaseModel):
    """Request to enable an integration."""
    agent_id: Optional[UUID] = None
    selected_rules: Optional[list[str]] = None
    custom_server_name: Optional[str] = None  # For custom_mcp template


class EnableIntegrationResponse(BaseModel):
    """Response after enabling an integration."""
    integration_id: str
    rules_created: int
    message: str


class DisableIntegrationResponse(BaseModel):
    """Response after disabling an integration."""
    integration_id: str
    rules_deleted: int
    message: str


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


# ---------------------------------------------------------------------------
# Traffic discovery endpoints
# ---------------------------------------------------------------------------

@router.get("/traffic/insights")
async def get_traffic_insights(
    db: AsyncSession = Depends(get_db),
    agent_id: Optional[UUID] = None,
    hours: int = Query(default=168, ge=1, le=720),
):
    """Discover MCP servers and tools from live audit traffic.

    Analyses recent evaluate requests, groups commands by detected service,
    checks rule coverage, and links to available templates.
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
):
    """Create smart default rules for an MCP server (allow reads, approve writes, deny destructive).

    Works for any server name — known or unknown.
    """
    if not request.server_name.strip():
        raise HTTPException(status_code=400, detail="server_name must not be empty")

    rule_defs = generate_rules_for_server(request.server_name)
    created = []

    for rule_def in rule_defs:
        rule = Rule(
            name=rule_def["name"],
            description=rule_def["description"],
            rule_type=RuleType(rule_def["rule_type"]),
            action=RuleAction(rule_def["action"]),
            priority=rule_def["priority"],
            parameters=rule_def["parameters"],
            agent_id=request.agent_id,
            is_active=True,
            source="traffic_discovery",
            source_reference=f"mcp_server:{request.server_name}",
        )
        db.add(rule)
        created.append(rule)

    await db.commit()

    logger.info(f"Created {len(created)} rules for MCP server '{request.server_name}'")

    return {
        "server_name": request.server_name,
        "rules_created": len(created),
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
# Template list / detail endpoints
# ---------------------------------------------------------------------------

@router.get("", response_model=list[CategoryInfo])
async def list_integrations(
    db: AsyncSession = Depends(get_db),
    agent_id: Optional[UUID] = None,
):
    """List all available integration templates organized by category.

    Shows which integrations are enabled (have rules created).
    """
    query = select(Rule).where(Rule.is_active == True, Rule.is_deleted == False)
    if agent_id:
        query = query.where(Rule.agent_id == agent_id)

    result = await db.execute(query)
    existing_rules = result.scalars().all()

    enabled_integrations = set()
    integration_rule_counts = {}

    for rule in existing_rules:
        for template_id, template in INTEGRATION_TEMPLATES.items():
            matched = False
            if rule.source == "integration" and rule.source_reference == template_id:
                matched = True
            elif rule.name.startswith(f"{template['name']} -"):
                matched = True
            if matched:
                enabled_integrations.add(template_id)
                integration_rule_counts[template_id] = integration_rule_counts.get(template_id, 0) + 1

    categories = []
    for category_id, category_info in INTEGRATION_CATEGORIES.items():
        integrations = []
        for template_id, template in INTEGRATION_TEMPLATES.items():
            if template.get("category") == category_id:
                integrations.append(IntegrationInfo(
                    id=template_id,
                    name=template["name"],
                    description=template["description"],
                    icon=template["icon"],
                    category=category_id,
                    mcp_matcher=template["mcp_matcher"],
                    enabled=template_id in enabled_integrations,
                    rule_count=integration_rule_counts.get(template_id, 0),
                ))

        if integrations:
            categories.append(CategoryInfo(
                id=category_id,
                name=category_info["name"],
                description=category_info["description"],
                icon=category_info["icon"],
                integrations=integrations,
            ))

    return categories


@router.get("/categories/summary")
async def get_categories_summary():
    """Get a summary of integration categories."""
    summary = []
    for category_id, category_info in INTEGRATION_CATEGORIES.items():
        count = sum(
            1 for t in INTEGRATION_TEMPLATES.values()
            if t.get("category") == category_id
        )
        summary.append({
            "id": category_id,
            **category_info,
            "integration_count": count,
        })
    return summary



@router.get("/{integration_id}")
async def get_integration(
    integration_id: str,
    db: AsyncSession = Depends(get_db),
    agent_id: Optional[UUID] = None,
):
    """Get details about a specific integration template."""
    template = get_template(integration_id)
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Integration '{integration_id}' not found",
        )

    query = select(Rule).where(
        Rule.is_active == True,
        Rule.is_deleted == False,
        or_(
            Rule.name.like(f"{template['name']} -%"),
            (Rule.source == "integration") & (Rule.source_reference == integration_id),
        ),
    )
    if agent_id:
        query = query.where(Rule.agent_id == agent_id)

    result = await db.execute(query)
    existing_rules = result.scalars().all()

    existing_rule_names = {rule.name for rule in existing_rules}

    enriched_rules = []
    for rule_def in template.get("rules", []):
        enriched_rules.append({
            **rule_def,
            "enabled": rule_def["name"] in existing_rule_names,
            "default_enabled": rule_def.get("default_enabled", True),
        })

    return {
        "id": integration_id,
        "name": template["name"],
        "description": template["description"],
        "icon": template["icon"],
        "category": template.get("category", ""),
        "mcp_matcher": template.get("mcp_matcher", ""),
        "selectable_rules": template.get("selectable_rules", False),
        "custom": template.get("custom", False),
        "enabled": len(existing_rules) > 0,
        "rule_count": len(existing_rules),
        "rules": enriched_rules,
        "existing_rules": [
            {
                "id": str(rule.id),
                "name": rule.name,
                "rule_type": rule.rule_type.value if hasattr(rule.rule_type, 'value') else rule.rule_type,
                "action": rule.action.value if hasattr(rule.action, 'value') else rule.action,
                "description": rule.description or "",
                "priority": rule.priority,
                "parameters": rule.parameters or {},
            }
            for rule in existing_rules
        ],
    }


@router.post("/{integration_id}/enable", response_model=EnableIntegrationResponse)
async def enable_integration(
    integration_id: str,
    request: EnableIntegrationRequest,
    db: AsyncSession = Depends(get_db),
):
    """Enable an integration by creating its default rules.

    For custom_mcp, generates rules dynamically from custom_server_name.
    """
    template = get_template(integration_id)
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Integration '{integration_id}' not found",
        )

    # Handle custom MCP server
    if template.get("custom"):
        if not request.custom_server_name or not request.custom_server_name.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="custom_server_name is required for custom MCP integration",
            )

        server_name = request.custom_server_name.strip()
        rule_defs = generate_rules_for_server(server_name)
        rules_created = 0

        for rule_def in rule_defs:
            rule = Rule(
                name=rule_def["name"],
                description=rule_def.get("description", ""),
                rule_type=RuleType(rule_def["rule_type"]),
                action=RuleAction(rule_def["action"]),
                priority=rule_def.get("priority", 0),
                parameters=rule_def.get("parameters", {}),
                agent_id=request.agent_id,
                is_active=True,
                source="integration",
                source_reference=f"custom_mcp:{server_name}",
            )
            db.add(rule)
            rules_created += 1

        await db.commit()
        logger.info(f"Enabled custom MCP '{server_name}' with {rules_created} rules")

        return EnableIntegrationResponse(
            integration_id=integration_id,
            rules_created=rules_created,
            message=f"Created {rules_created} rules for MCP server '{server_name}'",
        )

    # Standard template enable
    query = select(Rule).where(
        Rule.is_active == True,
        or_(
            Rule.name.like(f"{template['name']} -%"),
            (Rule.source == "integration") & (Rule.source_reference == integration_id),
        ),
    )
    if request.agent_id:
        query = query.where(Rule.agent_id == request.agent_id)
    else:
        query = query.where(Rule.agent_id.is_(None))

    result = await db.execute(query)
    existing_rules = result.scalars().all()

    if existing_rules:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Integration '{integration_id}' is already enabled with {len(existing_rules)} rules",
        )

    rules_created = 0
    selectable = template.get("selectable_rules", False)

    for rule_def in template.get("rules", []):
        rule_id = rule_def.get("id")

        if selectable and request.selected_rules is not None:
            if rule_id not in request.selected_rules:
                continue
        elif selectable and request.selected_rules is None:
            if not rule_def.get("default_enabled", True):
                continue

        rule_type = RuleType(rule_def["rule_type"])
        action = RuleAction(rule_def["action"])

        rule = Rule(
            name=rule_def["name"],
            description=rule_def.get("description", ""),
            rule_type=rule_type,
            action=action,
            priority=rule_def.get("priority", 0),
            parameters=rule_def.get("parameters", {}),
            agent_id=request.agent_id,
            is_active=True,
            source="integration",
            source_reference=integration_id,
        )
        db.add(rule)
        rules_created += 1

    await db.commit()

    logger.info(f"Enabled integration '{integration_id}' with {rules_created} rules")

    return EnableIntegrationResponse(
        integration_id=integration_id,
        rules_created=rules_created,
        message=f"Successfully enabled {template['name']} with {rules_created} security rules",
    )


@router.post("/{integration_id}/disable", response_model=DisableIntegrationResponse)
async def disable_integration(
    integration_id: str,
    db: AsyncSession = Depends(get_db),
    agent_id: Optional[UUID] = None,
):
    """Disable an integration by soft-deleting its rules."""
    template = get_template(integration_id)

    # Build query — if template exists, match by name prefix too
    conditions = [(Rule.source == "integration") & (Rule.source_reference == integration_id)]
    if template:
        conditions.append(Rule.name.like(f"{template['name']} -%"))
    # Also match custom_mcp:* source_reference for custom server rules
    conditions.append(
        (Rule.source == "integration") & (Rule.source_reference.like(f"custom_mcp:{integration_id}"))
    )

    query = select(Rule).where(
        Rule.is_deleted == False,
        or_(*conditions),
    )
    if agent_id:
        query = query.where(Rule.agent_id == agent_id)
    else:
        query = query.where(Rule.agent_id.is_(None))

    result = await db.execute(query)
    existing_rules = result.scalars().all()

    if not existing_rules:
        if not template:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Integration '{integration_id}' not found and no matching rules exist",
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Integration '{integration_id}' is not enabled",
        )

    rules_deleted = 0
    now = datetime.utcnow()
    for rule in existing_rules:
        rule.is_active = False
        rule.is_deleted = True
        rule.deleted_at = now
        rules_deleted += 1

    template_name = template["name"] if template else integration_id
    audit_entry = AuditLog(
        action=AuditAction.RULE_DEACTIVATED,
        severity=AuditSeverity.INFO,
        agent_id=agent_id,
        message=f"Disabled integration '{integration_id}' ({template_name}), soft-deleted {rules_deleted} rules",
        details={
            "integration_id": integration_id,
            "integration_name": template_name,
            "rules_deleted": rules_deleted,
            "rule_ids": [str(rule.id) for rule in existing_rules],
        },
    )
    db.add(audit_entry)

    await db.commit()

    try:
        from app.redis_client import redis_client
        from app.services.rule_engine import RuleEngine
        engine = RuleEngine(db, redis_client)
        await engine.invalidate_cache(agent_id)
    except Exception as e:
        logger.warning(f"Failed to invalidate rule cache after disabling integration: {e}")

    logger.info(f"Disabled integration '{integration_id}', soft-deleted {rules_deleted} rules")

    return DisableIntegrationResponse(
        integration_id=integration_id,
        rules_deleted=rules_deleted,
        message=f"Successfully disabled {template_name}, removed {rules_deleted} rules",
    )
