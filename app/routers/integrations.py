"""API routes for managing integration templates."""

import logging
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.data.integration_templates import (
    INTEGRATION_TEMPLATES,
    INTEGRATION_CATEGORIES,
    get_templates_by_category,
    get_template,
)
from app.database import get_db
from app.models.rules import Rule, RuleType, RuleAction

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/integrations", tags=["integrations"])


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
    agent_id: Optional[UUID] = None  # None for global rules
    selected_rules: Optional[list[str]] = None  # Rule IDs to enable (None = all defaults)


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


@router.get("", response_model=list[CategoryInfo])
async def list_integrations(
    db: AsyncSession = Depends(get_db),
    agent_id: Optional[UUID] = None,
):
    """List all available integration templates organized by category.

    Shows which integrations are enabled (have rules created).
    """
    # Get all rules to check which integrations are enabled
    query = select(Rule).where(Rule.is_active == True)
    if agent_id:
        query = query.where(Rule.agent_id == agent_id)

    result = await db.execute(query)
    existing_rules = result.scalars().all()

    # Build a set of enabled integration IDs based on rule names
    enabled_integrations = set()
    integration_rule_counts = {}

    for rule in existing_rules:
        for template_id, template in INTEGRATION_TEMPLATES.items():
            # Check if rule name matches any template rule name prefix
            template_prefix = f"{template['name']} -"
            if rule.name.startswith(template_prefix):
                enabled_integrations.add(template_id)
                integration_rule_counts[template_id] = integration_rule_counts.get(template_id, 0) + 1

    # Build response by category
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

    # Check if enabled
    query = select(Rule).where(
        Rule.is_active == True,
        Rule.name.like(f"{template['name']} -%"),
    )
    if agent_id:
        query = query.where(Rule.agent_id == agent_id)

    result = await db.execute(query)
    existing_rules = result.scalars().all()

    # Build existing rule name set for matching
    existing_rule_names = {rule.name for rule in existing_rules}

    # Enrich rules with enabled status
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
        "enabled": len(existing_rules) > 0,
        "rule_count": len(existing_rules),
        "rules": enriched_rules,
        "existing_rules": [
            {
                "id": str(rule.id),
                "name": rule.name,
                "rule_type": rule.rule_type.value if hasattr(rule.rule_type, 'value') else rule.rule_type,
                "action": rule.action.value if hasattr(rule.action, 'value') else rule.action,
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

    Creates all the rules defined in the integration template.
    """
    template = get_template(integration_id)
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Integration '{integration_id}' not found",
        )

    # Check if already enabled
    query = select(Rule).where(
        Rule.is_active == True,
        Rule.name.like(f"{template['name']} -%"),
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

    # Create rules from template
    rules_created = 0
    selectable = template.get("selectable_rules", False)

    for rule_def in template.get("rules", []):
        rule_id = rule_def.get("id")

        # If selectable rules, check if this rule should be enabled
        if selectable and request.selected_rules is not None:
            # Only enable explicitly selected rules
            if rule_id not in request.selected_rules:
                continue
        elif selectable and request.selected_rules is None:
            # Use defaults if no selection provided
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
    """Disable an integration by removing its rules.

    Deletes all rules that were created for this integration.
    """
    template = get_template(integration_id)
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Integration '{integration_id}' not found",
        )

    # Find existing rules for this integration
    query = select(Rule).where(
        Rule.name.like(f"{template['name']} -%"),
    )
    if agent_id:
        query = query.where(Rule.agent_id == agent_id)
    else:
        query = query.where(Rule.agent_id.is_(None))

    result = await db.execute(query)
    existing_rules = result.scalars().all()

    if not existing_rules:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Integration '{integration_id}' is not enabled",
        )

    # Delete the rules
    rules_deleted = 0
    for rule in existing_rules:
        await db.delete(rule)
        rules_deleted += 1

    await db.commit()

    logger.info(f"Disabled integration '{integration_id}', removed {rules_deleted} rules")

    return DisableIntegrationResponse(
        integration_id=integration_id,
        rules_deleted=rules_deleted,
        message=f"Successfully disabled {template['name']}, removed {rules_deleted} rules",
    )


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
