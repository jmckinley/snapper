"""Rule management API endpoints."""

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

import yaml
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import DbSessionDep, OptionalOrgIdDep, RedisDep, default_rate_limit
from app.models.audit_logs import AuditAction, AuditLog, AuditSeverity, PolicyViolation
from app.services.event_publisher import publish_from_audit_log
from app.services.quota import QuotaChecker
from app.models.rules import Rule, RuleAction, RuleType, RULE_PARAMETER_SCHEMAS
from app.schemas.rules import (
    ApplyTemplateRequest,
    RuleCreate,
    RuleExportRequest,
    RuleExportResponse,
    RuleImportRequest,
    RuleImportResponse,
    RuleListResponse,
    RuleResponse,
    RuleTemplateResponse,
    RuleUpdate,
    RuleValidateRequest,
    RuleValidateResponse,
)
from app.services.rule_engine import EvaluationContext, RuleEngine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/rules", dependencies=[Depends(default_rate_limit)])

# Pre-built rule templates.
# These templates cover agents/tools not in the Integrations page.
# For service-specific rule packs (Gmail, GitHub, Slack, AWS, etc.),
# see app/data/rule_packs.py.
RULE_TEMPLATES = {
    "cve-2026-25253-mitigation": {
        "id": "cve-2026-25253-mitigation",
        "name": "CVE-2026-25253 Mitigation",
        "description": "Mitigate WebSocket RCE vulnerability by validating origin headers",
        "category": "cve",
        "severity": "critical",
        "rule_type": RuleType.ORIGIN_VALIDATION,
        "default_action": RuleAction.DENY,
        "default_parameters": {
            "allowed_origins": ["http://localhost:8000", "http://127.0.0.1:8000"],
            "strict_mode": False,  # False: allow requests without Origin (hooks/CLI); deny invalid origins
        },
        "tags": ["cve", "websocket", "critical"],
        "is_recommended": True,
    },
    "malicious-skill-blocker": {
        "id": "malicious-skill-blocker",
        "name": "Malicious Skill Blocker",
        "description": "Block known malicious ClawHub skills and auto-block flagged ones",
        "category": "skill",
        "severity": "critical",
        "rule_type": RuleType.SKILL_DENYLIST,
        "default_action": RuleAction.DENY,
        "default_parameters": {
            "skills": [],  # Will be populated from database
            "auto_block_flagged": True,
        },
        "tags": ["clawhub", "malware", "critical"],
        "is_recommended": True,
    },
    "credential-protection": {
        "id": "credential-protection",
        "name": "Credential Protection",
        "description": "Prevent access to sensitive credential files",
        "category": "security",
        "severity": "high",
        "rule_type": RuleType.CREDENTIAL_PROTECTION,
        "default_action": RuleAction.DENY,
        "default_parameters": {
            "protected_patterns": [
                r"\.env$",
                r"\.pem$",
                r"\.key$",
                r"credentials\.json$",
                r"secrets\.ya?ml$",
                r"\.aws/credentials",
                r"\.ssh/",
                r"\.gnupg/",
            ],
            "block_plaintext_secrets": True,
        },
        "tags": ["credentials", "secrets", "high"],
        "is_recommended": True,
    },
    "localhost-only": {
        "id": "localhost-only",
        "name": "Localhost Only Access",
        "description": "Restrict access to localhost connections only",
        "category": "security",
        "severity": "high",
        "rule_type": RuleType.LOCALHOST_RESTRICTION,
        "default_action": RuleAction.DENY,
        "default_parameters": {
            "enabled": True,
            "allowed_ips": ["127.0.0.1", "::1"],
        },
        "tags": ["localhost", "access-control", "high"],
        "is_recommended": True,
    },
    "rate-limit-standard": {
        "id": "rate-limit-standard",
        "name": "Standard Rate Limit",
        "description": "Standard rate limiting to prevent abuse",
        "category": "rate-limiting",
        "severity": "medium",
        "rule_type": RuleType.RATE_LIMIT,
        "default_action": RuleAction.DENY,
        "default_parameters": {
            "max_requests": 100,
            "window_seconds": 60,
            "scope": "agent",
        },
        "tags": ["rate-limit", "abuse-prevention"],
        "is_recommended": True,
    },
    "business-hours-only": {
        "id": "business-hours-only",
        "name": "Business Hours Only",
        "description": "Restrict agent operations to business hours",
        "category": "time",
        "severity": "low",
        "rule_type": RuleType.TIME_RESTRICTION,
        "default_action": RuleAction.ALLOW,
        "default_parameters": {
            "allowed_hours": {"start": 9, "end": 17},
            "allowed_days": [0, 1, 2, 3, 4],  # Monday-Friday
            "timezone": "UTC",
        },
        "tags": ["time-restriction", "business-hours"],
        "is_recommended": False,
    },
    "human-approval-sensitive": {
        "id": "human-approval-sensitive",
        "name": "Human Approval for Sensitive Operations",
        "description": "Require human approval for sensitive operations",
        "category": "approval",
        "severity": "medium",
        "rule_type": RuleType.HUMAN_IN_LOOP,
        "default_action": RuleAction.REQUIRE_APPROVAL,
        "default_parameters": {
            "require_approval_for": ["file_write", "network", "credential_access"],
            "timeout_seconds": 300,
            "auto_deny_on_timeout": True,
        },
        "tags": ["approval", "human-in-loop"],
        "is_recommended": False,
    },
    # =========================================================================
    # ALLOW RULES - Explicitly permit specific actions
    # =========================================================================
    "command-allowlist-safe": {
        "id": "command-allowlist-safe",
        "name": "Safe Commands Allowlist",
        "description": "Explicitly allow common safe commands (git, npm, python, etc.)",
        "category": "allowlist",
        "severity": "low",
        "rule_type": RuleType.COMMAND_ALLOWLIST,
        "default_action": RuleAction.ALLOW,
        "default_parameters": {
            "patterns": [
                r"^git\s+(status|log|diff|branch|show|ls-files)",
                r"^npm\s+(list|ls|outdated|audit)",
                r"^python\s+--version",
                r"^python\s+-c\s+['\"]print",
                r"^node\s+--version",
                r"^ls\s",
                r"^pwd$",
                r"^whoami$",
                r"^date$",
                r"^echo\s",
                r"^cat\s+[^|;&]*$",  # cat without pipes or command chaining
                r"^head\s",
                r"^tail\s",
                r"^wc\s",
                r"^grep\s+[^|;&]*$",  # grep without pipes
            ],
        },
        "tags": ["allowlist", "commands", "safe"],
        "is_recommended": False,
    },
    "command-allowlist-dev": {
        "id": "command-allowlist-dev",
        "name": "Development Commands Allowlist",
        "description": "Allow common development commands (build, test, lint)",
        "category": "allowlist",
        "severity": "low",
        "rule_type": RuleType.COMMAND_ALLOWLIST,
        "default_action": RuleAction.ALLOW,
        "default_parameters": {
            "patterns": [
                r"^npm\s+(run|test|build|start|install)",
                r"^yarn\s+(run|test|build|start|install|add)",
                r"^pnpm\s+(run|test|build|start|install|add)",
                r"^python\s+(-m\s+)?(pytest|unittest|pip)",
                r"^pip\s+(install|list|freeze|show)",
                r"^poetry\s+(install|add|show|run)",
                r"^cargo\s+(build|test|run|check)",
                r"^go\s+(build|test|run|mod)",
                r"^make\s+",
                r"^docker\s+(ps|images|logs)",
                r"^docker-compose\s+(ps|logs)",
            ],
        },
        "tags": ["allowlist", "commands", "development"],
        "is_recommended": False,
    },
    "file-allowlist-project": {
        "id": "file-allowlist-project",
        "name": "Project Files Allowlist",
        "description": "Allow access to common project files (code, configs, docs)",
        "category": "allowlist",
        "severity": "low",
        "rule_type": RuleType.FILE_ACCESS,
        "default_action": RuleAction.ALLOW,
        "default_parameters": {
            "allowed_paths": [
                r".*\.(js|ts|jsx|tsx|py|rb|go|rs|java|kt|swift|c|cpp|h)$",
                r".*\.(json|yaml|yml|toml|ini|cfg)$",
                r".*\.(md|txt|rst|html|css|scss)$",
                r".*(README|LICENSE|CHANGELOG|CONTRIBUTING).*",
                r".*package\.json$",
                r".*tsconfig\.json$",
                r".*pyproject\.toml$",
                r".*Cargo\.toml$",
                r".*go\.mod$",
                r".*/src/.*",
                r".*/lib/.*",
                r".*/app/.*",
                r".*/components/.*",
                r".*/tests/.*",
                r".*/docs/.*",
            ],
        },
        "tags": ["allowlist", "files", "project"],
        "is_recommended": False,
    },
    # =========================================================================
    # MCP SERVER / INTEGRATION TEMPLATES
    # (Service-specific rule packs for Gmail, GitHub, Slack, AWS, etc. are
    #  in app/data/rule_packs.py — only non-overlapping templates remain here.)
    # =========================================================================
    "brave-search-protection": {
        "id": "brave-search-protection",
        "name": "Brave Search Protection",
        "description": "Security rules for Brave Search MCP server - controls web search operations",
        "category": "mcp-integration",
        "severity": "low",
        "rule_type": RuleType.RATE_LIMIT,
        "default_action": RuleAction.DENY,
        "default_parameters": {
            "integration": "brave-search",
            "max_requests": 100,
            "window_seconds": 3600,
            "blocked_search_terms": [],  # terms to block
            "log_all_searches": True,
        },
        "tags": ["brave", "search", "mcp", "web"],
        "is_recommended": False,
    },
    "puppeteer-protection": {
        "id": "puppeteer-protection",
        "name": "Puppeteer/Browser Protection",
        "description": "Security rules for Puppeteer MCP server - controls browser automation",
        "category": "mcp-integration",
        "severity": "high",
        "rule_type": RuleType.NETWORK_EGRESS,
        "default_action": RuleAction.REQUIRE_APPROVAL,
        "default_parameters": {
            "integration": "puppeteer",
            "require_approval_for": ["navigate", "click", "fill_form", "screenshot"],
            "blocked_domains": ["*.gov", "*.mil", "bank*.*", "*login*", "*admin*"],
            "allowed_domains": [],  # empty = allow all except blocked
            "block_downloads": True,
            "block_file_uploads": True,
            "max_pages_per_session": 50,
            "timeout_seconds": 300,
        },
        "tags": ["puppeteer", "browser", "mcp", "automation"],
        "is_recommended": True,
    },
    "memory-protection": {
        "id": "memory-protection",
        "name": "Memory/Knowledge Graph Protection",
        "description": "Security rules for Memory MCP server - controls knowledge storage",
        "category": "mcp-integration",
        "severity": "low",
        "rule_type": RuleType.RATE_LIMIT,
        "default_action": RuleAction.ALLOW,
        "default_parameters": {
            "integration": "memory",
            "max_entities": 10000,
            "max_relations": 50000,
            "blocked_entity_types": ["credential", "password", "api_key", "secret"],
            "log_all_writes": True,
        },
        "tags": ["memory", "knowledge-graph", "mcp", "storage"],
        "is_recommended": False,
    },
    "fetch-protection": {
        "id": "fetch-protection",
        "name": "HTTP Fetch Protection",
        "description": "Security rules for Fetch MCP server - controls HTTP requests",
        "category": "mcp-integration",
        "severity": "high",
        "rule_type": RuleType.NETWORK_EGRESS,
        "default_action": RuleAction.LOG_ONLY,
        "default_parameters": {
            "integration": "fetch",
            "blocked_domains": [
                "*.pastebin.com",
                "*.transfer.sh",
                "*.file.io",
                "*.ngrok.io",
                "localhost",
                "127.0.0.1",
                "*.internal",
                "*.local",
            ],
            "blocked_ports": [22, 23, 25, 445, 3389, 6666, 6667],
            "allowed_methods": ["GET", "POST"],
            "blocked_methods": ["DELETE", "PUT", "PATCH"],
            "require_https": True,
            "max_response_size_mb": 10,
            "timeout_seconds": 30,
        },
        "tags": ["fetch", "http", "mcp", "network"],
        "is_recommended": True,
    },
    "sentry-protection": {
        "id": "sentry-protection",
        "name": "Sentry Protection",
        "description": "Security rules for Sentry MCP server - controls error tracking access",
        "category": "mcp-integration",
        "severity": "medium",
        "rule_type": RuleType.HUMAN_IN_LOOP,
        "default_action": RuleAction.LOG_ONLY,
        "default_parameters": {
            "integration": "sentry",
            "require_approval_for": ["resolve_issue", "ignore_issue", "delete_issue"],
            "allowed_operations": ["list_issues", "get_issue", "search_issues"],
            "blocked_operations": ["delete_project"],
            "timeout_seconds": 300,
        },
        "tags": ["sentry", "error-tracking", "mcp", "monitoring"],
        "is_recommended": False,
    },
    "stripe-protection": {
        "id": "stripe-protection",
        "name": "Stripe Protection",
        "description": "Security rules for Stripe MCP server - controls payment operations",
        "category": "mcp-integration",
        "severity": "critical",
        "rule_type": RuleType.HUMAN_IN_LOOP,
        "default_action": RuleAction.REQUIRE_APPROVAL,
        "default_parameters": {
            "integration": "stripe",
            "require_approval_for": [
                "create_charge", "refund", "create_subscription",
                "cancel_subscription", "modify_customer"
            ],
            "allowed_operations": ["list_customers", "get_balance", "list_transactions"],
            "blocked_operations": ["delete_customer", "create_payout"],
            "max_charge_amount": 10000,  # cents
            "timeout_seconds": 300,
        },
        "tags": ["stripe", "payments", "mcp", "billing"],
        "is_recommended": True,
    },
    "twilio-protection": {
        "id": "twilio-protection",
        "name": "Twilio Protection",
        "description": "Security rules for Twilio MCP server - controls SMS and voice operations",
        "category": "mcp-integration",
        "severity": "high",
        "rule_type": RuleType.HUMAN_IN_LOOP,
        "default_action": RuleAction.REQUIRE_APPROVAL,
        "default_parameters": {
            "integration": "twilio",
            "require_approval_for": ["send_sms", "make_call", "send_mms"],
            "allowed_operations": ["list_messages", "get_message", "list_calls"],
            "blocked_operations": ["delete_number", "bulk_send"],
            "rate_limit": {"max_messages": 100, "window_hours": 24},
            "allowed_countries": ["US", "CA", "GB"],  # country codes
            "timeout_seconds": 300,
        },
        "tags": ["twilio", "sms", "mcp", "communications"],
        "is_recommended": True,
    },
    "confluence-protection": {
        "id": "confluence-protection",
        "name": "Confluence Protection",
        "description": "Security rules for Confluence MCP server - controls wiki and documentation",
        "category": "mcp-integration",
        "severity": "medium",
        "rule_type": RuleType.HUMAN_IN_LOOP,
        "default_action": RuleAction.REQUIRE_APPROVAL,
        "default_parameters": {
            "integration": "confluence",
            "require_approval_for": ["delete_page", "modify_permissions", "move_page"],
            "allowed_operations": ["read_page", "create_page", "update_page", "search"],
            "blocked_operations": ["delete_space", "export_space"],
            "protected_spaces": ["HR", "Legal", "Finance", "Security"],
            "timeout_seconds": 300,
        },
        "tags": ["confluence", "wiki", "mcp", "atlassian"],
        "is_recommended": True,
    },
    # =========================================================================
    # OPENCLAW / CLAUDE CODE AGENT TEMPLATES
    # =========================================================================
    "openclaw-safe-commands": {
        "id": "openclaw-safe-commands",
        "name": "OpenClaw Safe Commands",
        "description": "Allow common safe commands for OpenClaw agents (ls, cat, grep, git status, etc.)",
        "category": "openclaw",
        "severity": "low",
        "rule_type": RuleType.COMMAND_ALLOWLIST,
        "default_action": RuleAction.ALLOW,
        "default_parameters": {
            "patterns": [
                r"^ls(\s|$)",
                r"^cat\s+[^|;&]*$",
                r"^head\s",
                r"^tail\s",
                r"^grep\s+[^|;&]*$",
                r"^find\s+[^|;&]*$",
                r"^pwd$",
                r"^whoami$",
                r"^date$",
                r"^echo\s",
                r"^wc\s",
                r"^git\s+(status|log|diff|branch|show|ls-files)",
                r"^node\s+--version",
                r"^npm\s+(list|ls|outdated)",
                r"^python3?\s+--version",
                r"^rclone\s+(version|lsd|ls|lsl)",
            ],
        },
        "tags": ["openclaw", "allowlist", "safe-commands"],
        "is_recommended": True,
    },
    "openclaw-sync-operations": {
        "id": "openclaw-sync-operations",
        "name": "OpenClaw Sync Operations",
        "description": "Allow file sync operations (rclone, rsync) for OpenClaw workspace management",
        "category": "openclaw",
        "severity": "medium",
        "rule_type": RuleType.COMMAND_ALLOWLIST,
        "default_action": RuleAction.ALLOW,
        "default_parameters": {
            "patterns": [
                r"^sync-to-gdrive",
                r"^rclone\s+(copy|sync)\s+/home/node/",
                r"^rsync\s+-[a-z]+\s+/home/node/",
            ],
        },
        "tags": ["openclaw", "sync", "gdrive", "rclone"],
        "is_recommended": True,
    },
    "openclaw-block-dangerous": {
        "id": "openclaw-block-dangerous",
        "name": "OpenClaw Block Dangerous",
        "description": "Block dangerous commands that could harm the system or exfiltrate data",
        "category": "openclaw",
        "severity": "critical",
        "rule_type": RuleType.COMMAND_DENYLIST,
        "default_action": RuleAction.DENY,
        "default_parameters": {
            "patterns": [
                r"rm\s+-rf\s+/",
                r"rm\s+-rf\s+~",
                r"rm\s+-rf\s+\*",
                r"mkfs\.",
                r"dd\s+if=.*of=/dev/",
                r"chmod\s+-R\s+777\s+/",
                r"curl.*\|\s*(bash|sh)",
                r"wget.*\|\s*(bash|sh)",
                r">\s*/etc/",
                r"nc\s+-[el]",
                r"ncat\s+-[el]",
                r"/dev/tcp/",
                r"base64\s+-d.*\|\s*(bash|sh)",
                r"eval\s+\$\(",
            ],
        },
        "tags": ["openclaw", "denylist", "security", "critical"],
        "is_recommended": True,
    },
    "openclaw-require-approval": {
        "id": "openclaw-require-approval",
        "name": "OpenClaw Approval Required",
        "description": "Require human approval for sensitive operations like installs and config changes",
        "category": "openclaw",
        "severity": "high",
        "rule_type": RuleType.HUMAN_IN_LOOP,
        "default_action": RuleAction.REQUIRE_APPROVAL,
        "default_parameters": {
            "patterns": [
                r"^(apt|apt-get|yum|dnf|pacman)\s+install",
                r"^pip\s+install",
                r"^npm\s+install\s+-g",
                r"^sudo\s+",
                r"^chmod\s+[0-7]*[75][0-7]*\s+",
                r"^chown\s+",
                r">\s*\.(bashrc|zshrc|profile|env)",
                r"crontab\s+",
            ],
            "timeout_seconds": 300,
            "auto_deny_on_timeout": True,
        },
        "tags": ["openclaw", "approval", "install", "sensitive"],
        "is_recommended": True,
    },
    # =========================================================================
    # PII PROTECTION TEMPLATES
    # =========================================================================
    "pii-gate-protection": {
        "id": "pii-gate-protection",
        "name": "PII Gate Protection",
        "description": "Detect and require approval when PII or vault tokens are about to be submitted via browser or other tools",
        "category": "pii",
        "severity": "critical",
        "rule_type": RuleType.PII_GATE,
        "default_action": RuleAction.REQUIRE_APPROVAL,
        "default_parameters": {
            "scan_tool_input": True,
            "scan_command": True,
            "detect_vault_tokens": True,
            "detect_raw_pii": True,
            "pii_categories": [
                "credit_card",
                "email",
                "phone_us_ca",
                "street_address",
                "name_with_title",
            ],
            "exempt_domains": [],
            "require_vault_for_approval": False,
        },
        "default_priority": 200,
        "tags": ["pii", "vault", "browser", "approval"],
        "is_recommended": True,
    },
    "pii-gate-strict": {
        "id": "pii-gate-strict",
        "name": "PII Gate (Strict - Vault Required)",
        "description": "Deny raw PII submissions outright - only vault tokens are allowed (with approval)",
        "category": "pii",
        "severity": "critical",
        "rule_type": RuleType.PII_GATE,
        "default_action": RuleAction.REQUIRE_APPROVAL,
        "default_parameters": {
            "scan_tool_input": True,
            "scan_command": True,
            "detect_vault_tokens": True,
            "detect_raw_pii": True,
            "pii_categories": [
                "credit_card",
                "us_ssn",
                "email",
                "phone_us_ca",
                "street_address",
                "name_with_title",
                "passport",
            ],
            "exempt_domains": [],
            "require_vault_for_approval": True,
        },
        "default_priority": 200,
        "tags": ["pii", "vault", "strict", "browser"],
        "is_recommended": False,
    },
}


@router.get("", response_model=RuleListResponse)
async def list_rules(
    db: DbSessionDep,
    org_id: OptionalOrgIdDep,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    agent_id: Optional[UUID] = None,
    rule_type: Optional[RuleType] = None,
    is_active: Optional[bool] = None,
    include_global: bool = True,
    include_deleted: bool = False,
):
    """List all rules with pagination and filtering."""
    stmt = select(Rule)

    # Org scoping
    if org_id:
        stmt = stmt.where(
            (Rule.organization_id == org_id) | (Rule.organization_id == None)
        )

    if not include_deleted:
        stmt = stmt.where(Rule.is_deleted == False)

    if agent_id:
        if include_global:
            stmt = stmt.where((Rule.agent_id == agent_id) | (Rule.agent_id == None))
        else:
            stmt = stmt.where(Rule.agent_id == agent_id)

    if rule_type:
        stmt = stmt.where(Rule.rule_type == rule_type)

    if is_active is not None:
        stmt = stmt.where(Rule.is_active == is_active)

    # Get total count
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    # Apply pagination and ordering
    stmt = stmt.order_by(Rule.priority.desc(), Rule.created_at.desc())
    stmt = stmt.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(stmt)
    rules = list(result.scalars().all())

    return RuleListResponse(
        items=[RuleResponse.model_validate(r) for r in rules],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.post(
    "",
    response_model=RuleResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(QuotaChecker("rules"))],
)
async def create_rule(
    rule_data: RuleCreate,
    db: DbSessionDep,
    redis: RedisDep,
    org_id: OptionalOrgIdDep,
):
    """Create a new rule."""
    # Validate parameters against schema
    schema = RULE_PARAMETER_SCHEMAS.get(rule_data.rule_type)
    if schema:
        # Basic validation - could use jsonschema for full validation
        required = schema.get("required", [])
        for field in required:
            if field not in rule_data.parameters:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Missing required parameter: {field}",
                )

    # Create rule
    rule = Rule(
        name=rule_data.name,
        description=rule_data.description,
        agent_id=rule_data.agent_id,
        rule_type=rule_data.rule_type,
        action=rule_data.action,
        priority=rule_data.priority,
        parameters=rule_data.parameters,
        is_active=rule_data.is_active,
        tags=rule_data.tags,
        source=rule_data.source,
        source_reference=rule_data.source_reference,
        organization_id=org_id,
    )

    db.add(rule)
    await db.flush()

    # Create audit log
    audit_log = AuditLog(
        action=AuditAction.RULE_CREATED,
        severity=AuditSeverity.INFO,
        rule_id=rule.id,
        agent_id=rule.agent_id,
        message=f"Rule '{rule.name}' created",
        new_value={
            "name": rule.name,
            "rule_type": rule.rule_type,
            "action": rule.action,
            "priority": rule.priority,
        },
    )
    db.add(audit_log)

    await db.commit()
    asyncio.ensure_future(publish_from_audit_log(audit_log))
    await db.refresh(rule)

    # Invalidate rule cache for agent
    if rule.agent_id:
        engine = RuleEngine(db, redis)
        await engine.invalidate_cache(rule.agent_id)

    logger.info(f"Rule created: {rule.id} ({rule.name})")
    return RuleResponse.model_validate(rule)


@router.get("/templates", response_model=List[RuleTemplateResponse])
async def list_templates():
    """List available rule templates."""
    return [
        RuleTemplateResponse(**template)
        for template in RULE_TEMPLATES.values()
    ]


@router.post("/templates/{template_id}/apply", response_model=RuleResponse)
async def apply_template(
    template_id: str,
    request: ApplyTemplateRequest,
    db: DbSessionDep,
    redis: RedisDep,
):
    """Apply a rule template to create a new rule."""
    template = RULE_TEMPLATES.get(template_id)
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Template '{template_id}' not found",
        )

    # Merge default parameters with overrides
    parameters = {**template["default_parameters"], **request.parameter_overrides}

    # Create rule from template
    rule = Rule(
        name=template["name"],
        description=template["description"],
        agent_id=request.agent_id,
        rule_type=template["rule_type"],
        action=template["default_action"],
        priority=100 if template["severity"] == "critical" else 50,
        parameters=parameters,
        is_active=request.activate_immediately,
        tags=template["tags"],
        source="template",
        source_reference=template_id,
    )

    db.add(rule)
    await db.flush()

    # Create audit log
    audit_log = AuditLog(
        action=AuditAction.RULE_CREATED,
        severity=AuditSeverity.INFO,
        rule_id=rule.id,
        agent_id=rule.agent_id,
        message=f"Rule created from template: {template['name']}",
        new_value={"template_id": template_id, "parameters": parameters},
    )
    db.add(audit_log)

    await db.commit()
    asyncio.ensure_future(publish_from_audit_log(audit_log))
    await db.refresh(rule)

    # Invalidate cache
    if rule.agent_id:
        engine = RuleEngine(db, redis)
        await engine.invalidate_cache(rule.agent_id)

    return RuleResponse.model_validate(rule)


@router.get("/{rule_id}", response_model=RuleResponse)
async def get_rule(
    rule_id: UUID,
    db: DbSessionDep,
):
    """Get rule by ID."""
    stmt = select(Rule).where(Rule.id == rule_id, Rule.is_deleted == False)
    rule = (await db.execute(stmt)).scalar_one_or_none()

    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule {rule_id} not found",
        )

    return RuleResponse.model_validate(rule)


@router.put("/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: UUID,
    rule_data: RuleUpdate,
    db: DbSessionDep,
    redis: RedisDep,
):
    """Update a rule."""
    stmt = select(Rule).where(Rule.id == rule_id, Rule.is_deleted == False)
    rule = (await db.execute(stmt)).scalar_one_or_none()

    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule {rule_id} not found",
        )

    # Store old values for audit
    old_values = {
        "name": rule.name,
        "action": rule.action,
        "priority": rule.priority,
        "is_active": rule.is_active,
    }

    # Update fields
    update_data = rule_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(rule, field, value)

    # Determine appropriate audit action
    if "is_active" in update_data:
        if update_data["is_active"]:
            action = AuditAction.RULE_ACTIVATED
        else:
            action = AuditAction.RULE_DEACTIVATED
    else:
        action = AuditAction.RULE_UPDATED

    # Create audit log
    audit_log = AuditLog(
        action=action,
        severity=AuditSeverity.INFO,
        rule_id=rule.id,
        agent_id=rule.agent_id,
        message=f"Rule '{rule.name}' updated",
        old_value=old_values,
        new_value=update_data,
    )
    db.add(audit_log)

    await db.commit()
    asyncio.ensure_future(publish_from_audit_log(audit_log))
    await db.refresh(rule)

    # Invalidate cache
    if rule.agent_id:
        engine = RuleEngine(db, redis)
        await engine.invalidate_cache(rule.agent_id)

    return RuleResponse.model_validate(rule)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: UUID,
    db: DbSessionDep,
    redis: RedisDep,
    hard_delete: bool = False,
):
    """Delete a rule."""
    stmt = select(Rule).where(Rule.id == rule_id)
    rule = (await db.execute(stmt)).scalar_one_or_none()

    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule {rule_id} not found",
        )

    agent_id = rule.agent_id

    if hard_delete:
        await db.delete(rule)
    else:
        rule.is_deleted = True
        rule.deleted_at = datetime.utcnow()
        rule.is_active = False

    # Create audit log
    audit_log = AuditLog(
        action=AuditAction.RULE_DELETED,
        severity=AuditSeverity.WARNING,
        rule_id=rule.id,
        agent_id=agent_id,
        message=f"Rule '{rule.name}' deleted",
        old_value={"name": rule.name, "rule_type": rule.rule_type},
    )
    db.add(audit_log)

    await db.commit()
    asyncio.ensure_future(publish_from_audit_log(audit_log))

    # Invalidate cache
    if agent_id:
        engine = RuleEngine(db, redis)
        await engine.invalidate_cache(agent_id)


@router.post("/validate", response_model=RuleValidateResponse)
async def validate_rule(
    request: RuleValidateRequest,
    db: DbSessionDep,
    redis: RedisDep,
):
    """Validate a rule (dry run)."""
    errors = []
    warnings = []

    # Validate parameters against schema
    schema = RULE_PARAMETER_SCHEMAS.get(request.rule.rule_type)
    if schema:
        required = schema.get("required", [])
        for field in required:
            if field not in request.rule.parameters:
                errors.append(f"Missing required parameter: {field}")

    # Test evaluation if context provided
    would_match = False
    action_result = request.rule.action
    evaluation_details = {}

    if request.test_context and not errors:
        # Create temporary rule for testing
        temp_rule = Rule(
            name=request.rule.name,
            rule_type=request.rule.rule_type,
            action=request.rule.action,
            parameters=request.rule.parameters,
            is_active=True,
        )

        # Build evaluation context
        context = EvaluationContext(
            agent_id=request.test_context.get("agent_id", UUID("00000000-0000-0000-0000-000000000000")),
            request_type=request.test_context.get("request_type", "api"),
            command=request.test_context.get("command"),
            skill_id=request.test_context.get("skill_id"),
            origin=request.test_context.get("origin"),
            ip_address=request.test_context.get("ip_address"),
        )

        # This is simplified - full evaluation would use the engine
        evaluation_details = {
            "context": request.test_context,
            "rule_type": request.rule.rule_type,
        }

    return RuleValidateResponse(
        is_valid=len(errors) == 0,
        would_match=would_match,
        action_result=action_result,
        validation_errors=errors,
        warnings=warnings,
        evaluation_details=evaluation_details,
    )


@router.post("/export", response_model=RuleExportResponse)
async def export_rules(
    request: RuleExportRequest,
    db: DbSessionDep,
):
    """Export rules as JSON or YAML."""
    stmt = select(Rule).where(Rule.is_deleted == False, Rule.is_active == True)

    if request.rule_ids:
        stmt = stmt.where(Rule.id.in_(request.rule_ids))
    elif request.agent_id:
        if request.include_global:
            stmt = stmt.where((Rule.agent_id == request.agent_id) | (Rule.agent_id == None))
        else:
            stmt = stmt.where(Rule.agent_id == request.agent_id)

    result = await db.execute(stmt)
    rules = list(result.scalars().all())

    # Convert to exportable format
    export_data = []
    for rule in rules:
        export_data.append({
            "name": rule.name,
            "description": rule.description,
            "rule_type": rule.rule_type,
            "action": rule.action,
            "priority": rule.priority,
            "parameters": rule.parameters,
            "tags": rule.tags,
        })

    # Format output
    if request.format == "yaml":
        data_str = yaml.dump(export_data, default_flow_style=False)
    else:
        data_str = json.dumps(export_data, indent=2)

    return RuleExportResponse(
        format=request.format,
        rules_count=len(rules),
        data=data_str,
        exported_at=datetime.utcnow(),
    )


@router.post("/import", response_model=RuleImportResponse)
async def import_rules(
    request: RuleImportRequest,
    db: DbSessionDep,
    redis: RedisDep,
):
    """Import rules from JSON."""
    imported = 0
    skipped = 0
    errors = []
    created_rules = []

    for rule_data in request.rules:
        try:
            # Check for existing rule with same name
            stmt = select(Rule).where(
                Rule.name == rule_data.name,
                Rule.is_deleted == False,
            )
            existing = (await db.execute(stmt)).scalar_one_or_none()

            if existing:
                if request.overwrite_existing:
                    # Update existing
                    for field, value in rule_data.model_dump(exclude_unset=True).items():
                        if field != "agent_id":
                            setattr(existing, field, value)
                    imported += 1
                    created_rules.append(RuleResponse.model_validate(existing))
                else:
                    skipped += 1
                continue

            if request.dry_run:
                imported += 1
                continue

            # Create new rule
            rule = Rule(
                name=rule_data.name,
                description=rule_data.description,
                agent_id=rule_data.agent_id,
                rule_type=rule_data.rule_type,
                action=rule_data.action,
                priority=rule_data.priority,
                parameters=rule_data.parameters,
                is_active=rule_data.is_active,
                tags=rule_data.tags,
                source="import",
            )
            db.add(rule)
            await db.flush()

            imported += 1
            created_rules.append(RuleResponse.model_validate(rule))

        except Exception as e:
            errors.append({
                "rule_name": rule_data.name,
                "error": str(e),
            })

    if not request.dry_run:
        await db.commit()

    return RuleImportResponse(
        imported=imported,
        skipped=skipped,
        errors=errors,
        rules=created_rules if not request.dry_run else [],
    )


# ============================================================================
# POLICY-AS-CODE: YAML GET EXPORT / POST IMPORT / SYNC
# ============================================================================

@router.get("/export")
async def export_rules_yaml(
    db: DbSessionDep,
    agent_id: Optional[UUID] = None,
    format: str = Query("yaml", pattern="^(yaml|json)$"),
    include_global: bool = True,
):
    """Export rules as YAML or JSON (GET-based, policy-as-code friendly).

    Returns human-readable YAML suitable for version control.
    """
    stmt = select(Rule).where(Rule.is_deleted == False, Rule.is_active == True)

    if agent_id:
        if include_global:
            stmt = stmt.where((Rule.agent_id == agent_id) | (Rule.agent_id == None))
        else:
            stmt = stmt.where(Rule.agent_id == agent_id)

    stmt = stmt.order_by(Rule.priority.desc())
    result = await db.execute(stmt)
    rules = list(result.scalars().all())

    export_data = {
        "version": "1",
        "exported_at": datetime.utcnow().isoformat(),
        "rules": [
            {
                "name": r.name,
                "type": r.rule_type if isinstance(r.rule_type, str) else r.rule_type.value,
                "action": r.action if isinstance(r.action, str) else r.action.value,
                "priority": r.priority,
                "active": r.is_active,
                "parameters": r.parameters,
                **({"description": r.description} if r.description else {}),
                **({"tags": r.tags} if r.tags else {}),
                **({"agent_id": str(r.agent_id)} if r.agent_id else {"agent": "*"}),
            }
            for r in rules
        ],
    }

    if format == "yaml":
        from fastapi.responses import Response as RawResponse
        data_str = yaml.dump(export_data, default_flow_style=False, sort_keys=False)
        return RawResponse(
            content=data_str,
            media_type="application/x-yaml",
            headers={"Content-Disposition": "attachment; filename=snapper-rules.yaml"},
        )
    else:
        return export_data


@router.post("/sync")
async def sync_rules_yaml(
    request: Request,
    db: DbSessionDep,
    dry_run: bool = Query(False),
):
    """Sync rules from a YAML payload — diffs against current rules and applies changes.

    Designed for CI/CD pipelines and GitOps workflows.
    Returns a diff of what would change (or was changed).
    """
    body = await request.body()
    try:
        payload = yaml.safe_load(body.decode())
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {e}")

    if not isinstance(payload, dict) or "rules" not in payload:
        raise HTTPException(status_code=400, detail="YAML must contain a 'rules' key")

    incoming_rules = payload["rules"]
    if not isinstance(incoming_rules, list):
        raise HTTPException(status_code=400, detail="'rules' must be a list")

    # Load current rules
    stmt = select(Rule).where(Rule.is_deleted == False)
    result = await db.execute(stmt)
    current_rules = {r.name: r for r in result.scalars().all()}

    diff = {"created": [], "updated": [], "unchanged": [], "errors": []}

    for rule_data in incoming_rules:
        name = rule_data.get("name")
        if not name:
            diff["errors"].append({"error": "Rule missing 'name' field", "data": rule_data})
            continue

        try:
            rule_type = rule_data.get("type", rule_data.get("rule_type"))
            action = rule_data.get("action", "deny")
            priority = rule_data.get("priority", 0)
            parameters = rule_data.get("parameters", {})
            is_active = rule_data.get("active", True)
            description = rule_data.get("description")
            tags = rule_data.get("tags", [])

            if name in current_rules:
                existing = current_rules[name]
                # Check if anything changed
                changed = False
                changes = {}
                if rule_type and (existing.rule_type if isinstance(existing.rule_type, str) else existing.rule_type.value) != rule_type:
                    changes["rule_type"] = rule_type
                    changed = True
                if (existing.action if isinstance(existing.action, str) else existing.action.value) != action:
                    changes["action"] = action
                    changed = True
                if existing.priority != priority:
                    changes["priority"] = priority
                    changed = True
                if existing.parameters != parameters:
                    changes["parameters"] = parameters
                    changed = True
                if existing.is_active != is_active:
                    changes["is_active"] = is_active
                    changed = True

                if changed:
                    if not dry_run:
                        if rule_type:
                            existing.rule_type = rule_type
                        existing.action = action
                        existing.priority = priority
                        existing.parameters = parameters
                        existing.is_active = is_active
                        if description is not None:
                            existing.description = description
                        if tags:
                            existing.tags = tags
                    diff["updated"].append({"name": name, "changes": changes})
                else:
                    diff["unchanged"].append(name)
            else:
                # New rule
                if not dry_run:
                    new_rule = Rule(
                        name=name,
                        description=description,
                        rule_type=rule_type,
                        action=action,
                        priority=priority,
                        parameters=parameters,
                        is_active=is_active,
                        tags=tags,
                        source="policy-as-code",
                    )
                    db.add(new_rule)
                diff["created"].append(name)

        except Exception as e:
            diff["errors"].append({"name": name, "error": str(e)})

    if not dry_run:
        await db.flush()

    return {
        "dry_run": dry_run,
        "summary": {
            "created": len(diff["created"]),
            "updated": len(diff["updated"]),
            "unchanged": len(diff["unchanged"]),
            "errors": len(diff["errors"]),
        },
        "diff": diff,
    }


# ============================================================================
# RULE EVALUATION ENDPOINT (for hooks)
# ============================================================================

from pydantic import BaseModel


class EvaluateRequest(BaseModel):
    """Request for rule evaluation from hooks."""
    agent_id: str
    request_type: str  # "command", "file_access", "network", "tool", "skill"
    # For command requests
    command: Optional[str] = None
    # For file access requests
    file_path: Optional[str] = None
    file_operation: Optional[str] = None  # "read" or "write"
    # For network requests
    url: Optional[str] = None
    # For origin validation (CVE-2026-25253 mitigation)
    origin: Optional[str] = None
    # For skill installation requests
    skill_id: Optional[str] = None
    # For generic tool requests
    tool_name: Optional[str] = None
    tool_input: Optional[Dict[str, Any]] = None


class EvaluateResponse(BaseModel):
    """Response from rule evaluation."""
    decision: str  # "allow", "deny", "require_approval"
    reason: str
    matched_rule_id: Optional[str] = None
    matched_rule_name: Optional[str] = None
    approval_request_id: Optional[str] = None  # For require_approval decisions
    approval_timeout_seconds: Optional[int] = None  # How long until approval expires
    resolved_data: Optional[Dict[str, Any]] = None  # Inline-resolved vault tokens (auto mode)


@router.post("/evaluate", response_model=EvaluateResponse)
async def evaluate_request(
    request: EvaluateRequest,
    fastapi_request: Request,
    db: DbSessionDep,
    redis: RedisDep,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    """
    Evaluate a request against rules.

    This endpoint is called by the PreToolUse hook to check if an action
    should be allowed, denied, or require approval.

    Authentication:
    - If X-API-Key header is provided, agent is identified by API key
    - Otherwise, agent is identified by agent_id in request body
    - If REQUIRE_API_KEY=true and no key provided, returns 401
    """
    from app.models.agents import Agent
    from app.config import get_settings

    settings = get_settings()
    agent = None

    # Try API key authentication first
    if x_api_key:
        if not x_api_key.startswith("snp_"):
            return EvaluateResponse(
                decision="deny",
                reason="Invalid API key format",
            )

        stmt = select(Agent).where(
            Agent.api_key == x_api_key,
            Agent.is_deleted == False,
        )
        agent = (await db.execute(stmt)).scalar_one_or_none()

        if not agent:
            return EvaluateResponse(
                decision="deny",
                reason="Invalid API key",
            )

        # Update last used + last seen timestamps
        agent.api_key_last_used = datetime.utcnow()
        agent.last_seen_at = datetime.utcnow()

    # Fall back to external_id lookup if no API key
    if not agent and request.agent_id:
        if settings.REQUIRE_API_KEY:
            return EvaluateResponse(
                decision="deny",
                reason="API key required. Set X-API-Key header.",
            )

        stmt = select(Agent).where(
            Agent.external_id == request.agent_id,
            Agent.is_deleted == False,
        )
        agent = (await db.execute(stmt)).scalar_one_or_none()

    if not agent:
        # Unknown agent - deny by default
        return EvaluateResponse(
            decision="deny",
            reason=f"Unknown agent: {request.agent_id}",
        )

    # Check agent status
    if agent.status == "suspended":
        return EvaluateResponse(
            decision="deny",
            reason="Agent is suspended",
        )

    if agent.status == "quarantined":
        return EvaluateResponse(
            decision="deny",
            reason="Agent is quarantined due to security concerns",
        )

    # Parse URL for network requests
    target_host = None
    if request.url:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(request.url)
            target_host = parsed.netloc or parsed.hostname
        except Exception:
            pass

    # Check for one-time approval (from "Allow Once" button)
    if request.command:
        import hashlib
        cmd_hash = hashlib.sha256(request.command.encode()).hexdigest()[:16]
        # Check both by agent name and external_id
        approval_keys = [
            f"once_allow:{agent.name}:{cmd_hash}",
            f"once_allow:{request.agent_id}:{cmd_hash}",
        ]
        for approval_key in approval_keys:
            if await redis.get(approval_key):
                # One-time approval found - delete it and allow
                await redis.delete(approval_key)
                return EvaluateResponse(
                    decision="allow",
                    reason="One-time approval granted via Telegram",
                )

    # Build evaluation context
    client_ip = fastapi_request.client.host if fastapi_request.client else None
    context = EvaluationContext(
        agent_id=agent.id,
        request_type=request.request_type,
        command=request.command,
        skill_id=request.skill_id,
        file_path=request.file_path,
        file_operation=request.file_operation,
        target_host=target_host,
        origin=request.origin,
        ip_address=client_ip,
        metadata={"tool_name": request.tool_name, "tool_input": request.tool_input} if request.tool_name else {},
    )

    # Create rule engine and evaluate
    engine = RuleEngine(db, redis)
    result = await engine.evaluate(context)

    # Update agent activity counters
    agent.last_rule_evaluation_at = datetime.utcnow()
    if result.decision.value == "deny":
        agent.violation_count = (agent.violation_count or 0) + 1

    # Update match_count and last_matched_at for all matched rules
    if result.matched_rules:
        await db.execute(
            update(Rule)
            .where(Rule.id.in_(result.matched_rules))
            .values(match_count=Rule.match_count + 1, last_matched_at=datetime.utcnow())
        )

    # Get matched rule name if we have a blocking rule
    matched_rule_name = None
    if result.blocking_rule:
        stmt = select(Rule).where(Rule.id == result.blocking_rule)
        blocking_rule = (await db.execute(stmt)).scalar_one_or_none()
        if blocking_rule:
            matched_rule_name = blocking_rule.name

    # Log to audit trail (all decisions: allow, deny, require_approval)
    audit_action_map = {
        "allow": AuditAction.REQUEST_ALLOWED,
        "deny": AuditAction.REQUEST_DENIED,
        "require_approval": AuditAction.REQUEST_PENDING_APPROVAL,
    }
    audit_severity_map = {
        "allow": AuditSeverity.INFO,
        "deny": AuditSeverity.WARNING,
        "require_approval": AuditSeverity.INFO,
    }
    audit_log = AuditLog(
        action=audit_action_map.get(result.decision.value, AuditAction.REQUEST_DENIED),
        severity=audit_severity_map.get(result.decision.value, AuditSeverity.WARNING),
        agent_id=agent.id,
        rule_id=result.blocking_rule,
        organization_id=agent.organization_id,
        message=f"{result.decision.value.upper()}: {result.reason}",
        old_value=None,
        new_value={
            "request_type": request.request_type,
            "command": request.command,
            "file_path": request.file_path,
            "tool_name": request.tool_name,
            "decision": result.decision.value,
        },
    )
    db.add(audit_log)
    await db.commit()

    # Publish event to SIEM (fire-and-forget)
    try:
        from app.services.event_publisher import publish_event
        from app.middleware.metrics import record_rule_evaluation
        await publish_event(
            action=audit_log.action if isinstance(audit_log.action, str) else audit_log.action.value,
            severity=audit_log.severity if isinstance(audit_log.severity, str) else audit_log.severity.value,
            message=audit_log.message,
            agent_id=str(agent.id),
            rule_id=str(result.blocking_rule) if result.blocking_rule else None,
            ip_address=client_ip,
            details={
                "request_type": request.request_type,
                "command": request.command,
                "tool_name": request.tool_name,
                "decision": result.decision.value,
            },
            organization_id=str(agent.organization_id) if agent.organization_id else None,
        )
        record_rule_evaluation(
            rule_type=request.request_type,
            decision=result.decision.value,
            duration_ms=result.evaluation_time_ms,
        )
    except Exception:
        pass  # SIEM/metrics are best-effort

    if result.decision.value in ("deny", "require_approval"):
        # Create PolicyViolation record for denials
        if result.decision.value == "deny":
            violation = PolicyViolation(
                violation_type="rule_denial",
                severity=AuditSeverity.WARNING,
                agent_id=agent.id,
                rule_id=result.blocking_rule,
                audit_log_id=audit_log.id,
                description=f"Agent '{agent.name}' denied: {result.reason}",
                context={
                    "request_type": request.request_type,
                    "command": request.command,
                    "file_path": request.file_path,
                    "tool_name": request.tool_name,
                },
            )
            db.add(violation)
            await db.commit()

        # Send notification for blocked events (async, don't wait)
        try:
            from app.tasks.alerts import send_alert
            from app.config import get_settings
            notify_settings = get_settings()

            # Build notification message — use enriched action from PII gate if available
            pii_ctx = context.metadata.get("pii_detected")
            pii_action = pii_ctx.get("action") if pii_ctx else None
            action_desc = pii_action or request.command or request.file_path or request.tool_name or request.request_type

            if result.decision.value == "deny" and notify_settings.NOTIFY_ON_BLOCK:
                send_alert.delay(
                    title=f"Action Blocked: {matched_rule_name or 'Security Rule'}",
                    message=f"Agent `{agent.name}` attempted: `{action_desc}`\n\nBlocked by: {result.reason}",
                    severity="warning",
                    metadata={
                        "agent_id": request.agent_id,
                        "agent_name": agent.name,
                        "command": request.command,
                        "file_path": request.file_path,
                        "tool_name": request.tool_name,
                        "rule_name": matched_rule_name,
                        "rule_id": str(result.blocking_rule) if result.blocking_rule else None,
                        "agent_owner_chat_id": getattr(agent, "owner_chat_id", None),
                    },
                )
            elif result.decision.value == "require_approval":
                # Create approval request in Redis
                from app.routers.approvals import create_approval_request

                # Check if PII was detected (from PII gate evaluator)
                pii_context = context.metadata.get("pii_detected")
                vault_tokens = pii_context.get("vault_tokens", []) if pii_context else []
                placeholder_matches = pii_context.get("placeholder_matches", {}) if pii_context else {}
                label_matches = pii_context.get("label_matches", {}) if pii_context else {}

                # Include placeholder-mapped and label-mapped tokens in vault_tokens for resolution
                all_vault_tokens = list(vault_tokens)
                for token in placeholder_matches.values():
                    if token not in all_vault_tokens:
                        all_vault_tokens.append(token)
                for token in label_matches.values():
                    if token not in all_vault_tokens:
                        all_vault_tokens.append(token)

                # Look up vault token owner for ownership enforcement
                vault_owner_chat_id = None
                if all_vault_tokens:
                    try:
                        from app.services.pii_vault import get_entry_by_token
                        first_entry = await get_entry_by_token(db, all_vault_tokens[0])
                        if first_entry:
                            vault_owner_chat_id = first_entry.owner_chat_id
                    except Exception as e:
                        logger.warning(f"Failed to look up vault token owner: {e}")

                approval_request_id = await create_approval_request(
                    redis=redis,
                    agent_id=request.agent_id,
                    agent_name=agent.name,
                    request_type=request.request_type,
                    rule_id=str(result.blocking_rule) if result.blocking_rule else "",
                    rule_name=matched_rule_name or "Security Rule",
                    command=request.command,
                    file_path=request.file_path,
                    tool_name=request.tool_name,
                    pii_context=pii_context,
                    vault_tokens=all_vault_tokens if all_vault_tokens else None,
                    owner_chat_id=vault_owner_chat_id,
                )

                if notify_settings.NOTIFY_ON_APPROVAL_REQUEST:
                    alert_metadata = {
                        "agent_id": request.agent_id,
                        "agent_name": agent.name,
                        "command": request.command,
                        "file_path": request.file_path,
                        "tool_name": request.tool_name,
                        "rule_name": matched_rule_name,
                        "request_id": approval_request_id,
                        "requires_approval": True,
                        "agent_owner_chat_id": getattr(agent, "owner_chat_id", None),
                    }

                    # Add PII context for rich Telegram notification
                    if pii_context:
                        alert_metadata["pii_context"] = pii_context
                        if vault_owner_chat_id:
                            pii_context["owner_chat_id"] = vault_owner_chat_id

                    title = f"Approval Required: {matched_rule_name or 'Security Rule'}"
                    if pii_context:
                        title = f"PII Submission Detected: {matched_rule_name or 'PII Gate'}"

                    send_alert.delay(
                        title=title,
                        message=f"Agent `{agent.name}` wants to: `{action_desc}`\n\nRule: {result.reason}",
                        severity="warning",
                        metadata=alert_metadata,
                    )
        except Exception as e:
            logger.warning(f"Failed to send alert notification: {e}")

    # Build response
    response = EvaluateResponse(
        decision=result.decision.value,
        reason=result.reason,
        matched_rule_id=str(result.blocking_rule) if result.blocking_rule else None,
        matched_rule_name=matched_rule_name,
    )

    # Add approval info if applicable
    if result.decision.value == "require_approval" and 'approval_request_id' in dir():
        response.approval_request_id = approval_request_id
        response.approval_timeout_seconds = 300  # 5 minutes

    # Inline token resolution for auto mode (allow + pii_detected with vault tokens, placeholders, or labels)
    if result.decision.value == "allow":
        pii_detected = context.metadata.get("pii_detected")
        if pii_detected and (pii_detected.get("vault_tokens") or pii_detected.get("placeholder_matches") or pii_detected.get("label_matches")):
            try:
                from app.services.pii_vault import resolve_tokens, resolve_placeholders, get_entry_by_token

                vault_tokens = pii_detected.get("vault_tokens", [])
                placeholder_matches = pii_detected.get("placeholder_matches", {})
                label_matches = pii_detected.get("label_matches", {})
                destination_domain = pii_detected.get("destination_domain")

                # Look up owner for ownership enforcement
                auto_owner_chat_id = None
                try:
                    all_tokens = list(vault_tokens)
                    for t in list(placeholder_matches.values()) + list(label_matches.values()):
                        if t not in all_tokens:
                            all_tokens.append(t)
                    if all_tokens:
                        first_entry = await get_entry_by_token(db, all_tokens[0])
                        if first_entry:
                            auto_owner_chat_id = first_entry.owner_chat_id
                except Exception:
                    pass

                resolved = {}

                # Resolve vault tokens
                if vault_tokens:
                    token_resolved = await resolve_tokens(
                        db=db,
                        tokens=vault_tokens,
                        destination_domain=destination_domain,
                        requester_chat_id=auto_owner_chat_id,
                    )
                    resolved.update(token_resolved)

                # Resolve placeholders
                if placeholder_matches:
                    placeholder_resolved = await resolve_placeholders(
                        db=db,
                        placeholder_map=placeholder_matches,
                        destination_domain=destination_domain,
                        requester_chat_id=auto_owner_chat_id,
                    )
                    resolved.update(placeholder_resolved)

                # Resolve label references
                if label_matches:
                    label_resolved = await resolve_placeholders(
                        db=db,
                        placeholder_map=label_matches,
                        destination_domain=destination_domain,
                        requester_chat_id=auto_owner_chat_id,
                    )
                    resolved.update(label_resolved)

                if resolved:
                    response.resolved_data = resolved
                    logger.info(f"Auto-resolved {len(resolved)} vault entries for agent {agent.name}")
            except Exception as e:
                logger.error(f"Failed to resolve vault tokens: {e}")

    return response
