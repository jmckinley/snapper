"""Rule management API endpoints."""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

import yaml
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import DbSessionDep, RedisDep, default_rate_limit
from app.models.audit_logs import AuditAction, AuditLog, AuditSeverity
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

# Pre-built rule templates
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
            "strict_mode": True,
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
    # =========================================================================
    "gmail-protection": {
        "id": "gmail-protection",
        "name": "Gmail Protection",
        "description": "Security rules for Gmail MCP server - controls email access, sending, and deletion",
        "category": "mcp-integration",
        "severity": "high",
        "rule_type": RuleType.HUMAN_IN_LOOP,
        "default_action": RuleAction.REQUIRE_APPROVAL,
        "default_parameters": {
            "integration": "gmail",
            "require_approval_for": ["send_email", "delete_email", "modify_labels"],
            "allowed_operations": ["read_email", "search_email", "list_labels"],
            "blocked_operations": ["delete_all", "forward_all"],
            "rate_limit": {"max_sends": 50, "window_hours": 24},
            "allowed_recipients_pattern": None,  # null = allow all
            "blocked_recipients_pattern": r".*@(competitor|spam)\.com$",
            "max_attachment_size_mb": 25,
            "timeout_seconds": 300,
        },
        "tags": ["gmail", "email", "mcp", "google"],
        "is_recommended": True,
    },
    "google-calendar-protection": {
        "id": "google-calendar-protection",
        "name": "Google Calendar Protection",
        "description": "Security rules for Google Calendar MCP server - controls event creation and modification",
        "category": "mcp-integration",
        "severity": "medium",
        "rule_type": RuleType.HUMAN_IN_LOOP,
        "default_action": RuleAction.REQUIRE_APPROVAL,
        "default_parameters": {
            "integration": "google-calendar",
            "require_approval_for": ["create_event", "delete_event", "invite_attendees"],
            "allowed_operations": ["read_events", "list_calendars", "search_events"],
            "blocked_operations": ["delete_calendar", "share_calendar_public"],
            "max_attendees_per_event": 50,
            "allowed_calendars": [],  # empty = allow all
            "timeout_seconds": 300,
        },
        "tags": ["calendar", "google", "mcp", "scheduling"],
        "is_recommended": True,
    },
    "google-drive-protection": {
        "id": "google-drive-protection",
        "name": "Google Drive Protection",
        "description": "Security rules for Google Drive MCP server - controls file access and sharing",
        "category": "mcp-integration",
        "severity": "high",
        "rule_type": RuleType.HUMAN_IN_LOOP,
        "default_action": RuleAction.REQUIRE_APPROVAL,
        "default_parameters": {
            "integration": "google-drive",
            "require_approval_for": ["delete_file", "share_public", "share_external", "move_to_trash"],
            "allowed_operations": ["read_file", "list_files", "search_files", "create_file"],
            "blocked_operations": ["empty_trash", "share_with_anyone_link"],
            "protected_folders": ["Confidential", "HR", "Finance", "Legal"],
            "max_file_size_mb": 100,
            "timeout_seconds": 300,
        },
        "tags": ["drive", "google", "mcp", "file-storage"],
        "is_recommended": True,
    },
    "slack-protection": {
        "id": "slack-protection",
        "name": "Slack Protection",
        "description": "Security rules for Slack MCP server - controls messaging and channel operations",
        "category": "mcp-integration",
        "severity": "high",
        "rule_type": RuleType.HUMAN_IN_LOOP,
        "default_action": RuleAction.REQUIRE_APPROVAL,
        "default_parameters": {
            "integration": "slack",
            "require_approval_for": ["post_message", "create_channel", "invite_user", "upload_file"],
            "allowed_operations": ["read_messages", "list_channels", "search_messages"],
            "blocked_operations": ["delete_channel", "remove_user", "post_to_all_channels"],
            "allowed_channels": [],  # empty = allow all
            "blocked_channels": ["#announcements", "#exec-team", "#hr-confidential"],
            "rate_limit": {"max_messages": 100, "window_hours": 1},
            "timeout_seconds": 300,
        },
        "tags": ["slack", "messaging", "mcp", "chat"],
        "is_recommended": True,
    },
    "github-protection": {
        "id": "github-protection",
        "name": "GitHub Protection",
        "description": "Security rules for GitHub MCP server - controls repository and code operations",
        "category": "mcp-integration",
        "severity": "critical",
        "rule_type": RuleType.HUMAN_IN_LOOP,
        "default_action": RuleAction.REQUIRE_APPROVAL,
        "default_parameters": {
            "integration": "github",
            "require_approval_for": ["push_code", "create_pr", "merge_pr", "delete_branch", "create_release"],
            "allowed_operations": ["read_code", "list_repos", "list_prs", "list_issues", "read_pr"],
            "blocked_operations": ["delete_repo", "force_push_main", "disable_branch_protection"],
            "protected_branches": ["main", "master", "production", "release/*"],
            "protected_repos": [],  # specific repos that need extra protection
            "require_pr_for_changes": True,
            "timeout_seconds": 600,
        },
        "tags": ["github", "code", "mcp", "version-control"],
        "is_recommended": True,
    },
    "linear-protection": {
        "id": "linear-protection",
        "name": "Linear Protection",
        "description": "Security rules for Linear MCP server - controls issue and project management",
        "category": "mcp-integration",
        "severity": "medium",
        "rule_type": RuleType.HUMAN_IN_LOOP,
        "default_action": RuleAction.LOG_ONLY,
        "default_parameters": {
            "integration": "linear",
            "require_approval_for": ["delete_issue", "archive_project", "modify_workflow"],
            "allowed_operations": ["read_issues", "create_issue", "update_issue", "add_comment"],
            "blocked_operations": ["delete_project", "remove_team_member"],
            "timeout_seconds": 300,
        },
        "tags": ["linear", "project-management", "mcp", "issues"],
        "is_recommended": True,
    },
    "notion-protection": {
        "id": "notion-protection",
        "name": "Notion Protection",
        "description": "Security rules for Notion MCP server - controls page and database operations",
        "category": "mcp-integration",
        "severity": "medium",
        "rule_type": RuleType.HUMAN_IN_LOOP,
        "default_action": RuleAction.REQUIRE_APPROVAL,
        "default_parameters": {
            "integration": "notion",
            "require_approval_for": ["delete_page", "share_public", "modify_permissions"],
            "allowed_operations": ["read_page", "create_page", "update_page", "search"],
            "blocked_operations": ["delete_workspace", "share_with_web"],
            "protected_pages": [],  # page IDs that need extra protection
            "timeout_seconds": 300,
        },
        "tags": ["notion", "wiki", "mcp", "documentation"],
        "is_recommended": True,
    },
    "postgres-protection": {
        "id": "postgres-protection",
        "name": "PostgreSQL Protection",
        "description": "Security rules for PostgreSQL MCP server - controls database operations",
        "category": "mcp-integration",
        "severity": "critical",
        "rule_type": RuleType.COMMAND_DENYLIST,
        "default_action": RuleAction.DENY,
        "default_parameters": {
            "integration": "postgres",
            "blocked_operations": ["DROP DATABASE", "DROP TABLE", "TRUNCATE", "DELETE FROM.*WHERE 1=1"],
            "require_approval_for": ["DELETE", "UPDATE", "ALTER TABLE", "CREATE INDEX"],
            "allowed_operations": ["SELECT"],
            "blocked_patterns": [
                r"DROP\s+(DATABASE|TABLE|SCHEMA)",
                r"TRUNCATE",
                r"DELETE\s+FROM\s+\w+\s*;",  # DELETE without WHERE
                r"UPDATE\s+\w+\s+SET.*WHERE\s+1\s*=\s*1",
                r"--",  # SQL comments (potential injection)
                r";.*DROP",  # Chained DROP
            ],
            "max_rows_affected": 1000,
            "read_only_mode": False,
            "timeout_seconds": 30,
        },
        "tags": ["postgres", "database", "mcp", "sql"],
        "is_recommended": True,
    },
    "filesystem-protection": {
        "id": "filesystem-protection",
        "name": "Filesystem Protection",
        "description": "Security rules for Filesystem MCP server - controls file read/write operations",
        "category": "mcp-integration",
        "severity": "critical",
        "rule_type": RuleType.CREDENTIAL_PROTECTION,
        "default_action": RuleAction.DENY,
        "default_parameters": {
            "integration": "filesystem",
            "allowed_directories": ["./", "/tmp", "/home/user/projects"],
            "blocked_directories": ["/etc", "/var", "/root", "/usr", "/bin", "/sbin"],
            "blocked_patterns": [
                r"\.env$",
                r"\.pem$",
                r"\.key$",
                r"id_rsa",
                r"\.ssh/",
                r"\.aws/",
                r"\.gnupg/",
                r"/etc/passwd",
                r"/etc/shadow",
            ],
            "require_approval_for": ["write", "delete", "move"],
            "allowed_operations": ["read", "list"],
            "max_file_size_mb": 50,
        },
        "tags": ["filesystem", "files", "mcp", "local"],
        "is_recommended": True,
    },
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
    "cloudflare-protection": {
        "id": "cloudflare-protection",
        "name": "Cloudflare Protection",
        "description": "Security rules for Cloudflare MCP server - controls DNS and CDN operations",
        "category": "mcp-integration",
        "severity": "critical",
        "rule_type": RuleType.HUMAN_IN_LOOP,
        "default_action": RuleAction.REQUIRE_APPROVAL,
        "default_parameters": {
            "integration": "cloudflare",
            "require_approval_for": ["modify_dns", "purge_cache", "modify_firewall", "modify_workers"],
            "allowed_operations": ["list_zones", "get_dns_records", "get_analytics"],
            "blocked_operations": ["delete_zone", "disable_ssl", "disable_firewall"],
            "protected_zones": [],  # zone IDs that need extra protection
            "timeout_seconds": 600,
        },
        "tags": ["cloudflare", "dns", "mcp", "cdn"],
        "is_recommended": True,
    },
    "aws-protection": {
        "id": "aws-protection",
        "name": "AWS Protection",
        "description": "Security rules for AWS MCP server - controls cloud resource operations",
        "category": "mcp-integration",
        "severity": "critical",
        "rule_type": RuleType.HUMAN_IN_LOOP,
        "default_action": RuleAction.REQUIRE_APPROVAL,
        "default_parameters": {
            "integration": "aws",
            "require_approval_for": [
                "create_instance", "terminate_instance", "modify_security_group",
                "create_bucket", "delete_bucket", "modify_iam"
            ],
            "allowed_operations": ["describe_*", "list_*", "get_*"],
            "blocked_operations": [
                "delete_vpc", "delete_subnet", "modify_root_credentials",
                "create_access_key", "attach_admin_policy"
            ],
            "protected_resources": ["prod-*", "production-*"],
            "allowed_regions": ["us-east-1", "us-west-2", "eu-west-1"],
            "timeout_seconds": 600,
        },
        "tags": ["aws", "cloud", "mcp", "infrastructure"],
        "is_recommended": True,
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
    "discord-protection": {
        "id": "discord-protection",
        "name": "Discord Protection",
        "description": "Security rules for Discord MCP server - controls bot and messaging operations",
        "category": "mcp-integration",
        "severity": "medium",
        "rule_type": RuleType.HUMAN_IN_LOOP,
        "default_action": RuleAction.REQUIRE_APPROVAL,
        "default_parameters": {
            "integration": "discord",
            "require_approval_for": ["send_message", "create_channel", "ban_user", "kick_user"],
            "allowed_operations": ["read_messages", "list_channels", "list_members"],
            "blocked_operations": ["delete_server", "mass_ban", "post_to_all_channels"],
            "blocked_channels": [],  # channel IDs to block
            "rate_limit": {"max_messages": 60, "window_minutes": 1},
            "timeout_seconds": 300,
        },
        "tags": ["discord", "chat", "mcp", "community"],
        "is_recommended": True,
    },
    "jira-protection": {
        "id": "jira-protection",
        "name": "Jira Protection",
        "description": "Security rules for Jira MCP server - controls issue and project management",
        "category": "mcp-integration",
        "severity": "medium",
        "rule_type": RuleType.HUMAN_IN_LOOP,
        "default_action": RuleAction.LOG_ONLY,
        "default_parameters": {
            "integration": "jira",
            "require_approval_for": ["delete_issue", "modify_workflow", "delete_project"],
            "allowed_operations": ["read_issue", "create_issue", "update_issue", "add_comment", "search"],
            "blocked_operations": ["delete_project", "modify_permissions"],
            "protected_projects": [],  # project keys that need extra protection
            "timeout_seconds": 300,
        },
        "tags": ["jira", "project-management", "mcp", "atlassian"],
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


@router.post("", response_model=RuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    rule_data: RuleCreate,
    db: DbSessionDep,
    redis: RedisDep,
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

        # Update last used timestamp
        agent.api_key_last_used = datetime.utcnow()

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
    context = EvaluationContext(
        agent_id=agent.id,
        request_type=request.request_type,
        command=request.command,
        skill_id=request.skill_id,
        file_path=request.file_path,
        file_operation=request.file_operation,
        target_host=target_host,
        origin=request.origin,
        metadata={"tool_name": request.tool_name, "tool_input": request.tool_input} if request.tool_name else {},
    )

    # Create rule engine and evaluate
    engine = RuleEngine(db, redis)
    result = await engine.evaluate(context)

    # Get matched rule name if we have a blocking rule
    matched_rule_name = None
    if result.blocking_rule:
        stmt = select(Rule).where(Rule.id == result.blocking_rule)
        blocking_rule = (await db.execute(stmt)).scalar_one_or_none()
        if blocking_rule:
            matched_rule_name = blocking_rule.name

    # Log to audit trail
    if result.decision.value in ("deny", "require_approval"):
        audit_log = AuditLog(
            action=AuditAction.REQUEST_DENIED if result.decision.value == "deny" else AuditAction.REQUEST_PENDING_APPROVAL,
            severity=AuditSeverity.WARNING if result.decision.value == "deny" else AuditSeverity.INFO,
            agent_id=agent.id,
            rule_id=result.blocking_rule,
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

        # Send notification for blocked events (async, don't wait)
        try:
            from app.tasks.alerts import send_alert
            from app.config import get_settings
            notify_settings = get_settings()

            # Build notification message
            action_desc = request.command or request.file_path or request.tool_name or request.request_type

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
                    },
                )
            elif result.decision.value == "require_approval":
                # Create approval request in Redis
                from app.routers.approvals import create_approval_request

                # Check if PII was detected (from PII gate evaluator)
                pii_context = context.metadata.get("pii_detected")
                vault_tokens = pii_context.get("vault_tokens", []) if pii_context else []

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
                    vault_tokens=vault_tokens if vault_tokens else None,
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
                    }

                    # Add PII context for rich Telegram notification
                    if pii_context:
                        alert_metadata["pii_context"] = pii_context

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

    # Inline token resolution for auto mode (allow + pii_detected with vault tokens)
    if result.decision.value == "allow":
        pii_detected = context.metadata.get("pii_detected")
        if pii_detected and pii_detected.get("vault_tokens"):
            try:
                from app.services.pii_vault import resolve_tokens

                vault_tokens = pii_detected["vault_tokens"]
                destination_domain = pii_detected.get("destination_domain")

                resolved = await resolve_tokens(
                    db=db,
                    tokens=vault_tokens,
                    destination_domain=destination_domain,
                )

                if resolved:
                    response.resolved_data = resolved
                    logger.info(f"Auto-resolved {len(resolved)} vault tokens for agent {agent.name}")
            except Exception as e:
                logger.error(f"Failed to resolve vault tokens: {e}")

    return response
