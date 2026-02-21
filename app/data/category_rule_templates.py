"""Category-based rule templates for MCP server security.

Each security category maps to a set of rule templates that can be
instantiated for a specific server. Templates use {server_key} and
{server_display} placeholders expanded at rule creation time.

These live in code (like RULE_PACKS), not in DB. ~60 template rules
cover all 13 categories instead of needing ~100k per-server rules.
"""

from typing import Any


CATEGORY_RULE_TEMPLATES: dict[str, dict[str, Any]] = {
    # =========================================================================
    # DATA STORE — Strict
    # =========================================================================
    "data_store": {
        "name": "Data Store Security",
        "posture": "strict",
        "rules": [
            {
                "name": "{server_display} - Allow Reads",
                "description": "Allow read-only database operations for {server_display}",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:read|get|list|search|query|find|count|describe|show|select|fetch|browse|inspect|explain).*",
                    ],
                },
            },
            {
                "name": "{server_display} - Approve Writes",
                "description": "Require approval for write operations on {server_display}",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:write|insert|update|upsert|create|set|put|add|alter|modify|merge).*",
                    ],
                },
            },
            {
                "name": "{server_display} - Deny Destructive",
                "description": "Block destructive operations on {server_display}",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:delete|drop|truncate|destroy|remove|purge|wipe|reset).*",
                    ],
                },
            },
            {
                "name": "{server_display} - Deny Bulk Export",
                "description": "Block bulk data export from {server_display}",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 210,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:export_all|dump|backup|bulk_read|extract|migrate_all).*",
                    ],
                },
            },
        ],
    },

    # =========================================================================
    # CODE REPOSITORY — Moderate
    # =========================================================================
    "code_repository": {
        "name": "Code Repository Security",
        "posture": "moderate",
        "rules": [
            {
                "name": "{server_display} - Allow Reads",
                "description": "Allow read-only repository operations for {server_display}",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:get|list|search|read|view|diff|compare|blame|log|show|status|fetch).*",
                    ],
                },
            },
            {
                "name": "{server_display} - Approve Writes",
                "description": "Require approval for commits, merges, and write operations on {server_display}",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:create|update|commit|push|merge|comment|review|approve|assign|label|edit).*",
                    ],
                },
            },
            {
                "name": "{server_display} - Deny Destructive",
                "description": "Block force-push, branch deletion, and destructive ops on {server_display}",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:delete|force_push|destroy|remove|archive|transfer).*",
                    ],
                },
            },
        ],
    },

    # =========================================================================
    # FILESYSTEM — Strict
    # =========================================================================
    "filesystem": {
        "name": "Filesystem Security",
        "posture": "strict",
        "rules": [
            {
                "name": "{server_display} - Allow Reads",
                "description": "Allow read-only filesystem operations for {server_display}",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:read|list|get|search|stat|info|exists|find|glob|head|tail).*",
                    ],
                },
            },
            {
                "name": "{server_display} - Approve Writes",
                "description": "Require approval for file writes on {server_display}",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:write|create|copy|move|rename|append|upload|mkdir).*",
                    ],
                },
            },
            {
                "name": "{server_display} - Deny Destructive",
                "description": "Block file deletion and destructive operations on {server_display}",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:delete|remove|rmdir|unlink|purge|wipe|truncate).*",
                    ],
                },
            },
            {
                "name": "{server_display} - Block Sensitive Paths",
                "description": "Block access to sensitive file paths via {server_display}",
                "rule_type": "credential_protection",
                "action": "deny",
                "priority": 250,
                "parameters": {
                    "protected_patterns": [
                        r"\.env$", r"\.pem$", r"\.key$", r"credentials\.json$",
                        r"\.aws/", r"\.ssh/", r"\.gnupg/",
                    ],
                },
            },
        ],
    },

    # =========================================================================
    # SHELL EXEC — Very Strict
    # =========================================================================
    "shell_exec": {
        "name": "Shell Execution Security",
        "posture": "very_strict",
        "rules": [
            {
                "name": "{server_display} - Allow Safe Reads",
                "description": "Allow read-only shell commands via {server_display}",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:read|get|list|status|info|which|whoami|pwd|echo|cat|head|tail|wc|date).*",
                    ],
                },
            },
            {
                "name": "{server_display} - Approve Execution",
                "description": "Require approval for command execution via {server_display}",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:run|exec|execute|shell|command).*",
                    ],
                },
            },
            {
                "name": "{server_display} - Deny Dangerous",
                "description": "Block dangerous shell operations via {server_display}",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:delete|remove|kill|sudo|chmod|chown|rm|format|mkfs|dd).*",
                    ],
                },
            },
        ],
    },

    # =========================================================================
    # BROWSER AUTOMATION — Strict
    # =========================================================================
    "browser_automation": {
        "name": "Browser Automation Security",
        "posture": "strict",
        "rules": [
            {
                "name": "{server_display} - Allow Navigation",
                "description": "Allow browsing and screenshot operations for {server_display}",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:navigate|goto|screenshot|get_text|get_html|get_url|scroll|wait|evaluate|query_selector|extract).*",
                    ],
                },
            },
            {
                "name": "{server_display} - Approve Interactions",
                "description": "Require approval for form fills and clicks via {server_display}",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:click|fill|type|select|submit|upload|download|press|hover).*",
                    ],
                },
            },
            {
                "name": "{server_display} - Deny Destructive",
                "description": "Block destructive browser operations on {server_display}",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:delete|clear_cookies|clear_storage|close_all|inject|execute_script).*",
                    ],
                },
            },
        ],
    },

    # =========================================================================
    # NETWORK/HTTP — Moderate
    # =========================================================================
    "network_http": {
        "name": "Network/HTTP Security",
        "posture": "moderate",
        "rules": [
            {
                "name": "{server_display} - Allow Reads",
                "description": "Allow GET requests and searches via {server_display}",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:get|search|fetch|read|list|query|lookup|resolve|head|options).*",
                    ],
                },
            },
            {
                "name": "{server_display} - Approve Writes",
                "description": "Require approval for POST/PUT requests via {server_display}",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:post|put|patch|send|submit|create|upload|webhook).*",
                    ],
                },
            },
            {
                "name": "{server_display} - Deny Destructive",
                "description": "Block destructive network operations on {server_display}",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:delete|purge|remove|destroy).*",
                    ],
                },
            },
        ],
    },

    # =========================================================================
    # COMMUNICATION — Moderate
    # =========================================================================
    "communication": {
        "name": "Communication Security",
        "posture": "moderate",
        "rules": [
            {
                "name": "{server_display} - Allow Reads",
                "description": "Allow reading messages and channels on {server_display}",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:get|list|search|read|fetch|view|history|info|members|channels).*",
                    ],
                },
            },
            {
                "name": "{server_display} - Approve Sends",
                "description": "Require approval for sending messages via {server_display}",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:send|post|reply|create|update|react|pin|upload|share).*",
                    ],
                },
            },
            {
                "name": "{server_display} - Deny Admin/Destructive",
                "description": "Block admin and destructive operations on {server_display}",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:delete|remove|kick|ban|archive|destroy|admin|invite|permission).*",
                    ],
                },
            },
        ],
    },

    # =========================================================================
    # CLOUD INFRASTRUCTURE — Strict
    # =========================================================================
    "cloud_infra": {
        "name": "Cloud Infrastructure Security",
        "posture": "strict",
        "rules": [
            {
                "name": "{server_display} - Allow Describe/List",
                "description": "Allow read-only cloud resource operations for {server_display}",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:describe|list|get|show|inspect|status|info|check|view|logs).*",
                    ],
                },
            },
            {
                "name": "{server_display} - Approve Create/Update",
                "description": "Require approval for creating and updating cloud resources on {server_display}",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:create|update|deploy|scale|configure|modify|launch|start|restart|apply|plan).*",
                    ],
                },
            },
            {
                "name": "{server_display} - Deny Destructive",
                "description": "Block termination and deletion of cloud resources on {server_display}",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:delete|terminate|destroy|remove|deregister|detach|stop|shutdown|drain|force).*",
                    ],
                },
            },
        ],
    },

    # =========================================================================
    # IDENTITY/AUTH — Very Strict
    # =========================================================================
    "identity_auth": {
        "name": "Identity & Auth Security",
        "posture": "very_strict",
        "rules": [
            {
                "name": "{server_display} - Approve Reads",
                "description": "Require approval even for reading identity data on {server_display}",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 100,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:get|list|search|read|check|verify|validate|inspect).*",
                    ],
                },
            },
            {
                "name": "{server_display} - Deny Most Operations",
                "description": "Block write/modify operations on {server_display}",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:create|update|delete|modify|grant|revoke|reset|rotate|assign|remove|disable|enable|impersonate).*",
                    ],
                },
            },
        ],
    },

    # =========================================================================
    # PAYMENT/FINANCE — Maximum
    # =========================================================================
    "payment_finance": {
        "name": "Payment & Finance Security",
        "posture": "maximum",
        "rules": [
            {
                "name": "{server_display} - Approve All Reads",
                "description": "Require approval for reading financial data on {server_display}",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 100,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:get|list|search|read|view|fetch|check|balance|statement).*",
                    ],
                },
            },
            {
                "name": "{server_display} - Deny Writes",
                "description": "Block all financial write operations on {server_display}",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:charge|transfer|refund|payout|create|update|delete|cancel|void|reverse|withdraw|send).*",
                    ],
                },
            },
        ],
    },

    # =========================================================================
    # AI MODEL — Moderate
    # =========================================================================
    "ai_model": {
        "name": "AI Model Security",
        "posture": "moderate",
        "rules": [
            {
                "name": "{server_display} - Allow Queries",
                "description": "Allow inference and query operations on {server_display}",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:generate|complete|chat|embed|search|query|list|get|infer|predict|classify|summarize).*",
                    ],
                },
            },
            {
                "name": "{server_display} - Approve Training",
                "description": "Require approval for model training operations on {server_display}",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:train|fine_tune|upload|create|deploy|configure|update).*",
                    ],
                },
            },
            {
                "name": "{server_display} - Deny Destructive",
                "description": "Block model deletion on {server_display}",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:delete|remove|destroy|purge|undeploy).*",
                    ],
                },
            },
        ],
    },

    # =========================================================================
    # MONITORING — Low
    # =========================================================================
    "monitoring": {
        "name": "Monitoring Security",
        "posture": "low",
        "rules": [
            {
                "name": "{server_display} - Allow Reads",
                "description": "Allow reading metrics, logs, and alerts on {server_display}",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:get|list|search|query|read|view|fetch|check|status|metrics|logs|alerts|trace|dashboard).*",
                    ],
                },
            },
            {
                "name": "{server_display} - Approve Config Changes",
                "description": "Require approval for configuration changes on {server_display}",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:create|update|configure|set|enable|disable|mute|acknowledge).*",
                    ],
                },
            },
            {
                "name": "{server_display} - Deny Data Deletion",
                "description": "Block deletion of monitoring data on {server_display}",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:delete|remove|purge|destroy|wipe|truncate).*",
                    ],
                },
            },
        ],
    },

    # =========================================================================
    # GENERAL — Default fallback
    # =========================================================================
    "general": {
        "name": "General Security",
        "posture": "default",
        "rules": [
            {
                "name": "{server_display} - Allow Reads",
                "description": "Allow read-only operations for {server_display}",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:read|get|list|search|query|find|count|describe|fetch|view|show|status|info).*",
                    ],
                },
            },
            {
                "name": "{server_display} - Approve Writes",
                "description": "Require approval for write operations on {server_display}",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:write|create|update|send|post|set|put|add|edit|modify|upsert|insert).*",
                    ],
                },
            },
            {
                "name": "{server_display} - Deny Destructive",
                "description": "Block destructive operations on {server_display}",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:{server_key})__(?:delete|drop|destroy|remove|purge|truncate|kill|force).*",
                    ],
                },
            },
        ],
    },
}


def generate_rules_from_category(
    category: str,
    server_key: str,
    server_display: str,
) -> list[dict]:
    """Generate rule definitions from a category template.

    Expands {server_key} and {server_display} placeholders in the template.
    Returns a list of rule dicts ready for rule creation.
    """
    template = CATEGORY_RULE_TEMPLATES.get(category)
    if not template:
        template = CATEGORY_RULE_TEMPLATES["general"]

    rules = []
    for rule_tmpl in template["rules"]:
        rule = _expand_template(rule_tmpl, server_key, server_display)
        rule["id"] = f"{server_key}-cat-{rule['action']}-{len(rules)}"
        rules.append(rule)

    return rules


def _expand_template(
    template: dict,
    server_key: str,
    server_display: str,
) -> dict:
    """Expand placeholders in a rule template."""
    import copy
    import re as _re

    rule = copy.deepcopy(template)

    # Escape server_key for use in regex patterns
    escaped_key = _re.escape(server_key)

    def _replace(val):
        if isinstance(val, str):
            return val.replace("{server_key}", escaped_key).replace(
                "{server_display}", server_display
            )
        elif isinstance(val, list):
            return [_replace(v) for v in val]
        elif isinstance(val, dict):
            return {k: _replace(v) for k, v in val.items()}
        return val

    return _replace(rule)


def get_category_info(category: str) -> dict:
    """Get display info for a security category."""
    from app.services.server_classifier import SECURITY_CATEGORIES

    template = CATEGORY_RULE_TEMPLATES.get(category, CATEGORY_RULE_TEMPLATES["general"])
    return {
        "category": category,
        "name": template["name"],
        "posture": template["posture"],
        "description": SECURITY_CATEGORIES.get(category, ""),
        "rule_count": len(template["rules"]),
    }


def get_all_categories() -> list[dict]:
    """Get info for all security categories."""
    return [get_category_info(cat) for cat in CATEGORY_RULE_TEMPLATES]
