"""Curated rule packs for known MCP servers and integrations.

Each pack contains expert-crafted security rules with patterns matching
real MCP tool names. Used by traffic discovery (for known servers) and
the "Add MCP Server" manual path.

Patterns match both Claude-style (mcp__server__tool) and OpenClaw-style
(server_tool) naming conventions, as well as bare CLI commands.
"""

from typing import Any

# Pack structure:
# - name: Display name
# - description: What this integration does
# - icon: Emoji or icon identifier
# - category: Group for UI organization
# - mcp_matcher: Regex for matching tool names to this pack
# - rules: List of rule definitions to create when enabled

RULE_PACKS: dict[str, dict[str, Any]] = {
    # =========================================================================
    # SYSTEM
    # =========================================================================
    "shell": {
        "name": "Shell/Bash",
        "description": "Command line shell access — safe read commands, git, and dangerous command blocking",
        "icon": "💻",
        "category": "system",
        "mcp_matcher": "^(bash|exec)$|^Bash$",
        "rules": [
            {
                "id": "shell-safe-allowlist",
                "name": "Shell - Allow Safe Commands",
                "description": "Allow common read-only commands",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": [
                        "^ls\\b",
                        "^cat\\b",
                        "^head\\b",
                        "^tail\\b",
                        "^grep\\b",
                        "^find\\b",
                        "^pwd$",
                        "^whoami$",
                        "^date$",
                        "^echo\\b",
                        "^wc\\b",
                    ],
                }
            },
            {
                "id": "shell-git-read-allowlist",
                "name": "Shell - Allow Git Read",
                "description": "Allow git status, log, diff commands",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 95,
                "parameters": {
                    "patterns": [
                        "^git\\s+(status|log|diff|show|branch|remote|tag)\\b",
                    ],
                }
            },
            {
                "id": "shell-git-write-approval",
                "name": "Shell - Approval for Git Write",
                "description": "Require approval for git commits, push",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": [
                        "^git\\s+(add|commit|push|pull|merge|rebase|checkout)\\b",
                    ],
                }
            },
            {
                "id": "shell-block-dangerous",
                "name": "Shell - Block Dangerous Commands",
                "description": "Block rm -rf, sudo, format, etc.",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": [
                        "rm\\s+-rf",
                        "rm\\s+-r\\s+/",
                        "^sudo\\b",
                        "^su\\b",
                        "mkfs",
                        "dd\\s+if=",
                        ":(){ :|:& };:",
                        "chmod\\s+-R\\s+777",
                        "curl.*\\|.*sh",
                        "wget.*\\|.*sh",
                    ],
                }
            },
        ]
    },

    "filesystem": {
        "name": "Filesystem",
        "description": "Local file system access via MCP filesystem server or built-in tools",
        "icon": "📂",
        "category": "system",
        "mcp_matcher": "^mcp__filesystem__.*|^mcp__fs__.*|^(read|write)$",
        "rules": [
            {
                "id": "filesystem-read-allowlist",
                "name": "Filesystem - Allow Read Operations",
                "description": "Allow reading files and listing directories",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:filesystem|fs)__(?:read|list|search|get|directory_tree|stat).*",
                        "^filesystem_(?:read|list|search|get).*",
                        "^fs_(?:read|list|stat).*",
                    ],
                }
            },
            {
                "id": "filesystem-write-approval",
                "name": "Filesystem - Approval for Write",
                "description": "Require approval for creating/modifying files",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:filesystem|fs)__(?:write|create|edit|move|mkdir|append).*",
                        "^filesystem_(?:write|create|edit|move).*",
                        "^fs_(?:write|create|mkdir).*",
                    ],
                }
            },
            {
                "id": "filesystem-block-delete",
                "name": "Filesystem - Block Delete",
                "description": "Block file and directory deletion",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:filesystem|fs)__(?:delete|remove|rmdir).*",
                        "^filesystem_(?:delete|remove).*",
                        "^fs_(?:delete|remove|rmdir).*",
                    ],
                }
            },
            {
                "id": "filesystem-block-sensitive",
                "name": "Filesystem - Block Sensitive Paths",
                "description": "Block access to sensitive system paths",
                "rule_type": "credential_protection",
                "action": "deny",
                "priority": 250,
                "parameters": {
                    "patterns": [
                        ".*\\.env.*",
                        ".*credentials.*",
                        ".*\\.ssh/.*",
                        ".*\\.aws/.*",
                        ".*/etc/passwd",
                        ".*/etc/shadow",
                    ],
                }
            },
        ]
    },

    # =========================================================================
    # DEVELOPER
    # =========================================================================
    "github": {
        "name": "GitHub",
        "description": "Code hosting and collaboration via GitHub MCP server or git CLI",
        "icon": "🐙",
        "category": "developer",
        "mcp_matcher": "^mcp__(?:github|gh)__.*|^github_.*|^git\\s+",
        "selectable_rules": True,
        "rules": [
            {
                "id": "github-read",
                "name": "GitHub - Read Repos & Issues",
                "description": "View repos, files, issues, PRs, branches, commits",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "default_enabled": True,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:github|gh)__(?:get|list|search|read|issue_read|pull_request_read).*",
                        "^github_(?:get|list|search|read).*",
                    ],
                }
            },
            {
                "id": "github-comment",
                "name": "GitHub - Comment on Issues/PRs",
                "description": "Add comments, reply to discussions",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 95,
                "default_enabled": True,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:github|gh)__(?:add_issue_comment|add_comment|add_reply).*",
                        "^github_(?:comment|add_comment).*",
                    ],
                }
            },
            {
                "id": "github-write",
                "name": "GitHub - Create/Update (Issues, PRs, Commits)",
                "description": "Create issues, PRs, push commits, merge",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "default_enabled": True,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:github|gh)__(?:create|update|push|merge|issue_write|pull_request_review_write|commit).*",
                        "^github_(?:create|update|push|merge|commit).*",
                    ],
                }
            },
            {
                "id": "github-block-destructive",
                "name": "GitHub - Block Destructive Operations",
                "description": "Block force push, delete repos/branches, change protections",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "default_enabled": True,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:github|gh)__(?:delete|force_push|remove|disable_protection|update_branch_protection).*",
                        "^github_(?:delete|force_push|remove).*",
                    ],
                }
            },
        ]
    },

    # =========================================================================
    # NETWORK
    # =========================================================================
    "browser": {
        "name": "Browser",
        "description": "Web browsing via Playwright, Puppeteer MCP servers, or built-in browser tool",
        "icon": "🌐",
        "category": "network",
        "mcp_matcher": "^browser$|^mcp__(?:puppeteer|playwright)__.*",
        "rules": [
            {
                "id": "browser-navigate-allow",
                "name": "Browser - Allow Navigation & Read",
                "description": "Allow navigating, screenshots, reading page content",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": [
                        "^browser$",
                        "^mcp__(?:puppeteer|playwright)__(?:puppeteer_)?(?:navigate|screenshot|snapshot|evaluate|console_messages|network_requests|tabs|browser_snapshot).*",
                        "^mcp__(?:puppeteer|playwright)__browser_(?:navigate|take_screenshot|snapshot|evaluate|console|network|tabs|wait).*",
                    ],
                }
            },
            {
                "id": "browser-interact-approval",
                "name": "Browser - Approval for Interactions",
                "description": "Require approval for clicking, typing, form fills",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:puppeteer|playwright)__(?:puppeteer_)?(?:click|fill|select|type|hover|drag|press|file_upload|handle_dialog).*",
                        "^mcp__(?:puppeteer|playwright)__browser_(?:click|type|fill|select|hover|drag|press|file_upload|handle_dialog|run_code).*",
                    ],
                }
            },
            {
                "id": "browser-block-dangerous",
                "name": "Browser - Block Dangerous Actions",
                "description": "Block closing browser, running arbitrary code outside sandbox",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:puppeteer|playwright)__(?:browser_close|browser_install)$",
                    ],
                }
            },
        ]
    },

    "network": {
        "name": "Network / HTTP",
        "description": "HTTP requests, web fetching, and search via CLI or MCP servers",
        "icon": "🔗",
        "category": "network",
        "mcp_matcher": "^(curl|wget|http)\\b|^mcp__fetch__.*|^web_(?:fetch|search)$",
        "rules": [
            {
                "id": "network-fetch-allow",
                "name": "Network - Allow Fetch & Search",
                "description": "Allow web fetching and search operations",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": [
                        "^mcp__fetch__fetch$",
                        "^mcp__(?:brave-search|exa)__.*(?:search|crawl|research).*",
                        "^web_(?:fetch|search)$",
                        "^curl\\s+.*(?:-s|-o|--silent|--output).*",
                        "^wget\\s+",
                    ],
                }
            },
            {
                "id": "network-post-approval",
                "name": "Network - Approval for POST/PUT/DELETE",
                "description": "Require approval for mutating HTTP requests",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": [
                        "^curl\\s+.*(?:-X\\s*(?:POST|PUT|DELETE|PATCH)|--data|-d\\s).*",
                    ],
                }
            },
        ]
    },

    # =========================================================================
    # CLOUD
    # =========================================================================
    "aws": {
        "name": "AWS",
        "description": "Amazon Web Services via MCP server or aws CLI",
        "icon": "☁️",
        "category": "cloud",
        "mcp_matcher": "^mcp__aws__.*|^aws\\s+|^aws_.*",
        "rules": [
            {
                "id": "aws-read-allowlist",
                "name": "AWS - Allow Read Operations",
                "description": "Allow describing and listing resources",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": [
                        "^mcp__aws__(?:.*(?:read|get|list|describe|search|retrieve|recommend)).*",
                        "^aws\\s+(?:s3\\s+ls|ec2\\s+describe|iam\\s+list|sts\\s+get).*",
                        "^aws_(?:describe|get|list).*",
                    ],
                }
            },
            {
                "id": "aws-create-approval",
                "name": "AWS - Approval for Create/Modify",
                "description": "Require approval for creating or modifying resources",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": [
                        "^mcp__aws__(?:.*(?:create|put|run|start|launch|update|modify)).*",
                        "^aws\\s+(?:s3\\s+cp|s3\\s+sync|ec2\\s+run|lambda\\s+create).*",
                        "^aws_(?:create|put|run|start).*",
                    ],
                }
            },
            {
                "id": "aws-block-destructive",
                "name": "AWS - Block Destructive Operations",
                "description": "Block delete, terminate, and IAM changes",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": [
                        "^mcp__aws__(?:.*(?:delete|terminate|destroy|remove|drop)).*",
                        "^aws\\s+(?:.*(?:delete|terminate|remove)).*",
                        "^aws_(?:delete|terminate|destroy|remove|iam).*",
                    ],
                }
            },
        ]
    },

    "database": {
        "name": "Database",
        "description": "PostgreSQL, SQLite, MongoDB via MCP servers",
        "icon": "🗄️",
        "category": "cloud",
        "mcp_matcher": "^mcp__(?:postgres|postgresql|sqlite|mongo|mongodb|supabase|neon)__.*",
        "rules": [
            {
                "id": "database-read-allowlist",
                "name": "Database - Allow Read Operations",
                "description": "Allow SELECT queries, listing tables, describing schema",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:postgres|postgresql|sqlite|mongo|mongodb|supabase|neon)__(?:query|read_query|read|select|find|list|describe|get|aggregate|count|search).*",
                        "^(?:postgres|sqlite|mongo|supabase|neon)_(?:select|read|query|find|list|get|count).*",
                    ],
                }
            },
            {
                "id": "database-write-approval",
                "name": "Database - Approval for Write",
                "description": "Require approval for INSERT/UPDATE and schema changes",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:postgres|postgresql|sqlite|mongo|mongodb|supabase|neon)__(?:write_query|write|insert|update|upsert|create_table|append).*",
                        "^(?:postgres|sqlite|mongo|supabase|neon)_(?:insert|update|write|upsert|create).*",
                    ],
                }
            },
            {
                "id": "database-block-destructive",
                "name": "Database - Block Destructive Operations",
                "description": "Block DELETE, DROP, TRUNCATE",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:postgres|postgresql|sqlite|mongo|mongodb|supabase|neon)__(?:delete|drop|truncate|alter|remove|destroy).*",
                        "^(?:postgres|sqlite|mongo|supabase|neon)_(?:delete|drop|truncate|alter|remove).*",
                    ],
                }
            },
        ]
    },

    # =========================================================================
    # COMMUNICATION
    # =========================================================================
    "slack": {
        "name": "Slack",
        "description": "Team messaging via Slack MCP server",
        "icon": "💬",
        "category": "communication",
        "mcp_matcher": "^mcp__slack__.*|^slack_.*",
        "selectable_rules": True,
        "rules": [
            {
                "id": "slack-read",
                "name": "Slack - Read Channels & Users",
                "description": "View channels, messages, users, reactions",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "default_enabled": True,
                "parameters": {
                    "patterns": [
                        "^mcp__slack__slack_(?:list_channels|get_channel_history|get_thread_replies|get_users|get_user_profile|search).*",
                        "^slack_(?:list|get|read|search).*",
                    ],
                }
            },
            {
                "id": "slack-message",
                "name": "Slack - Post Messages & React",
                "description": "Send messages, reply to threads, add reactions",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "default_enabled": True,
                "parameters": {
                    "patterns": [
                        "^mcp__slack__slack_(?:post_message|reply_to_thread|add_reaction).*",
                        "^slack_(?:post|send|reply|add_reaction|message).*",
                    ],
                }
            },
            {
                "id": "slack-block-admin",
                "name": "Slack - Block Admin Operations",
                "description": "Prevent channel management, user admin",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "default_enabled": True,
                "parameters": {
                    "patterns": [
                        "^mcp__slack__slack_(?:create_channel|delete_channel|archive|invite|kick|remove).*",
                        "^slack_(?:create_channel|delete|archive|invite|kick|remove).*",
                    ],
                }
            },
        ]
    },

    "gmail": {
        "name": "Gmail / Email",
        "description": "Email management via Gmail MCP server",
        "icon": "📧",
        "category": "communication",
        "mcp_matcher": "^mcp__(?:gmail|google-mail|google.mail)__.*|^gmail_.*",
        "rules": [
            {
                "id": "gmail-read-allowlist",
                "name": "Gmail - Allow Read Operations",
                "description": "Allow reading emails, listing messages, searching",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:gmail|google-mail|google.mail)__(?:read|get|list|search|query).*",
                        "^gmail_(?:read|get|list|search).*",
                    ],
                }
            },
            {
                "id": "gmail-send-approval",
                "name": "Gmail - Approval for Send/Draft",
                "description": "Require approval before sending emails or creating drafts",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:gmail|google-mail|google.mail)__(?:send|create|draft|compose|reply|forward).*",
                        "^gmail_(?:send|draft|compose|reply|forward).*",
                    ],
                }
            },
            {
                "id": "gmail-block-delete",
                "name": "Gmail - Block Delete",
                "description": "Block permanent email deletion",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": [
                        "^mcp__(?:gmail|google-mail|google.mail)__(?:delete|trash|purge|remove).*",
                        "^gmail_(?:delete|trash|purge|remove).*",
                    ],
                }
            },
        ]
    },
}

# Categories for UI organization
RULE_PACK_CATEGORIES = {
    "system": {
        "name": "System",
        "description": "Shell, filesystem, and local tools",
        "icon": "💻",
    },
    "developer": {
        "name": "Developer",
        "description": "Code hosting and version control",
        "icon": "🛠️",
    },
    "network": {
        "name": "Network",
        "description": "HTTP, browser, and API calls",
        "icon": "🌐",
    },
    "cloud": {
        "name": "Cloud",
        "description": "Cloud services and databases",
        "icon": "☁️",
    },
    "communication": {
        "name": "Communication",
        "description": "Email and messaging",
        "icon": "💬",
    },
}


def get_packs_by_category() -> dict[str, list[dict]]:
    """Get rule packs organized by category."""
    result = {}
    for category_id, category_info in RULE_PACK_CATEGORIES.items():
        packs = [
            {
                "id": pack_id,
                **pack_data,
            }
            for pack_id, pack_data in RULE_PACKS.items()
            if pack_data.get("category") == category_id
        ]
        if packs:
            result[category_id] = {
                "info": category_info,
                "packs": packs,
            }
    return result


def get_rule_pack(pack_id: str) -> dict | None:
    """Get a specific rule pack by ID."""
    return RULE_PACKS.get(pack_id)
