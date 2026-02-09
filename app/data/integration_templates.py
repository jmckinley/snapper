"""Pre-built rule templates for popular integrations.

These templates provide sensible security defaults for common MCP servers
and can be enabled with one click from the dashboard.
"""

from typing import Any

# Template structure:
# - name: Display name
# - description: What this integration does
# - icon: Emoji or icon identifier
# - category: Group for UI organization
# - rules: List of rule definitions to create when enabled

INTEGRATION_TEMPLATES: dict[str, dict[str, Any]] = {
    # =========================================================================
    # COMMUNICATION
    # =========================================================================
    "gmail": {
        "name": "Gmail",
        "description": "Email management via Gmail API",
        "icon": "📧",
        "category": "communication",
        "mcp_matcher": "mcp__gmail__.*",
        "rules": [
            {
                "id": "gmail-read-allowlist",
                "name": "Gmail - Allow Read Operations",
                "description": "Allow reading emails, listing messages, searching",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["gmail_read", "gmail_list", "gmail_search"],
                    "description": "Read-only Gmail operations"
                }
            },
            {
                "id": "gmail-send-approval",
                "name": "Gmail - Approval for Send",
                "description": "Require approval before sending emails",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": ["gmail_send"],
                    "description": "Sending emails requires human approval"
                }
            },
            {
                "id": "gmail-draft-approval",
                "name": "Gmail - Approval for Draft",
                "description": "Require approval for creating drafts",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 85,
                "parameters": {
                    "patterns": ["gmail_draft"],
                    "description": "Creating drafts requires approval"
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
                    "patterns": ["gmail_delete"],
                    "description": "Deleting emails is blocked for safety"
                }
            },
        ]
    },

    "slack": {
        "name": "Slack",
        "description": "Team messaging and collaboration",
        "icon": "💬",
        "category": "communication",
        "mcp_matcher": "slack_.*",
        "selectable_rules": True,
        "rules": [
            {
                "id": "list_channels",
                "name": "Slack - List Channels",
                "description": "View public channels in the workspace",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "default_enabled": True,
                "parameters": {
                    "patterns": ["slack_list_channels"],
                }
            },
            {
                "id": "read_channel",
                "name": "Slack - Read Channel Messages",
                "description": "Read message history from channels",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 99,
                "default_enabled": True,
                "parameters": {
                    "patterns": ["slack_read_channel"],
                }
            },
            {
                "id": "list_users",
                "name": "Slack - List Users",
                "description": "View workspace members",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 98,
                "default_enabled": True,
                "parameters": {
                    "patterns": ["slack_list_users"],
                }
            },
            {
                "id": "search",
                "name": "Slack - Search Messages",
                "description": "Search for messages across channels",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 97,
                "default_enabled": True,
                "parameters": {
                    "patterns": ["slack_search"],
                }
            },
            {
                "id": "post_message",
                "name": "Slack - Post Messages",
                "description": "Send messages to channels",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "default_enabled": True,
                "parameters": {
                    "patterns": ["slack_post_message"],
                }
            },
            {
                "id": "add_reaction",
                "name": "Slack - Add Reactions",
                "description": "Add emoji reactions to messages",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 85,
                "default_enabled": True,
                "parameters": {
                    "patterns": ["slack_add_reaction"],
                }
            },
            {
                "id": "block_channel_mgmt",
                "name": "Slack - Block Channel Management",
                "description": "Prevent creating/deleting/archiving channels",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "default_enabled": True,
                "parameters": {
                    "patterns": ["slack_create_channel", "slack_delete_channel", "slack_archive_channel"],
                }
            },
            {
                "id": "block_user_mgmt",
                "name": "Slack - Block User Management",
                "description": "Prevent inviting/removing users",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "default_enabled": True,
                "parameters": {
                    "patterns": ["slack_invite_user", "slack_kick_user", "slack_remove_user"],
                }
            },
        ]
    },

    "telegram": {
        "name": "Telegram",
        "description": "Telegram messaging platform",
        "icon": "✈️",
        "category": "communication",
        "mcp_matcher": "mcp__telegram__.*",
        "rules": [
            {
                "id": "telegram-read-allowlist",
                "name": "Telegram - Allow Read Operations",
                "description": "Allow reading messages and chat info",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["telegram_read", "telegram_get", "telegram_list"],
                    "description": "Read-only Telegram operations"
                }
            },
            {
                "id": "telegram-send-approval",
                "name": "Telegram - Approval for Send",
                "description": "Require approval before sending messages",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": ["telegram_send", "telegram_message"],
                    "description": "Sending messages requires approval"
                }
            },
            {
                "id": "telegram-block-delete",
                "name": "Telegram - Block Delete",
                "description": "Block message deletion",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": ["telegram_delete"],
                    "description": "Deleting messages is blocked"
                }
            },
        ]
    },

    "discord": {
        "name": "Discord",
        "description": "Discord server and messaging",
        "icon": "🎮",
        "category": "communication",
        "mcp_matcher": "mcp__discord__.*",
        "rules": [
            {
                "id": "discord-read-allowlist",
                "name": "Discord - Allow Read Operations",
                "description": "Allow reading messages, channels, servers",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["discord_read", "discord_get", "discord_list"],
                    "description": "Read-only Discord operations"
                }
            },
            {
                "id": "discord-message-approval",
                "name": "Discord - Approval for Messages",
                "description": "Require approval before sending messages",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": ["discord_send", "discord_message", "discord_reply"],
                    "description": "Sending messages requires approval"
                }
            },
            {
                "id": "discord-block-admin",
                "name": "Discord - Block Admin Operations",
                "description": "Block server admin operations",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": ["discord_ban", "discord_kick", "discord_delete_channel", "discord_create_role"],
                    "description": "Admin operations are blocked"
                }
            },
        ]
    },

    # =========================================================================
    # PRODUCTIVITY
    # =========================================================================
    "google_calendar": {
        "name": "Google Calendar",
        "description": "Calendar and event management",
        "icon": "📅",
        "category": "productivity",
        "mcp_matcher": "mcp__google_calendar__.*|mcp__gcal__.*",
        "rules": [
            {
                "id": "google_calendar-read-allowlist",
                "name": "Calendar - Allow Read Operations",
                "description": "Allow viewing calendars and events",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["calendar_read", "calendar_get", "calendar_list", "gcal_read", "gcal_get", "gcal_list"],
                    "description": "Read-only calendar operations"
                }
            },
            {
                "id": "google_calendar-write-approval",
                "name": "Calendar - Approval for Create/Update",
                "description": "Require approval for creating or modifying events",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": ["calendar_create", "calendar_update", "gcal_create", "gcal_update"],
                    "description": "Creating/updating events requires approval"
                }
            },
            {
                "id": "google_calendar-delete-approval",
                "name": "Calendar - Approval for Delete",
                "description": "Require approval before deleting events",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 85,
                "parameters": {
                    "patterns": ["calendar_delete", "gcal_delete"],
                    "description": "Deleting events requires approval"
                }
            },
        ]
    },

    "google_drive": {
        "name": "Google Drive",
        "description": "File storage and collaboration",
        "icon": "📁",
        "category": "productivity",
        "mcp_matcher": "mcp__google_drive__.*|mcp__gdrive__.*",
        "rules": [
            {
                "id": "google_drive-read-allowlist",
                "name": "Drive - Allow Read Operations",
                "description": "Allow listing and reading files",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["drive_read", "drive_get", "drive_list", "drive_search", "gdrive_read", "gdrive_get", "gdrive_list"],
                    "description": "Read-only Drive operations"
                }
            },
            {
                "id": "google_drive-upload-approval",
                "name": "Drive - Approval for Upload/Create",
                "description": "Require approval for uploading files",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": ["drive_upload", "drive_create", "gdrive_upload", "gdrive_create"],
                    "description": "Uploading files requires approval"
                }
            },
            {
                "id": "google_drive-block-delete",
                "name": "Drive - Block Delete",
                "description": "Block file deletion",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": ["drive_delete", "gdrive_delete", "drive_trash"],
                    "description": "Deleting files is blocked"
                }
            },
            {
                "id": "google_drive-block-sharing",
                "name": "Drive - Block Sharing Changes",
                "description": "Block changing file sharing permissions",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": ["drive_share", "drive_permission", "gdrive_share"],
                    "description": "Changing sharing is blocked"
                }
            },
        ]
    },

    "notion": {
        "name": "Notion",
        "description": "Workspace and documentation",
        "icon": "📝",
        "category": "productivity",
        "mcp_matcher": "mcp__notion__.*",
        "rules": [
            {
                "id": "notion-read-allowlist",
                "name": "Notion - Allow Read Operations",
                "description": "Allow reading pages, databases, blocks",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["notion_read", "notion_get", "notion_list", "notion_search", "notion_query"],
                    "description": "Read-only Notion operations"
                }
            },
            {
                "id": "notion-write-approval",
                "name": "Notion - Approval for Write",
                "description": "Require approval for creating/updating content",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": ["notion_create", "notion_update", "notion_append"],
                    "description": "Writing content requires approval"
                }
            },
            {
                "id": "notion-block-delete",
                "name": "Notion - Block Delete",
                "description": "Block page/database deletion",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": ["notion_delete", "notion_archive"],
                    "description": "Deleting content is blocked"
                }
            },
        ]
    },

    "linear": {
        "name": "Linear",
        "description": "Issue tracking and project management",
        "icon": "📋",
        "category": "productivity",
        "mcp_matcher": "mcp__linear__.*",
        "rules": [
            {
                "id": "linear-read-allowlist",
                "name": "Linear - Allow Read Operations",
                "description": "Allow reading issues, projects, teams",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["linear_read", "linear_get", "linear_list", "linear_search"],
                    "description": "Read-only Linear operations"
                }
            },
            {
                "id": "linear-update-allowlist",
                "name": "Linear - Allow Issue Updates",
                "description": "Allow updating issue status and comments",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 90,
                "parameters": {
                    "patterns": ["linear_update_issue", "linear_comment"],
                    "description": "Issue updates are allowed"
                }
            },
            {
                "id": "linear-create-approval",
                "name": "Linear - Approval for Create",
                "description": "Require approval for creating issues",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 85,
                "parameters": {
                    "patterns": ["linear_create"],
                    "description": "Creating issues requires approval"
                }
            },
            {
                "id": "linear-block-delete",
                "name": "Linear - Block Delete",
                "description": "Block issue deletion",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": ["linear_delete"],
                    "description": "Deleting issues is blocked"
                }
            },
        ]
    },

    # =========================================================================
    # DEVELOPER TOOLS
    # =========================================================================
    "github": {
        "name": "GitHub",
        "description": "Code hosting and collaboration",
        "icon": "🐙",
        "category": "developer",
        "mcp_matcher": "mcp__github__.*",
        "selectable_rules": True,  # Allow users to pick individual rules
        "rules": [
            {
                "id": "read",
                "name": "GitHub - Read Repos & Code",
                "description": "View repositories, files, branches, commits",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "default_enabled": True,
                "parameters": {
                    "patterns": ["github_read", "github_get_repo", "github_get_file", "github_list_repos", "github_list_branches", "github_list_commits", "github_search_code"],
                }
            },
            {
                "id": "read_issues",
                "name": "GitHub - Read Issues & PRs",
                "description": "View issues, pull requests, and discussions",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 99,
                "default_enabled": True,
                "parameters": {
                    "patterns": ["github_list_issues", "github_get_issue", "github_list_prs", "github_get_pr", "github_list_reviews"],
                }
            },
            {
                "id": "comment",
                "name": "GitHub - Comment on Issues/PRs",
                "description": "Add comments to issues and pull requests",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 95,
                "default_enabled": True,
                "parameters": {
                    "patterns": ["github_comment", "github_add_comment", "github_create_comment"],
                }
            },
            {
                "id": "review",
                "name": "GitHub - Review Pull Requests",
                "description": "Submit PR reviews (approve, request changes)",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 94,
                "default_enabled": True,
                "parameters": {
                    "patterns": ["github_review", "github_submit_review", "github_approve_pr"],
                }
            },
            {
                "id": "create_issue",
                "name": "GitHub - Create Issues",
                "description": "Create new issues in repositories",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "default_enabled": True,
                "parameters": {
                    "patterns": ["github_create_issue"],
                }
            },
            {
                "id": "update_issue",
                "name": "GitHub - Update Issues",
                "description": "Edit, close, or reopen issues",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 89,
                "default_enabled": True,
                "parameters": {
                    "patterns": ["github_update_issue", "github_close_issue", "github_reopen_issue", "github_edit_issue"],
                }
            },
            {
                "id": "create_pr",
                "name": "GitHub - Create Pull Requests",
                "description": "Create new pull requests",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 88,
                "default_enabled": True,
                "parameters": {
                    "patterns": ["github_create_pr", "github_create_pull_request"],
                }
            },
            {
                "id": "commit",
                "name": "GitHub - Commit Changes",
                "description": "Create commits (via API)",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 85,
                "default_enabled": True,
                "parameters": {
                    "patterns": ["github_commit", "github_create_commit"],
                }
            },
            {
                "id": "push",
                "name": "GitHub - Push to Branches",
                "description": "Push commits to repository branches",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 84,
                "default_enabled": True,
                "parameters": {
                    "patterns": ["github_push", "github_push_files", "github_create_or_update_file"],
                }
            },
            {
                "id": "create_branch",
                "name": "GitHub - Create Branches",
                "description": "Create new branches",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 83,
                "default_enabled": True,
                "parameters": {
                    "patterns": ["github_create_branch"],
                }
            },
            {
                "id": "merge",
                "name": "GitHub - Merge Pull Requests",
                "description": "Merge PRs into target branches",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 80,
                "default_enabled": True,
                "parameters": {
                    "patterns": ["github_merge", "github_merge_pr", "github_merge_pull_request"],
                }
            },
            {
                "id": "create_release",
                "name": "GitHub - Create Releases",
                "description": "Create releases and tags",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 79,
                "default_enabled": False,
                "parameters": {
                    "patterns": ["github_create_release", "github_create_tag"],
                }
            },
            {
                "id": "block_force_push",
                "name": "GitHub - Block Force Push",
                "description": "Prevent force pushing (rewrites history)",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "default_enabled": True,
                "parameters": {
                    "patterns": ["github_force_push", "github_push_force"],
                }
            },
            {
                "id": "block_delete_repo",
                "name": "GitHub - Block Delete Repository",
                "description": "Prevent repository deletion",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "default_enabled": True,
                "parameters": {
                    "patterns": ["github_delete_repo", "github_delete_repository"],
                }
            },
            {
                "id": "block_delete_branch",
                "name": "GitHub - Block Delete Branches",
                "description": "Prevent branch deletion",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 199,
                "default_enabled": True,
                "parameters": {
                    "patterns": ["github_delete_branch"],
                }
            },
            {
                "id": "block_protection_changes",
                "name": "GitHub - Block Branch Protection Changes",
                "description": "Prevent modifying branch protection rules",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "default_enabled": True,
                "parameters": {
                    "patterns": ["github_update_branch_protection", "github_delete_branch_protection", "github_disable_protection"],
                }
            },
        ]
    },

    "gitlab": {
        "name": "GitLab",
        "description": "DevOps platform",
        "icon": "🦊",
        "category": "developer",
        "mcp_matcher": "mcp__gitlab__.*",
        "rules": [
            {
                "id": "gitlab-read-allowlist",
                "name": "GitLab - Allow Read Operations",
                "description": "Allow reading projects, issues, MRs",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["gitlab_read", "gitlab_get", "gitlab_list", "gitlab_search"],
                    "description": "Read-only GitLab operations"
                }
            },
            {
                "id": "gitlab-write-approval",
                "name": "GitLab - Approval for Write",
                "description": "Require approval for creating/updating",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": ["gitlab_create", "gitlab_update", "gitlab_push"],
                    "description": "Write operations require approval"
                }
            },
            {
                "id": "gitlab-block-dangerous",
                "name": "GitLab - Block Dangerous Operations",
                "description": "Block destructive operations",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": ["gitlab_delete", "gitlab_force_push"],
                    "description": "Dangerous operations are blocked"
                }
            },
        ]
    },

    "jira": {
        "name": "Jira",
        "description": "Project and issue tracking",
        "icon": "🎫",
        "category": "developer",
        "mcp_matcher": "mcp__jira__.*",
        "rules": [
            {
                "id": "jira-read-allowlist",
                "name": "Jira - Allow Read Operations",
                "description": "Allow reading issues, projects, boards",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["jira_read", "jira_get", "jira_list", "jira_search"],
                    "description": "Read-only Jira operations"
                }
            },
            {
                "id": "jira-status-allowlist",
                "name": "Jira - Allow Status Updates",
                "description": "Allow updating issue status and comments",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 95,
                "parameters": {
                    "patterns": ["jira_transition", "jira_comment"],
                    "description": "Status updates are allowed"
                }
            },
            {
                "id": "jira-create-approval",
                "name": "Jira - Approval for Create",
                "description": "Require approval for creating issues",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": ["jira_create"],
                    "description": "Creating issues requires approval"
                }
            },
            {
                "id": "jira-block-delete",
                "name": "Jira - Block Delete",
                "description": "Block issue deletion",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": ["jira_delete"],
                    "description": "Deleting issues is blocked"
                }
            },
        ]
    },

    # =========================================================================
    # CLOUD & INFRASTRUCTURE
    # =========================================================================
    "aws": {
        "name": "AWS",
        "description": "Amazon Web Services",
        "icon": "☁️",
        "category": "cloud",
        "mcp_matcher": "mcp__aws__.*",
        "rules": [
            {
                "id": "aws-read-allowlist",
                "name": "AWS - Allow Read Operations",
                "description": "Allow describing and listing resources",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["aws_describe", "aws_get", "aws_list"],
                    "description": "Read-only AWS operations"
                }
            },
            {
                "id": "aws-create-approval",
                "name": "AWS - Approval for Create",
                "description": "Require approval for creating resources",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": ["aws_create", "aws_put", "aws_run"],
                    "description": "Creating resources requires approval"
                }
            },
            {
                "id": "aws-block-destructive",
                "name": "AWS - Block Destructive Operations",
                "description": "Block delete, terminate, and dangerous operations",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": ["aws_delete", "aws_terminate", "aws_destroy", "aws_remove"],
                    "description": "Destructive operations are blocked"
                }
            },
            {
                "id": "aws-block-iam",
                "name": "AWS - Block IAM Changes",
                "description": "Block IAM policy and role modifications",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": ["aws_iam_create", "aws_iam_delete", "aws_iam_attach", "aws_iam_detach"],
                    "description": "IAM changes are blocked"
                }
            },
        ]
    },

    "kubernetes": {
        "name": "Kubernetes",
        "description": "Container orchestration",
        "icon": "⎈",
        "category": "cloud",
        "mcp_matcher": "mcp__kubernetes__.*|mcp__k8s__.*",
        "rules": [
            {
                "id": "kubernetes-read-allowlist",
                "name": "K8s - Allow Read Operations",
                "description": "Allow getting and listing resources",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["k8s_get", "k8s_list", "k8s_describe", "kubernetes_get", "kubernetes_list"],
                    "description": "Read-only K8s operations"
                }
            },
            {
                "id": "kubernetes-apply-approval",
                "name": "K8s - Approval for Apply",
                "description": "Require approval for applying manifests",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": ["k8s_apply", "k8s_create", "kubernetes_apply", "kubernetes_create"],
                    "description": "Applying changes requires approval"
                }
            },
            {
                "id": "kubernetes-block-delete",
                "name": "K8s - Block Delete",
                "description": "Block resource deletion",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": ["k8s_delete", "kubernetes_delete"],
                    "description": "Deleting resources is blocked"
                }
            },
        ]
    },

    "docker": {
        "name": "Docker",
        "description": "Container management",
        "icon": "🐳",
        "category": "cloud",
        "mcp_matcher": "mcp__docker__.*",
        "rules": [
            {
                "id": "docker-read-allowlist",
                "name": "Docker - Allow Read Operations",
                "description": "Allow listing and inspecting containers/images",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["docker_list", "docker_inspect", "docker_logs", "docker_ps"],
                    "description": "Read-only Docker operations"
                }
            },
            {
                "id": "docker-run-approval",
                "name": "Docker - Approval for Run",
                "description": "Require approval for running containers",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": ["docker_run", "docker_start", "docker_exec"],
                    "description": "Running containers requires approval"
                }
            },
            {
                "id": "docker-block-destructive",
                "name": "Docker - Block Destructive Operations",
                "description": "Block removing containers and images",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": ["docker_rm", "docker_rmi", "docker_prune", "docker_kill"],
                    "description": "Destructive operations are blocked"
                }
            },
        ]
    },

    "vercel": {
        "name": "Vercel",
        "description": "Frontend deployment platform",
        "icon": "▲",
        "category": "cloud",
        "mcp_matcher": "mcp__vercel__.*",
        "rules": [
            {
                "id": "vercel-read-allowlist",
                "name": "Vercel - Allow Read Operations",
                "description": "Allow listing projects, deployments, domains",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["vercel_list", "vercel_get", "vercel_inspect"],
                    "description": "Read-only Vercel operations"
                }
            },
            {
                "id": "vercel-deploy-approval",
                "name": "Vercel - Approval for Deploy",
                "description": "Require approval for deployments",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": ["vercel_deploy", "vercel_promote", "vercel_redeploy"],
                    "description": "Deployments require approval"
                }
            },
            {
                "id": "vercel-env-approval",
                "name": "Vercel - Approval for Environment Variables",
                "description": "Require approval for env var changes",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 85,
                "parameters": {
                    "patterns": ["vercel_env", "vercel_secret"],
                    "description": "Env var changes require approval"
                }
            },
            {
                "id": "vercel-block-delete",
                "name": "Vercel - Block Delete Operations",
                "description": "Block project and deployment deletion",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": ["vercel_delete", "vercel_remove", "vercel_rm"],
                    "description": "Delete operations are blocked"
                }
            },
        ]
    },

    "railway": {
        "name": "Railway",
        "description": "Infrastructure deployment platform",
        "icon": "🚂",
        "category": "cloud",
        "mcp_matcher": "mcp__railway__.*",
        "rules": [
            {
                "id": "railway-read-allowlist",
                "name": "Railway - Allow Read Operations",
                "description": "Allow listing projects, services, deployments",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["railway_list", "railway_get", "railway_status", "railway_logs"],
                    "description": "Read-only Railway operations"
                }
            },
            {
                "id": "railway-deploy-approval",
                "name": "Railway - Approval for Deploy",
                "description": "Require approval for deployments",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": ["railway_deploy", "railway_up", "railway_redeploy"],
                    "description": "Deployments require approval"
                }
            },
            {
                "id": "railway-vars-approval",
                "name": "Railway - Approval for Variables",
                "description": "Require approval for variable changes",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 85,
                "parameters": {
                    "patterns": ["railway_variables", "railway_env"],
                    "description": "Variable changes require approval"
                }
            },
            {
                "id": "railway-block-delete",
                "name": "Railway - Block Delete Operations",
                "description": "Block project and service deletion",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": ["railway_delete", "railway_remove", "railway_down"],
                    "description": "Delete operations are blocked"
                }
            },
        ]
    },

    "supabase": {
        "name": "Supabase",
        "description": "Backend as a Service (database, auth, storage)",
        "icon": "⚡",
        "category": "cloud",
        "mcp_matcher": "mcp__supabase__.*",
        "rules": [
            {
                "id": "supabase-read-allowlist",
                "name": "Supabase - Allow Read Operations",
                "description": "Allow reading data, listing projects",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["supabase_select", "supabase_list", "supabase_get", "supabase_read"],
                    "description": "Read-only Supabase operations"
                }
            },
            {
                "id": "supabase-write-approval",
                "name": "Supabase - Approval for Data Write",
                "description": "Require approval for insert/update",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": ["supabase_insert", "supabase_update", "supabase_upsert"],
                    "description": "Data writes require approval"
                }
            },
            {
                "id": "supabase-auth-approval",
                "name": "Supabase - Approval for Auth Changes",
                "description": "Require approval for auth operations",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 85,
                "parameters": {
                    "patterns": ["supabase_auth", "supabase_user_create", "supabase_user_update"],
                    "description": "Auth changes require approval"
                }
            },
            {
                "id": "supabase-block-delete",
                "name": "Supabase - Block Delete Operations",
                "description": "Block data and resource deletion",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": ["supabase_delete", "supabase_drop", "supabase_truncate"],
                    "description": "Delete operations are blocked"
                }
            },
            {
                "id": "supabase-block-schema",
                "name": "Supabase - Block Schema Changes",
                "description": "Block database schema modifications",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": ["supabase_migrate", "supabase_schema", "supabase_alter"],
                    "description": "Schema changes are blocked"
                }
            },
        ]
    },

    "netlify": {
        "name": "Netlify",
        "description": "Web deployment and hosting",
        "icon": "🌐",
        "category": "cloud",
        "mcp_matcher": "mcp__netlify__.*",
        "rules": [
            {
                "id": "netlify-read-allowlist",
                "name": "Netlify - Allow Read Operations",
                "description": "Allow listing sites, deploys, forms",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["netlify_list", "netlify_get", "netlify_status"],
                    "description": "Read-only Netlify operations"
                }
            },
            {
                "id": "netlify-deploy-approval",
                "name": "Netlify - Approval for Deploy",
                "description": "Require approval for deployments",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": ["netlify_deploy", "netlify_build", "netlify_publish"],
                    "description": "Deployments require approval"
                }
            },
            {
                "id": "netlify-block-delete",
                "name": "Netlify - Block Delete Operations",
                "description": "Block site deletion",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": ["netlify_delete", "netlify_remove"],
                    "description": "Delete operations are blocked"
                }
            },
        ]
    },

    "planetscale": {
        "name": "PlanetScale",
        "description": "Serverless MySQL platform",
        "icon": "🪐",
        "category": "cloud",
        "mcp_matcher": "mcp__planetscale__.*|mcp__pscale__.*",
        "rules": [
            {
                "id": "planetscale-read-allowlist",
                "name": "PlanetScale - Allow Read Operations",
                "description": "Allow SELECT queries and listing",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["pscale_select", "pscale_list", "pscale_get", "pscale_read"],
                    "description": "Read-only PlanetScale operations"
                }
            },
            {
                "id": "planetscale-write-approval",
                "name": "PlanetScale - Approval for Write",
                "description": "Require approval for insert/update",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": ["pscale_insert", "pscale_update", "pscale_write"],
                    "description": "Data writes require approval"
                }
            },
            {
                "id": "planetscale-branch-approval",
                "name": "PlanetScale - Approval for Branch Operations",
                "description": "Require approval for branch management",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 85,
                "parameters": {
                    "patterns": ["pscale_branch", "pscale_deploy_request", "pscale_promote"],
                    "description": "Branch operations require approval"
                }
            },
            {
                "id": "planetscale-block-destructive",
                "name": "PlanetScale - Block Destructive Operations",
                "description": "Block delete, drop operations",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": ["pscale_delete", "pscale_drop", "pscale_truncate"],
                    "description": "Destructive operations are blocked"
                }
            },
        ]
    },

    "neon": {
        "name": "Neon",
        "description": "Serverless Postgres",
        "icon": "🌙",
        "category": "cloud",
        "mcp_matcher": "mcp__neon__.*",
        "rules": [
            {
                "id": "neon-read-allowlist",
                "name": "Neon - Allow Read Operations",
                "description": "Allow SELECT queries and project listing",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["neon_select", "neon_list", "neon_get", "neon_read"],
                    "description": "Read-only Neon operations"
                }
            },
            {
                "id": "neon-write-approval",
                "name": "Neon - Approval for Write",
                "description": "Require approval for data writes",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": ["neon_insert", "neon_update", "neon_write"],
                    "description": "Data writes require approval"
                }
            },
            {
                "id": "neon-branch-approval",
                "name": "Neon - Approval for Branch Operations",
                "description": "Require approval for branch management",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 85,
                "parameters": {
                    "patterns": ["neon_branch_create", "neon_branch_reset"],
                    "description": "Branch operations require approval"
                }
            },
            {
                "id": "neon-block-destructive",
                "name": "Neon - Block Destructive Operations",
                "description": "Block delete and drop operations",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": ["neon_delete", "neon_drop", "neon_truncate", "neon_branch_delete"],
                    "description": "Destructive operations are blocked"
                }
            },
        ]
    },

    "cloudflare": {
        "name": "Cloudflare",
        "description": "CDN, DNS, Workers, and edge computing",
        "icon": "🔶",
        "category": "cloud",
        "mcp_matcher": "mcp__cloudflare__.*|mcp__cf__.*",
        "rules": [
            {
                "id": "cloudflare-read-allowlist",
                "name": "Cloudflare - Allow Read Operations",
                "description": "Allow listing zones, DNS records, analytics",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["cf_list", "cf_get", "cf_analytics", "cloudflare_list", "cloudflare_get"],
                    "description": "Read-only Cloudflare operations"
                }
            },
            {
                "id": "cloudflare-dns-approval",
                "name": "Cloudflare - Approval for DNS Changes",
                "description": "Require approval for DNS modifications",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": ["cf_dns_create", "cf_dns_update", "cloudflare_dns"],
                    "description": "DNS changes require approval"
                }
            },
            {
                "id": "cloudflare-worker-approval",
                "name": "Cloudflare - Approval for Worker Deploy",
                "description": "Require approval for Worker deployments",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 85,
                "parameters": {
                    "patterns": ["cf_worker_deploy", "cf_worker_publish", "cloudflare_worker"],
                    "description": "Worker deployments require approval"
                }
            },
            {
                "id": "cloudflare-block-delete",
                "name": "Cloudflare - Block Delete Operations",
                "description": "Block zone and record deletion",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": ["cf_delete", "cf_purge_all", "cloudflare_delete"],
                    "description": "Delete operations are blocked"
                }
            },
        ]
    },

    "render": {
        "name": "Render",
        "description": "Cloud application hosting",
        "icon": "🎨",
        "category": "cloud",
        "mcp_matcher": "mcp__render__.*",
        "rules": [
            {
                "id": "render-read-allowlist",
                "name": "Render - Allow Read Operations",
                "description": "Allow listing services, deploys, logs",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["render_list", "render_get", "render_logs", "render_status"],
                    "description": "Read-only Render operations"
                }
            },
            {
                "id": "render-deploy-approval",
                "name": "Render - Approval for Deploy",
                "description": "Require approval for deployments",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": ["render_deploy", "render_redeploy", "render_restart"],
                    "description": "Deployments require approval"
                }
            },
            {
                "id": "render-env-approval",
                "name": "Render - Approval for Env Changes",
                "description": "Require approval for environment variables",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 85,
                "parameters": {
                    "patterns": ["render_env", "render_secret"],
                    "description": "Env changes require approval"
                }
            },
            {
                "id": "render-block-delete",
                "name": "Render - Block Delete Operations",
                "description": "Block service deletion",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": ["render_delete", "render_remove"],
                    "description": "Delete operations are blocked"
                }
            },
        ]
    },

    "flyio": {
        "name": "Fly.io",
        "description": "Global application deployment",
        "icon": "🪁",
        "category": "cloud",
        "mcp_matcher": "mcp__flyio__.*|mcp__fly__.*",
        "rules": [
            {
                "id": "flyio-read-allowlist",
                "name": "Fly.io - Allow Read Operations",
                "description": "Allow listing apps, machines, status",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["fly_list", "fly_status", "fly_logs", "fly_info"],
                    "description": "Read-only Fly.io operations"
                }
            },
            {
                "id": "flyio-deploy-approval",
                "name": "Fly.io - Approval for Deploy",
                "description": "Require approval for deployments",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": ["fly_deploy", "fly_launch", "fly_scale"],
                    "description": "Deployments require approval"
                }
            },
            {
                "id": "flyio-secrets-approval",
                "name": "Fly.io - Approval for Secrets",
                "description": "Require approval for secret changes",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 85,
                "parameters": {
                    "patterns": ["fly_secrets", "fly_env"],
                    "description": "Secret changes require approval"
                }
            },
            {
                "id": "flyio-block-destructive",
                "name": "Fly.io - Block Destructive Operations",
                "description": "Block app and machine deletion",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": ["fly_destroy", "fly_delete", "fly_remove"],
                    "description": "Destructive operations are blocked"
                }
            },
        ]
    },

    "digitalocean": {
        "name": "DigitalOcean",
        "description": "Cloud infrastructure",
        "icon": "🌊",
        "category": "cloud",
        "mcp_matcher": "mcp__digitalocean__.*|mcp__do__.*",
        "rules": [
            {
                "id": "digitalocean-read-allowlist",
                "name": "DigitalOcean - Allow Read Operations",
                "description": "Allow listing droplets, apps, databases",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["do_list", "do_get", "do_status", "digitalocean_list"],
                    "description": "Read-only DigitalOcean operations"
                }
            },
            {
                "id": "digitalocean-create-approval",
                "name": "DigitalOcean - Approval for Create",
                "description": "Require approval for creating resources",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": ["do_create", "do_deploy", "digitalocean_create"],
                    "description": "Creating resources requires approval"
                }
            },
            {
                "id": "digitalocean-block-destructive",
                "name": "DigitalOcean - Block Destructive Operations",
                "description": "Block droplet and resource deletion",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": ["do_delete", "do_destroy", "digitalocean_delete"],
                    "description": "Destructive operations are blocked"
                }
            },
        ]
    },

    # =========================================================================
    # DATABASES
    # =========================================================================
    "postgresql": {
        "name": "PostgreSQL",
        "description": "PostgreSQL database",
        "icon": "🐘",
        "category": "database",
        "mcp_matcher": "mcp__postgres__.*|mcp__postgresql__.*",
        "rules": [
            {
                "id": "postgresql-read-allowlist",
                "name": "PostgreSQL - Allow Read Operations",
                "description": "Allow SELECT queries",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["postgres_select", "postgres_read", "postgres_query"],
                    "description": "Read queries are allowed"
                }
            },
            {
                "id": "postgresql-write-approval",
                "name": "PostgreSQL - Approval for Write",
                "description": "Require approval for INSERT/UPDATE",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": ["postgres_insert", "postgres_update", "postgres_write"],
                    "description": "Write operations require approval"
                }
            },
            {
                "id": "postgresql-block-destructive",
                "name": "PostgreSQL - Block Destructive Operations",
                "description": "Block DELETE, DROP, TRUNCATE",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": ["postgres_delete", "postgres_drop", "postgres_truncate", "postgres_alter"],
                    "description": "Destructive operations are blocked"
                }
            },
        ]
    },

    "mongodb": {
        "name": "MongoDB",
        "description": "MongoDB database",
        "icon": "🍃",
        "category": "database",
        "mcp_matcher": "mcp__mongodb__.*|mcp__mongo__.*",
        "rules": [
            {
                "id": "mongodb-read-allowlist",
                "name": "MongoDB - Allow Read Operations",
                "description": "Allow find queries",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["mongo_find", "mongo_read", "mongo_aggregate", "mongo_count"],
                    "description": "Read queries are allowed"
                }
            },
            {
                "id": "mongodb-write-approval",
                "name": "MongoDB - Approval for Write",
                "description": "Require approval for insert/update",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": ["mongo_insert", "mongo_update", "mongo_write"],
                    "description": "Write operations require approval"
                }
            },
            {
                "id": "mongodb-block-destructive",
                "name": "MongoDB - Block Destructive Operations",
                "description": "Block delete and drop operations",
                "rule_type": "command_denylist",
                "action": "deny",
                "priority": 200,
                "parameters": {
                    "patterns": ["mongo_delete", "mongo_drop", "mongo_remove"],
                    "description": "Destructive operations are blocked"
                }
            },
        ]
    },

    # =========================================================================
    # FILE & SYSTEM
    # =========================================================================
    "filesystem": {
        "name": "Filesystem",
        "description": "Local file system access",
        "icon": "📂",
        "category": "system",
        "mcp_matcher": "mcp__filesystem__.*",
        "rules": [
            {
                "id": "filesystem-read-allowlist",
                "name": "Filesystem - Allow Read Operations",
                "description": "Allow reading files and listing directories",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["fs_read", "fs_list", "fs_stat"],
                    "description": "Read operations are allowed"
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
                    "patterns": ["fs_write", "fs_create", "fs_mkdir"],
                    "description": "Write operations require approval"
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
                    "patterns": ["fs_delete", "fs_remove", "fs_rmdir"],
                    "description": "Delete operations are blocked"
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
                    "description": "Sensitive paths are blocked"
                }
            },
        ]
    },

    "shell": {
        "name": "Shell/Bash",
        "description": "Command line shell access",
        "icon": "💻",
        "category": "system",
        "mcp_matcher": "Bash",
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
                    "description": "Safe read-only commands"
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
                    "description": "Git read operations"
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
                    "description": "Git write operations require approval"
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
                    "description": "Dangerous commands are blocked"
                }
            },
        ]
    },

    # =========================================================================
    # AI & AUTOMATION
    # =========================================================================
    "openai": {
        "name": "OpenAI",
        "description": "OpenAI API access",
        "icon": "🤖",
        "category": "ai",
        "mcp_matcher": "mcp__openai__.*",
        "rules": [
            {
                "id": "openai-completions-allowlist",
                "name": "OpenAI - Allow Completions",
                "description": "Allow chat and completion calls",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["openai_chat", "openai_completion", "openai_embed"],
                    "description": "API calls are allowed"
                }
            },
            {
                "id": "openai-rate-limit",
                "name": "OpenAI - Rate Limit",
                "description": "Limit API calls to prevent cost overruns",
                "rule_type": "rate_limit",
                "action": "deny",
                "priority": 150,
                "parameters": {
                    "max_requests": 100,
                    "window_seconds": 3600,
                    "description": "Max 100 calls per hour"
                }
            },
        ]
    },

    "zapier": {
        "name": "Zapier",
        "description": "Workflow automation",
        "icon": "⚡",
        "category": "ai",
        "mcp_matcher": "mcp__zapier__.*",
        "rules": [
            {
                "id": "zapier-read-allowlist",
                "name": "Zapier - Allow Read Operations",
                "description": "Allow listing zaps and triggers",
                "rule_type": "command_allowlist",
                "action": "allow",
                "priority": 100,
                "parameters": {
                    "patterns": ["zapier_list", "zapier_get"],
                    "description": "Read operations are allowed"
                }
            },
            {
                "id": "zapier-trigger-approval",
                "name": "Zapier - Approval for Triggers",
                "description": "Require approval for triggering workflows",
                "rule_type": "command_allowlist",
                "action": "require_approval",
                "priority": 90,
                "parameters": {
                    "patterns": ["zapier_trigger", "zapier_run", "zapier_execute"],
                    "description": "Triggering workflows requires approval"
                }
            },
        ]
    },
}

# Categories for UI organization
INTEGRATION_CATEGORIES = {
    "communication": {
        "name": "Communication",
        "description": "Email, messaging, and team collaboration",
        "icon": "💬",
    },
    "productivity": {
        "name": "Productivity",
        "description": "Calendars, documents, and task management",
        "icon": "📊",
    },
    "developer": {
        "name": "Developer Tools",
        "description": "Code hosting, issue tracking, CI/CD",
        "icon": "🛠️",
    },
    "cloud": {
        "name": "Cloud & Infrastructure",
        "description": "Cloud providers and container platforms",
        "icon": "☁️",
    },
    "database": {
        "name": "Databases",
        "description": "Database access and management",
        "icon": "🗄️",
    },
    "system": {
        "name": "System",
        "description": "File system and shell access",
        "icon": "💻",
    },
    "ai": {
        "name": "AI & Automation",
        "description": "AI services and workflow automation",
        "icon": "🤖",
    },
}


def get_templates_by_category() -> dict[str, list[dict]]:
    """Get integration templates organized by category."""
    result = {}
    for category_id, category_info in INTEGRATION_CATEGORIES.items():
        templates = [
            {
                "id": template_id,
                **template_data,
            }
            for template_id, template_data in INTEGRATION_TEMPLATES.items()
            if template_data.get("category") == category_id
        ]
        if templates:
            result[category_id] = {
                "info": category_info,
                "templates": templates,
            }
    return result


def get_template(template_id: str) -> dict | None:
    """Get a specific integration template by ID."""
    return INTEGRATION_TEMPLATES.get(template_id)
