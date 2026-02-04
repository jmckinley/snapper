#!/bin/bash
# GitHub MCP Hook - Checks with Rules Manager before GitHub operations

RULES_MANAGER_URL="${RULES_MANAGER_URL:-http://localhost:8000}"
AGENT_ID="${SNAPPER_AGENT_ID:-snapper-localhost-8000}"

INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty')

# Extract GitHub operation from tool name (e.g., mcp__github__list_repos)
GITHUB_OP=$(echo "$TOOL_NAME" | sed 's/mcp__github__//' | sed 's/mcp__.*__//')

echo "[GitHub Hook] Checking operation: $GITHUB_OP" >&2

# Map GitHub operations to rule categories
case "$GITHUB_OP" in
    "list_repos"|"get_repo"|"list_branches"|"get_file"|"search_code"|"list_commits"|"get_commit")
        REQUEST_TYPE="github_read"
        ;;
    "list_issues"|"get_issue"|"list_prs"|"get_pr"|"list_reviews")
        REQUEST_TYPE="github_list"
        ;;
    "search_repos"|"search_issues"|"search_users")
        REQUEST_TYPE="github_search"
        ;;
    "create_issue"|"update_issue"|"add_comment"|"create_branch")
        REQUEST_TYPE="github_write"
        ;;
    "push"|"push_files"|"create_or_update_file")
        REQUEST_TYPE="github_push"
        ;;
    "create_pr"|"create_pull_request"|"update_pr")
        REQUEST_TYPE="github_pr"
        ;;
    "merge_pr"|"merge_pull_request")
        REQUEST_TYPE="github_merge"
        ;;
    "create_release"|"create_tag")
        REQUEST_TYPE="github_release"
        ;;
    "delete_repo"|"delete_repository")
        REQUEST_TYPE="github_delete_repo"
        ;;
    "force_push"|"push_force")
        REQUEST_TYPE="github_force_push"
        ;;
    "update_branch_protection"|"delete_branch_protection")
        REQUEST_TYPE="github_disable_protection"
        ;;
    *)
        REQUEST_TYPE="github_other"
        ;;
esac

# Call Rules Manager
REQUEST_BODY=$(jq -n \
    --arg agent_id "$AGENT_ID" \
    --arg request_type "command" \
    --arg command "$REQUEST_TYPE" \
    '{agent_id: $agent_id, request_type: $request_type, command: $command}')

RESPONSE=$(curl -s -X POST "${RULES_MANAGER_URL}/api/v1/rules/evaluate" \
    -H "Content-Type: application/json" \
    -d "$REQUEST_BODY" \
    --max-time 5 2>/dev/null)

if [ $? -ne 0 ]; then
    echo "[GitHub Hook] Rules Manager unreachable - denying" >&2
    jq -n '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: "Rules Manager unreachable"}}'
    exit 0
fi

DECISION=$(echo "$RESPONSE" | jq -r '.decision // "deny"')
REASON=$(echo "$RESPONSE" | jq -r '.reason // "No reason"')

echo "[GitHub Hook] Decision: $DECISION - $REASON" >&2

case "$DECISION" in
    "allow")
        exit 0
        ;;
    "require_approval")
        jq -n --arg reason "$REASON" '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: $reason}}'
        exit 0
        ;;
    *)
        jq -n --arg reason "$REASON" '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: $reason}}'
        exit 0
        ;;
esac
