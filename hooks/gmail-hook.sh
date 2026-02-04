#!/bin/bash
# Gmail MCP Hook - Checks with Rules Manager before Gmail operations

RULES_MANAGER_URL="${RULES_MANAGER_URL:-http://localhost:8000}"
AGENT_ID="${SNAPPER_AGENT_ID:-snapper-localhost-8000}"

# Read hook input
INPUT=$(cat)

# Extract tool name (e.g., mcp__gmail__send_email)
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty')
TOOL_INPUT=$(echo "$INPUT" | jq -c '.tool_input // {}')

# Extract the Gmail operation (after mcp__gmail__)
GMAIL_OP=$(echo "$TOOL_NAME" | sed 's/mcp__gmail__//')

echo "[Gmail Hook] Checking operation: $GMAIL_OP" >&2

# Map Gmail operations to our rule categories
case "$GMAIL_OP" in
    "send_email"|"send_message"|"create_draft")
        REQUEST_TYPE="gmail_send"
        RECIPIENT=$(echo "$TOOL_INPUT" | jq -r '.to // .recipient // empty')
        ;;
    "delete_email"|"delete_message"|"trash_message")
        REQUEST_TYPE="gmail_delete"
        ;;
    "read_email"|"get_message"|"list_messages"|"search")
        REQUEST_TYPE="gmail_read"
        ;;
    "modify_labels"|"add_label"|"remove_label")
        REQUEST_TYPE="gmail_modify"
        ;;
    *)
        REQUEST_TYPE="gmail_other"
        ;;
esac

# Build request to Rules Manager
# Send as "command" type so rule engine can pattern match
REQUEST_BODY=$(jq -n \
    --arg agent_id "$AGENT_ID" \
    --arg request_type "command" \
    --arg command "$REQUEST_TYPE" \
    '{
        agent_id: $agent_id,
        request_type: $request_type,
        command: $command
    }')

# Call Rules Manager
RESPONSE=$(curl -s -X POST "${RULES_MANAGER_URL}/api/v1/rules/evaluate" \
    -H "Content-Type: application/json" \
    -d "$REQUEST_BODY" \
    --max-time 5 2>/dev/null)

CURL_EXIT=$?

if [ $CURL_EXIT -ne 0 ]; then
    echo "[Gmail Hook] Rules Manager unreachable - denying (fail-safe)" >&2
    jq -n '{
        hookSpecificOutput: {
            hookEventName: "PreToolUse",
            permissionDecision: "deny",
            permissionDecisionReason: "Rules Manager unreachable - Gmail operations blocked for safety"
        }
    }'
    exit 0
fi

DECISION=$(echo "$RESPONSE" | jq -r '.decision // "deny"')
REASON=$(echo "$RESPONSE" | jq -r '.reason // "No reason provided"')

echo "[Gmail Hook] Decision: $DECISION - $REASON" >&2

case "$DECISION" in
    "allow")
        exit 0
        ;;
    "require_approval")
        jq -n --arg reason "Gmail operation requires approval: $REASON" '{
            hookSpecificOutput: {
                hookEventName: "PreToolUse",
                permissionDecision: "ask",
                permissionDecisionReason: $reason
            }
        }'
        exit 0
        ;;
    *)
        jq -n --arg reason "Gmail operation blocked: $REASON" '{
            hookSpecificOutput: {
                hookEventName: "PreToolUse",
                permissionDecision: "deny",
                permissionDecisionReason: $reason
            }
        }'
        exit 0
        ;;
esac
