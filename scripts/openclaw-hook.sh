#!/bin/bash
# Snapper PreToolUse Hook for OpenClaw
# This hook checks with Snapper before allowing any tool execution
#
# Install: Copy to ~/.openclaw/hooks/pre_tool_use.sh
# Or run: snapper integrate openclaw

SNAPPER_URL="${SNAPPER_URL:-http://localhost:8000}"
SNAPPER_AGENT_ID="${SNAPPER_AGENT_ID:-openclaw-$(hostname)}"

# Read hook input from stdin
INPUT=$(cat)

# Extract tool info from JSON input
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // .name // "unknown"')
TOOL_INPUT=$(echo "$INPUT" | jq -c '.tool_input // .input // {}')

# Determine request type based on tool
case "$TOOL_NAME" in
    Bash|bash|shell|execute)
        REQUEST_TYPE="command"
        COMMAND=$(echo "$TOOL_INPUT" | jq -r '.command // .cmd // ""')
        ;;
    Read|read|cat)
        REQUEST_TYPE="file_access"
        FILE_PATH=$(echo "$TOOL_INPUT" | jq -r '.file_path // .path // ""')
        FILE_OP="read"
        ;;
    Write|write|Edit|edit)
        REQUEST_TYPE="file_access"
        FILE_PATH=$(echo "$TOOL_INPUT" | jq -r '.file_path // .path // ""')
        FILE_OP="write"
        ;;
    WebFetch|fetch|curl|http)
        REQUEST_TYPE="network"
        URL=$(echo "$TOOL_INPUT" | jq -r '.url // ""')
        ;;
    *)
        REQUEST_TYPE="tool"
        ;;
esac

# Build request payload
PAYLOAD=$(jq -n \
    --arg agent_id "$SNAPPER_AGENT_ID" \
    --arg request_type "$REQUEST_TYPE" \
    --arg tool_name "$TOOL_NAME" \
    --argjson tool_input "$TOOL_INPUT" \
    --arg command "${COMMAND:-}" \
    --arg file_path "${FILE_PATH:-}" \
    --arg file_operation "${FILE_OP:-}" \
    --arg url "${URL:-}" \
    '{
        agent_id: $agent_id,
        request_type: $request_type,
        tool_name: $tool_name,
        tool_input: $tool_input,
        command: (if $command != "" then $command else null end),
        file_path: (if $file_path != "" then $file_path else null end),
        file_operation: (if $file_operation != "" then $file_operation else null end),
        url: (if $url != "" then $url else null end)
    }'
)

# Call Snapper
RESPONSE=$(curl -sf -X POST "$SNAPPER_URL/api/v1/rules/evaluate" \
    -H "Content-Type: application/json" \
    -H "Origin: http://localhost:8000" \
    -d "$PAYLOAD" 2>/dev/null)

# Check response
if [ $? -ne 0 ]; then
    # Snapper unreachable - fail closed (deny by default)
    echo '{"decision": "deny", "reason": "Snapper unreachable - failing closed for security"}' >&2
    exit 1
fi

DECISION=$(echo "$RESPONSE" | jq -r '.decision')

case "$DECISION" in
    allow)
        exit 0
        ;;
    deny)
        REASON=$(echo "$RESPONSE" | jq -r '.reason // "Denied by security policy"')
        echo "BLOCKED: $REASON" >&2
        exit 1
        ;;
    require_approval)
        REASON=$(echo "$RESPONSE" | jq -r '.reason // "Requires approval"')
        echo "PENDING APPROVAL: $REASON" >&2
        echo "Check Snapper dashboard or Telegram for approval request." >&2
        exit 2
        ;;
    *)
        echo "Unknown decision: $DECISION" >&2
        exit 1
        ;;
esac
