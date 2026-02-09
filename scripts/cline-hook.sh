#!/bin/bash
# Snapper PreToolUse Hook for Cline
# This hook checks with Snapper before allowing any tool execution
#
# Installation:
# 1. Copy this script to ~/.cline/hooks/pre_tool_use (no extension)
# 2. Make it executable: chmod +x ~/.cline/hooks/pre_tool_use
# 3. Cline auto-discovers executable scripts in the hooks directory
#
# Or run: snapper init --agent cline
#
# Protocol: Cline reads JSON on stdout. Output {"cancel": true} to block,
# {"cancel": false} to allow. Always exit 0.

# Source Snapper env if available
[ -f ~/.cline/.env.snapper ] && set -a && . ~/.cline/.env.snapper && set +a

SNAPPER_URL="${SNAPPER_URL:-http://localhost:8000}"
SNAPPER_AGENT_ID="${SNAPPER_AGENT_ID:-cline-$(hostname)}"
SNAPPER_API_KEY="${SNAPPER_API_KEY:-}"
APPROVAL_TIMEOUT="${SNAPPER_APPROVAL_TIMEOUT:-300}"

# Read hook input from stdin (JSON format)
INPUT=$(cat)

# Extract tool info - Cline format
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // .name // "unknown"')
TOOL_INPUT=$(echo "$INPUT" | jq -c '.tool_input // .input // {}')

# Determine request type based on tool
case "$TOOL_NAME" in
    execute_command|Bash|bash|shell|execute|computer)
        REQUEST_TYPE="command"
        COMMAND=$(echo "$TOOL_INPUT" | jq -r '.command // .cmd // ""')
        ;;
    read_file|Read|read)
        REQUEST_TYPE="file_access"
        FILE_PATH=$(echo "$TOOL_INPUT" | jq -r '.file_path // .path // ""')
        FILE_OP="read"
        ;;
    write_to_file|Write|write|Edit|edit)
        REQUEST_TYPE="file_access"
        FILE_PATH=$(echo "$TOOL_INPUT" | jq -r '.file_path // .path // ""')
        FILE_OP="write"
        ;;
    browser_action|browser|Browser)
        REQUEST_TYPE="browser_action"
        ACTION=$(echo "$TOOL_INPUT" | jq -r '.action // ""')
        URL=$(echo "$TOOL_INPUT" | jq -r '.url // .page_url // ""')
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

# Call Snapper evaluate endpoint
RESPONSE=$(curl -skf -X POST "$SNAPPER_URL/api/v1/rules/evaluate" \
    -H "Content-Type: application/json" \
    -H "Origin: $SNAPPER_URL" \
    ${SNAPPER_API_KEY:+-H "X-API-Key: $SNAPPER_API_KEY"} \
    -d "$PAYLOAD" 2>/dev/null)

# Check response - fail closed; Cline uses JSON on stdout
if [ $? -ne 0 ]; then
    echo '{"cancel": true, "reason": "Snapper unreachable - failing closed for security"}'
    exit 0
fi

DECISION=$(echo "$RESPONSE" | jq -r '.decision')
RULE_NAME=$(echo "$RESPONSE" | jq -r '.matched_rule_name // "Security Rule"')
REASON=$(echo "$RESPONSE" | jq -r '.reason // "Security policy"')

case "$DECISION" in
    allow)
        RESOLVED_DATA=$(echo "$RESPONSE" | jq -c '.resolved_data // null')
        if [ "$RESOLVED_DATA" != "null" ] && [ -n "$RESOLVED_DATA" ]; then
            # Emit resolved data then allow
            echo "$RESOLVED_DATA" >&2
        fi
        echo '{"cancel": false}'
        exit 0
        ;;

    deny)
        echo "{\"cancel\": true, \"reason\": \"Blocked by Snapper: $REASON\"}"
        exit 0
        ;;

    require_approval)
        APPROVAL_ID=$(echo "$RESPONSE" | jq -r '.approval_request_id // ""')

        if [ -z "$APPROVAL_ID" ] || [ "$APPROVAL_ID" = "null" ]; then
            echo '{"cancel": true, "reason": "Approval required but no request ID returned"}'
            exit 0
        fi

        echo "Waiting for approval (Rule: $RULE_NAME)" >&2
        echo "Check Telegram or Snapper dashboard to approve/deny." >&2

        # Poll for approval status
        START_TIME=$(date +%s)
        POLL_INTERVAL=5

        while true; do
            ELAPSED=$(($(date +%s) - START_TIME))

            if [ $ELAPSED -ge $APPROVAL_TIMEOUT ]; then
                echo '{"cancel": true, "reason": "Approval request timed out"}'
                exit 0
            fi

            STATUS_RESPONSE=$(curl -skf "$SNAPPER_URL/api/v1/approvals/$APPROVAL_ID/status" \
                -H "Origin: $SNAPPER_URL" \
                ${SNAPPER_API_KEY:+-H "X-API-Key: $SNAPPER_API_KEY"} 2>/dev/null)

            if [ $? -ne 0 ]; then
                sleep $POLL_INTERVAL
                continue
            fi

            STATUS=$(echo "$STATUS_RESPONSE" | jq -r '.status')

            case "$STATUS" in
                approved)
                    RESOLVED_DATA=$(echo "$STATUS_RESPONSE" | jq -c '.resolved_data // null')
                    if [ "$RESOLVED_DATA" != "null" ] && [ -n "$RESOLVED_DATA" ]; then
                        echo "$RESOLVED_DATA" >&2
                    fi
                    echo '{"cancel": false}'
                    exit 0
                    ;;
                denied)
                    echo '{"cancel": true, "reason": "Approval denied"}'
                    exit 0
                    ;;
                expired)
                    echo '{"cancel": true, "reason": "Approval expired"}'
                    exit 0
                    ;;
                pending)
                    WAIT=$(echo "$STATUS_RESPONSE" | jq -r '.wait_seconds // 5')
                    sleep $WAIT
                    ;;
                *)
                    sleep $POLL_INTERVAL
                    ;;
            esac
        done
        ;;

    *)
        echo "{\"cancel\": true, \"reason\": \"Unknown decision '$DECISION'\"}"
        exit 0
        ;;
esac
