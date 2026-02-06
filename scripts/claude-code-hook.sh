#!/bin/bash
# Snapper PreToolUse Hook for Claude Code
# This hook checks with Snapper before allowing any tool execution
#
# Installation:
# 1. Copy this script to ~/.claude/hooks/pre_tool_use.sh
# 2. Make it executable: chmod +x ~/.claude/hooks/pre_tool_use.sh
# 3. Add to ~/.claude/settings.json:
#    {
#      "hooks": {
#        "PreToolUse": [
#          {
#            "matcher": "",
#            "hooks": [
#              {
#                "type": "command",
#                "command": "~/.claude/hooks/pre_tool_use.sh"
#              }
#            ]
#          }
#        ]
#      }
#    }
#
# Or run: snapper integrate claude-code

SNAPPER_URL="${SNAPPER_URL:-http://localhost:8000}"
SNAPPER_AGENT_ID="${SNAPPER_AGENT_ID:-claude-code-$(hostname)}"
SNAPPER_API_KEY="${SNAPPER_API_KEY:-}"  # Optional: snp_xxx for authenticated requests
APPROVAL_TIMEOUT="${SNAPPER_APPROVAL_TIMEOUT:-300}"

# Read hook input from stdin (JSON format)
INPUT=$(cat)

# Extract tool info - Claude Code format
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // .name // "unknown"')
TOOL_INPUT=$(echo "$INPUT" | jq -c '.tool_input // .input // {}')

# Determine request type based on tool
case "$TOOL_NAME" in
    Bash|bash|shell|execute|computer)
        REQUEST_TYPE="command"
        COMMAND=$(echo "$TOOL_INPUT" | jq -r '.command // .cmd // ""')
        ;;
    Read|read|str_replace_editor)
        REQUEST_TYPE="file_access"
        FILE_PATH=$(echo "$TOOL_INPUT" | jq -r '.file_path // .path // ""')
        FILE_OP="read"
        ;;
    Write|write|Edit|edit)
        REQUEST_TYPE="file_access"
        FILE_PATH=$(echo "$TOOL_INPUT" | jq -r '.file_path // .path // ""')
        FILE_OP="write"
        ;;
    WebFetch|fetch|curl|http|web_search)
        REQUEST_TYPE="network"
        URL=$(echo "$TOOL_INPUT" | jq -r '.url // ""')
        ;;
    Glob|glob|Grep|grep|LSP|lsp)
        REQUEST_TYPE="file_access"
        FILE_PATH=$(echo "$TOOL_INPUT" | jq -r '.path // .pattern // ""')
        FILE_OP="read"
        ;;
    Task|task|Agent|agent)
        REQUEST_TYPE="tool"
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

# Build auth header if API key is set
AUTH_HEADER=""
if [ -n "$SNAPPER_API_KEY" ]; then
    AUTH_HEADER="-H \"X-API-Key: $SNAPPER_API_KEY\""
fi

# Call Snapper evaluate endpoint
RESPONSE=$(curl -sf -X POST "$SNAPPER_URL/api/v1/rules/evaluate" \
    -H "Content-Type: application/json" \
    -H "Origin: http://localhost:8000" \
    ${AUTH_HEADER:+-H "X-API-Key: $SNAPPER_API_KEY"} \
    -d "$PAYLOAD" 2>/dev/null)

# Check response
if [ $? -ne 0 ]; then
    echo "🚫 BLOCKED: Snapper unreachable - failing closed for security" >&2
    exit 1
fi

DECISION=$(echo "$RESPONSE" | jq -r '.decision')
RULE_NAME=$(echo "$RESPONSE" | jq -r '.matched_rule_name // "Security Rule"')
REASON=$(echo "$RESPONSE" | jq -r '.reason // "Security policy"')

case "$DECISION" in
    allow)
        exit 0
        ;;

    deny)
        echo "" >&2
        echo "🚫 BLOCKED by Snapper" >&2
        echo "   Rule: $RULE_NAME" >&2
        echo "   Reason: $REASON" >&2
        echo "" >&2
        exit 1
        ;;

    require_approval)
        APPROVAL_ID=$(echo "$RESPONSE" | jq -r '.approval_request_id // ""')

        if [ -z "$APPROVAL_ID" ] || [ "$APPROVAL_ID" = "null" ]; then
            echo "🚫 BLOCKED: Approval required but no request ID returned" >&2
            exit 1
        fi

        echo "" >&2
        echo "⏳ WAITING FOR APPROVAL" >&2
        echo "   Rule: $RULE_NAME" >&2
        echo "   Reason: $REASON" >&2
        echo "   Request ID: ${APPROVAL_ID:0:8}..." >&2
        echo "" >&2
        echo "   Check Telegram or Snapper dashboard to approve/deny." >&2
        echo "" >&2

        # Poll for approval status
        START_TIME=$(date +%s)
        POLL_INTERVAL=5

        while true; do
            ELAPSED=$(($(date +%s) - START_TIME))

            if [ $ELAPSED -ge $APPROVAL_TIMEOUT ]; then
                echo "❌ TIMEOUT: Approval request expired after ${APPROVAL_TIMEOUT}s" >&2
                exit 1
            fi

            STATUS_RESPONSE=$(curl -sf "$SNAPPER_URL/api/v1/approvals/$APPROVAL_ID/status" \
                -H "Origin: http://localhost:8000" \
                ${SNAPPER_API_KEY:+-H "X-API-Key: $SNAPPER_API_KEY"} 2>/dev/null)

            if [ $? -ne 0 ]; then
                sleep $POLL_INTERVAL
                continue
            fi

            STATUS=$(echo "$STATUS_RESPONSE" | jq -r '.status')
            STATUS_REASON=$(echo "$STATUS_RESPONSE" | jq -r '.reason // ""')

            case "$STATUS" in
                approved)
                    echo "✅ APPROVED: $STATUS_REASON" >&2
                    exit 0
                    ;;
                denied)
                    echo "❌ DENIED: $STATUS_REASON" >&2
                    exit 1
                    ;;
                expired)
                    echo "❌ EXPIRED: $STATUS_REASON" >&2
                    exit 1
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
        echo "🚫 BLOCKED: Unknown decision '$DECISION'" >&2
        exit 1
        ;;
esac
