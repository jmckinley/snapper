#!/bin/bash
# Snapper PreToolUse Hook for Claude Code
# Checks with Snapper before allowing any tool execution.
#
# NOTE: The canonical version lives at plugins/claude-code/snapper_hook.sh.
#       This file is kept for backward compatibility.
#
# Installation:
#   Quick: bash scripts/claude-code-setup.sh
#   Manual:
#     1. Copy to ~/.claude/hooks/pre_tool_use.sh
#     2. chmod +x ~/.claude/hooks/pre_tool_use.sh
#     3. Add to ~/.claude/settings.json (see plugins/claude-code/README.md)
#
# Exit codes (Claude Code convention):
#   0 = allow (tool proceeds)
#   2 = deny  (tool blocked, reason shown to user)
#   1 = error (non-blocking, logged but tool still proceeds)

set -o pipefail

SNAPPER_URL="${SNAPPER_URL:-http://localhost:8000}"
SNAPPER_AGENT_ID="${SNAPPER_AGENT_ID:-claude-code-$(hostname)}"
SNAPPER_API_KEY="${SNAPPER_API_KEY:-}"
SNAPPER_FAIL_MODE="${SNAPPER_FAIL_MODE:-closed}"  # "closed" (default) or "open"
APPROVAL_TIMEOUT="${SNAPPER_APPROVAL_TIMEOUT:-300}"

# Read hook input from stdin (JSON format from Claude Code)
INPUT=$(cat)

# Extract tool info
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // .name // "unknown"')
TOOL_INPUT=$(echo "$INPUT" | jq -c '.tool_input // .input // {}')

# --- Tool-to-request_type mapping ---
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
    Write|write|Edit|edit|NotebookEdit)
        REQUEST_TYPE="file_access"
        FILE_PATH=$(echo "$TOOL_INPUT" | jq -r '.file_path // .notebook_path // .path // ""')
        FILE_OP="write"
        ;;
    WebFetch|fetch|curl|http)
        REQUEST_TYPE="network"
        URL=$(echo "$TOOL_INPUT" | jq -r '.url // ""')
        ;;
    WebSearch|web_search)
        REQUEST_TYPE="network"
        URL=""  # WebSearch has no specific URL, just a query
        ;;
    Glob|glob|Grep|grep|LSP|lsp)
        REQUEST_TYPE="file_access"
        FILE_PATH=$(echo "$TOOL_INPUT" | jq -r '.path // .pattern // ""')
        FILE_OP="read"
        ;;
    browser|Browser|puppeteer|playwright)
        REQUEST_TYPE="browser_action"
        ACTION=$(echo "$TOOL_INPUT" | jq -r '.action // ""')
        URL=$(echo "$TOOL_INPUT" | jq -r '.url // .page_url // ""')
        ;;
    Task|task|Skill|skill|Agent|agent)
        REQUEST_TYPE="tool"
        ;;
    *)
        REQUEST_TYPE="tool"
        ;;
esac

# Build evaluate request payload
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

# --- Helper: output JSON decision for Claude Code ---
output_decision() {
    local decision="$1" reason="$2"
    jq -n \
        --arg decision "$decision" \
        --arg reason "$reason" \
        '{
            hookSpecificOutput: {
                hookEventName: "PreToolUse",
                permissionDecision: $decision,
                permissionDecisionReason: $reason
            }
        }'
}

# --- Call Snapper evaluate endpoint ---
RESPONSE=$(curl -skf -X POST "$SNAPPER_URL/api/v1/rules/evaluate" \
    -H "Content-Type: application/json" \
    ${SNAPPER_API_KEY:+-H "X-API-Key: $SNAPPER_API_KEY"} \
    -d "$PAYLOAD" 2>/dev/null)

if [ $? -ne 0 ]; then
    if [ "$SNAPPER_FAIL_MODE" = "open" ]; then
        echo "Snapper unreachable — fail-open, allowing tool" >&2
        exit 0
    fi
    echo "Snapper unreachable — failing closed for security" >&2
    output_decision "deny" "Blocked by Snapper: service unreachable (fail-closed)"
    exit 2
fi

DECISION=$(echo "$RESPONSE" | jq -r '.decision')
RULE_NAME=$(echo "$RESPONSE" | jq -r '.matched_rule_name // "Security Rule"')
REASON=$(echo "$RESPONSE" | jq -r '.reason // "Security policy"')

case "$DECISION" in
    allow)
        # Output resolved vault data if present (auto mode token resolution)
        RESOLVED_DATA=$(echo "$RESPONSE" | jq -c '.resolved_data // null')
        if [ "$RESOLVED_DATA" != "null" ] && [ -n "$RESOLVED_DATA" ]; then
            echo "Auto-resolved vault tokens" >&2
            echo "$RESOLVED_DATA"
        fi
        exit 0
        ;;

    deny)
        echo "" >&2
        echo "BLOCKED by Snapper" >&2
        echo "  Rule: $RULE_NAME" >&2
        echo "  Reason: $REASON" >&2
        echo "" >&2
        output_decision "deny" "Blocked by Snapper: $REASON"
        exit 2
        ;;

    require_approval)
        APPROVAL_ID=$(echo "$RESPONSE" | jq -r '.approval_request_id // ""')

        if [ -z "$APPROVAL_ID" ] || [ "$APPROVAL_ID" = "null" ]; then
            echo "BLOCKED: Approval required but no request ID returned" >&2
            output_decision "deny" "Blocked by Snapper: approval required but no request ID"
            exit 2
        fi

        echo "" >&2
        echo "WAITING FOR APPROVAL" >&2
        echo "  Rule: $RULE_NAME" >&2
        echo "  Reason: $REASON" >&2
        echo "  Request ID: ${APPROVAL_ID:0:8}..." >&2
        echo "" >&2
        echo "  Check Telegram or Snapper dashboard to approve/deny." >&2
        echo "" >&2

        # Poll for approval status
        START_TIME=$(date +%s)
        POLL_INTERVAL=5

        while true; do
            ELAPSED=$(($(date +%s) - START_TIME))

            if [ $ELAPSED -ge $APPROVAL_TIMEOUT ]; then
                echo "TIMEOUT: Approval request expired after ${APPROVAL_TIMEOUT}s" >&2
                output_decision "deny" "Blocked by Snapper: approval timed out after ${APPROVAL_TIMEOUT}s"
                exit 2
            fi

            STATUS_RESPONSE=$(curl -skf "$SNAPPER_URL/api/v1/approvals/$APPROVAL_ID/status" \
                ${SNAPPER_API_KEY:+-H "X-API-Key: $SNAPPER_API_KEY"} 2>/dev/null)

            if [ $? -ne 0 ]; then
                sleep $POLL_INTERVAL
                continue
            fi

            STATUS=$(echo "$STATUS_RESPONSE" | jq -r '.status')
            STATUS_REASON=$(echo "$STATUS_RESPONSE" | jq -r '.reason // ""')

            case "$STATUS" in
                approved)
                    echo "APPROVED: $STATUS_REASON" >&2
                    # Output resolved vault data if present (for token replacement)
                    RESOLVED_DATA=$(echo "$STATUS_RESPONSE" | jq -c '.resolved_data // null')
                    if [ "$RESOLVED_DATA" != "null" ] && [ -n "$RESOLVED_DATA" ]; then
                        echo "$RESOLVED_DATA"
                    fi
                    exit 0
                    ;;
                denied)
                    echo "DENIED: $STATUS_REASON" >&2
                    output_decision "deny" "Blocked by Snapper: approval denied — $STATUS_REASON"
                    exit 2
                    ;;
                expired)
                    echo "EXPIRED: $STATUS_REASON" >&2
                    output_decision "deny" "Blocked by Snapper: approval expired"
                    exit 2
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
        echo "BLOCKED: Unknown decision '$DECISION'" >&2
        output_decision "deny" "Blocked by Snapper: unknown decision '$DECISION'"
        exit 2
        ;;
esac
