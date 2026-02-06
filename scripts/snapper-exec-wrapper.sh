#!/bin/bash
# Snapper Exec Wrapper for OpenClaw
# This script validates commands with Snapper before executing them.
# Works without jq - uses grep/sed for JSON parsing.

set -euo pipefail

# Configuration
SNAPPER_URL="${SNAPPER_URL:-http://127.0.0.1:8000}"
SNAPPER_API_KEY="${SNAPPER_API_KEY:-}"
SNAPPER_AGENT_ID="${SNAPPER_AGENT_ID:-openclaw-main}"
SNAPPER_TIMEOUT="${SNAPPER_TIMEOUT:-5}"

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Build the full command from args
COMMAND="$*"

# Skip empty commands
if [[ -z "$COMMAND" ]]; then
    exit 0
fi

# Escape command for JSON (basic escaping)
ESCAPED_COMMAND=$(echo "$COMMAND" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g')

# Build JSON payload
JSON_PAYLOAD="{\"agent_id\": \"$SNAPPER_AGENT_ID\", \"request_type\": \"command\", \"command\": \"$ESCAPED_COMMAND\"}"

# Build curl headers
CURL_ARGS=(-s -m "$SNAPPER_TIMEOUT" -X POST -H "Content-Type: application/json")
if [[ -n "$SNAPPER_API_KEY" ]]; then
    CURL_ARGS+=(-H "X-API-Key: $SNAPPER_API_KEY")
fi

# Call Snapper's evaluate endpoint
RESPONSE=$(curl "${CURL_ARGS[@]}" -d "$JSON_PAYLOAD" "${SNAPPER_URL}/api/v1/rules/evaluate" 2>/dev/null || echo '{"decision":"error"}')

# Parse the decision using grep/sed (no jq needed)
# Extract "decision" value: look for "decision":"value"
DECISION=$(echo "$RESPONSE" | grep -o '"decision":"[^"]*"' | head -1 | sed 's/"decision":"//; s/"$//')
REASON=$(echo "$RESPONSE" | grep -o '"reason":"[^"]*"' | head -1 | sed 's/"reason":"//; s/"$//' || echo "Unknown")
RULE_NAME=$(echo "$RESPONSE" | grep -o '"matched_rule_name":"[^"]*"' | head -1 | sed 's/"matched_rule_name":"//; s/"$//' || echo "")

# Default to error if we couldn't parse
if [[ -z "$DECISION" ]]; then
    DECISION="error"
fi

case "$DECISION" in
    "allow")
        # Command allowed - execute it
        exec bash -c "$COMMAND"
        ;;
    "deny")
        echo -e "${RED}BLOCKED by Snapper${NC}" >&2
        echo -e "  Reason: $REASON" >&2
        if [[ -n "$RULE_NAME" && "$RULE_NAME" != "null" ]]; then
            echo -e "  Rule: $RULE_NAME" >&2
        fi
        exit 1
        ;;
    "require_approval")
        APPROVAL_ID=$(echo "$RESPONSE" | grep -o '"approval_request_id":"[^"]*"' | head -1 | sed 's/"approval_request_id":"//; s/"$//' || echo "unknown")
        echo -e "${YELLOW}APPROVAL REQUIRED${NC}" >&2
        echo -e "  Approval ID: $APPROVAL_ID" >&2
        echo -e "  Check Telegram for approval request" >&2
        exit 2
        ;;
    *)
        # Error or unknown response
        if [[ "${SNAPPER_FAIL_OPEN:-false}" == "true" ]]; then
            echo -e "${YELLOW}Warning: Snapper unreachable, allowing command${NC}" >&2
            exec bash -c "$COMMAND"
        else
            echo -e "${RED}Snapper Error: $REASON${NC}" >&2
            exit 1
        fi
        ;;
esac
