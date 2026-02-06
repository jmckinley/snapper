#!/bin/bash
# Snapper Exec Wrapper for OpenClaw
# This script validates commands with Snapper before executing them.
# Set this as SNAPPER_EXEC_WRAPPER=1 in OpenClaw environment to use.

set -euo pipefail

# Configuration
SNAPPER_URL="${SNAPPER_URL:-http://127.0.0.1:8000}"
SNAPPER_API_KEY="${SNAPPER_API_KEY:-}"
SNAPPER_AGENT_ID="${SNAPPER_AGENT_ID:-openclaw-main}"
SNAPPER_TIMEOUT="${SNAPPER_TIMEOUT:-5}"

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Build the full command from args
COMMAND="$*"

# Skip empty commands
if [[ -z "$COMMAND" ]]; then
    exit 0
fi

# Build curl headers
HEADERS=(-H "Content-Type: application/json")
if [[ -n "$SNAPPER_API_KEY" ]]; then
    HEADERS+=(-H "X-API-Key: $SNAPPER_API_KEY")
fi

# Call Snapper's evaluate endpoint
RESPONSE=$(curl -s -m "$SNAPPER_TIMEOUT" -X POST \
    "${HEADERS[@]}" \
    -d "$(jq -n \
        --arg agent_id "$SNAPPER_AGENT_ID" \
        --arg request_type "command" \
        --arg command "$COMMAND" \
        '{agent_id: $agent_id, request_type: $request_type, command: $command}')" \
    "${SNAPPER_URL}/api/v1/rules/evaluate" 2>/dev/null || echo '{"decision":"error","reason":"Snapper unreachable"}')

# Parse the decision
DECISION=$(echo "$RESPONSE" | jq -r '.decision // "error"')
REASON=$(echo "$RESPONSE" | jq -r '.reason // "Unknown error"')
RULE_NAME=$(echo "$RESPONSE" | jq -r '.matched_rule_name // "N/A"')

case "$DECISION" in
    "allow")
        # Command allowed - execute it
        exec bash -c "$COMMAND"
        ;;
    "deny")
        echo -e "${RED}BLOCKED by Snapper${NC}" >&2
        echo -e "  Reason: $REASON" >&2
        if [[ "$RULE_NAME" != "null" && "$RULE_NAME" != "N/A" ]]; then
            echo -e "  Rule: $RULE_NAME" >&2
        fi
        exit 1
        ;;
    "require_approval")
        APPROVAL_ID=$(echo "$RESPONSE" | jq -r '.approval_request_id // "unknown"')
        echo -e "${YELLOW}APPROVAL REQUIRED${NC}" >&2
        echo -e "  Approval ID: $APPROVAL_ID" >&2
        echo -e "  Check Telegram for approval request" >&2
        exit 2
        ;;
    "error")
        # If Snapper is unreachable, fail open or closed based on config
        if [[ "${SNAPPER_FAIL_OPEN:-false}" == "true" ]]; then
            echo -e "${YELLOW}Warning: Snapper unreachable, allowing command${NC}" >&2
            exec bash -c "$COMMAND"
        else
            echo -e "${RED}Snapper Error: $REASON${NC}" >&2
            exit 1
        fi
        ;;
    *)
        echo -e "${RED}Unexpected Snapper response: $DECISION${NC}" >&2
        exit 1
        ;;
esac
