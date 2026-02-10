#!/bin/bash
# Snapper Shell Wrapper for OpenClaw
REAL_SHELL="/bin/bash"
SNAPPER_API_KEY="${SNAPPER_API_KEY:?Set SNAPPER_API_KEY env var}"

# If interactive or no args, just run shell
[ -t 0 ] && [ $# -eq 0 ] && exec $REAL_SHELL

# Get command
[ "$1" = "-c" ] && CMD="$2" || CMD="$*"
[ -z "$CMD" ] && exec $REAL_SHELL "$@"

# Call Snapper
RESP=$(curl -sf -X POST "${SNAPPER_URL:-http://127.0.0.1:8000}/api/v1/rules/evaluate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $SNAPPER_API_KEY" \
  -d "{\"agent_id\": \"openclaw-main\", \"request_type\": \"command\", \"command\": \"$CMD\"}" 2>/dev/null)

# Check decision
if echo "$RESP" | grep -q '"decision":"deny"'; then
  REASON=$(echo "$RESP" | sed 's/.*"reason":"\([^"]*\)".*/\1/')
  echo "BLOCKED by Snapper: $REASON" >&2
  exit 1
fi

if echo "$RESP" | grep -q '"decision":"require_approval"'; then
  echo "Approval required - check Telegram" >&2
  exit 1
fi

# Execute
exec $REAL_SHELL "$@"
