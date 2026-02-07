#!/bin/sh
# Bash wrapper that validates commands with Snapper
REAL_BASH="/bin/bash.real"
SNAPPER_API_KEY="${SNAPPER_API_KEY:?Set SNAPPER_API_KEY env var}"

# Get command from -c flag
CMD=""
for arg in "$@"; do
  if [ "$prev" = "-c" ]; then
    CMD="$arg"
    break
  fi
  prev="$arg"
done

# If no -c command or empty, just run bash
[ -z "$CMD" ] && exec $REAL_BASH "$@"

# Call Snapper
RESP=$(curl -sf -X POST "http://host.docker.internal:8000/api/v1/rules/evaluate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $SNAPPER_API_KEY" \
  -d "{\"agent_id\": \"openclaw-main\", \"request_type\": \"command\", \"command\": \"$CMD\"}" 2>/dev/null)

# Check for deny
if echo "$RESP" | grep -q "\"decision\":\"deny\""; then
  REASON=$(echo "$RESP" | sed "s/.*\"reason\":\"\([^\"]*\)\".*/\1/")
  echo "BLOCKED by Snapper: $REASON" >&2
  exit 1
fi

# Run the actual command
exec $REAL_BASH "$@"
