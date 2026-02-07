#!/bin/sh
CMD="$*"
SNAPPER_API_KEY="${SNAPPER_API_KEY:?Set SNAPPER_API_KEY env var}"
RESP=$(wget -qO- --post-data="{\"agent_id\": \"openclaw-main\", \"request_type\": \"command\", \"command\": \"$CMD\"}" \
  --header="Content-Type: application/json" \
  --header="X-API-Key: $SNAPPER_API_KEY" \
  http://host.docker.internal:8000/api/v1/rules/evaluate 2>/dev/null)
case "$RESP" in *deny*) echo "BLOCKED by Snapper" >&2; exit 1 ;; esac
exec "$@"
