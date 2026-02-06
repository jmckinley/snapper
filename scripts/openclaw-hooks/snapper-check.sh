#!/bin/sh
CMD="$*"
RESP=$(wget -qO- --post-data="{\"agent_id\": \"openclaw-main\", \"request_type\": \"command\", \"command\": \"$CMD\"}" \
  --header="Content-Type: application/json" \
  --header="X-API-Key: snp_DFlHdJhpjhBfb_WRE8RB7j0CuPUnISRZSVv2x07WWBI" \
  http://host.docker.internal:8000/api/v1/rules/evaluate 2>/dev/null)
case "$RESP" in *deny*) echo "BLOCKED by Snapper" >&2; exit 1 ;; esac
exec "$@"
