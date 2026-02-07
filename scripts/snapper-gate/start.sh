#!/bin/bash
# Start the Snapper Approval Listener for OpenClaw
# Validates required environment variables before launching.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Load environment from .env file
if [ -f .env ]; then
    set -a
    source .env
    set +a
fi

# ── Validate required vars ────────────────────────────
MISSING=0

check_var() {
    local name="$1"
    local hint="$2"
    eval "local val=\${${name}:-}"
    if [ -z "$val" ]; then
        echo "[error] $name is not set." >&2
        echo "[error] $hint" >&2
        echo "" >&2
        MISSING=1
    fi
}

check_var OPENCLAW_GATEWAY_TOKEN \
    "Copy it from your OpenClaw .env (grep OPENCLAW_GATEWAY_TOKEN /opt/openclaw/.env)"

check_var SNAPPER_API_KEY \
    "Register an agent in Snapper and use the returned snp_xxx key."

check_var SNAPPER_URL \
    "Set to your Snapper API URL, e.g. http://127.0.0.1:8000"

if [ "$MISSING" -eq 1 ]; then
    echo "[error] Fix the above and re-run. See .env.example for a template." >&2
    exit 1
fi

# ── Launch ─────────────────────────────────────────────
echo "Starting Snapper Approval Listener..."
echo "Snapper URL: $SNAPPER_URL"
echo "Agent ID:    ${SNAPPER_AGENT_ID:-openclaw-main}"
echo "Gateway:     ${OPENCLAW_GATEWAY_URL:-ws://127.0.0.1:18789}"
echo "Token:       ${OPENCLAW_GATEWAY_TOKEN:0:8}..."

exec node snapper-approval-listener.js
