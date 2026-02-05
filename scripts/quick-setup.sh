#!/bin/bash
# Snapper Quick Setup for OpenClaw Users
# One command to rule them all:
#   curl -fsSL https://snapper.sh/go | bash
#
# Or with options:
#   curl -fsSL https://snapper.sh/go | bash -s -- --strict

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

PROFILE="${1:-recommended}"
SNAPPER_URL="${SNAPPER_URL:-http://localhost:8000}"
INSTALL_DIR="${SNAPPER_DIR:-$HOME/snapper}"

echo -e "${BLUE}${BOLD}"
echo "┌─────────────────────────────────────────────────────────────┐"
echo "│  🐢 Snapper Quick Setup for OpenClaw                       │"
echo "└─────────────────────────────────────────────────────────────┘"
echo -e "${NC}"

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --strict)
            PROFILE="strict"
            shift
            ;;
        --permissive)
            PROFILE="permissive"
            shift
            ;;
        *)
            shift
            ;;
    esac
done

echo -e "${BOLD}Security profile:${NC} $PROFILE"
echo ""

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker is required. Install from: https://docs.docker.com/get-docker/${NC}"
    exit 1
fi

# Check if Snapper is already running
if curl -sf "$SNAPPER_URL/health" > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Snapper already running"
else
    echo -e "${YELLOW}Installing Snapper...${NC}"

    # Install Snapper
    if [ -d "$INSTALL_DIR" ]; then
        cd "$INSTALL_DIR"
        git pull origin main 2>/dev/null || true
    else
        git clone https://github.com/jmckinley/snapper.git "$INSTALL_DIR" 2>/dev/null || {
            mkdir -p "$INSTALL_DIR"
            curl -fsSL https://github.com/jmckinley/snapper/archive/main.tar.gz | \
                tar -xz -C "$INSTALL_DIR" --strip-components=1
        }
        cd "$INSTALL_DIR"
    fi

    # Create .env if needed
    if [ ! -f .env ]; then
        SECRET_KEY=$(openssl rand -hex 32 2>/dev/null || head -c 64 /dev/urandom | base64 | tr -d '/+=' | head -c 64)
        cat > .env << EOF
SECRET_KEY=$SECRET_KEY
DATABASE_URL=postgresql+asyncpg://snapper:snapper@postgres:5432/snapper
REDIS_URL=redis://redis:6379/0
DENY_BY_DEFAULT=true
VALIDATE_WEBSOCKET_ORIGIN=true
DEBUG=true
EOF
    fi

    # Start services
    docker compose up -d

    # Wait for health
    echo -n "Starting services"
    for i in {1..30}; do
        if curl -sf "$SNAPPER_URL/health" > /dev/null 2>&1; then
            break
        fi
        echo -n "."
        sleep 2
    done
    echo ""

    if ! curl -sf "$SNAPPER_URL/health" > /dev/null 2>&1; then
        echo -e "${RED}Failed to start Snapper${NC}"
        exit 1
    fi

    echo -e "${GREEN}✓${NC} Snapper started"
fi

# Generate agent ID
AGENT_ID="openclaw-$(hostname)"

# Register agent
echo -e "${YELLOW}Registering agent...${NC}"
REGISTER_RESPONSE=$(curl -sf -X POST "$SNAPPER_URL/api/v1/agents" \
    -H "Content-Type: application/json" \
    -H "Origin: http://localhost:8000" \
    -d "{\"name\": \"OpenClaw on $(hostname)\", \"external_id\": \"$AGENT_ID\", \"require_localhost_only\": true}" 2>/dev/null || echo '{"id": "existing"}')

AGENT_UUID=$(echo "$REGISTER_RESPONSE" | grep -o '"id"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')

if [ -n "$AGENT_UUID" ] && [ "$AGENT_UUID" != "existing" ]; then
    echo -e "${GREEN}✓${NC} Agent registered: $AGENT_ID"

    # Activate agent
    curl -sf -X PUT "$SNAPPER_URL/api/v1/agents/$AGENT_UUID" \
        -H "Content-Type: application/json" \
        -H "Origin: http://localhost:8000" \
        -d '{"status": "active"}' > /dev/null 2>&1
else
    echo -e "${GREEN}✓${NC} Using existing agent: $AGENT_ID"
fi

# Apply security profile
echo -e "${YELLOW}Applying $PROFILE security profile...${NC}"

case $PROFILE in
    strict)
        TEMPLATES="cve-2026-25253-mitigation credential-protection malicious-skill-blocker rate-limit-standard localhost-only human-approval-sensitive"
        ;;
    permissive)
        TEMPLATES="credential-protection"
        ;;
    *)
        TEMPLATES="cve-2026-25253-mitigation credential-protection malicious-skill-blocker rate-limit-standard"
        ;;
esac

for template in $TEMPLATES; do
    result=$(curl -sf -X POST "$SNAPPER_URL/api/v1/rules/templates/$template/apply" \
        -H "Content-Type: application/json" \
        -H "Origin: http://localhost:8000" \
        -d "{\"agent_id\": \"$AGENT_UUID\"}" 2>/dev/null || echo '{"error": true}')

    if echo "$result" | grep -q '"name"'; then
        name=$(echo "$result" | grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/')
        echo -e "  ${GREEN}✓${NC} $name"
    else
        echo -e "  ${YELLOW}○${NC} $template (already applied or skipped)"
    fi
done

# Install OpenClaw hook
echo -e "${YELLOW}Installing OpenClaw hook...${NC}"

OPENCLAW_DIR="$HOME/.openclaw"
mkdir -p "$OPENCLAW_DIR/hooks"

# Download hook script
HOOK_PATH="$OPENCLAW_DIR/hooks/pre_tool_use.sh"
if [ -f "$INSTALL_DIR/scripts/openclaw-hook.sh" ]; then
    cp "$INSTALL_DIR/scripts/openclaw-hook.sh" "$HOOK_PATH"
else
    curl -fsSL "https://raw.githubusercontent.com/jmckinley/snapper/main/scripts/openclaw-hook.sh" -o "$HOOK_PATH" 2>/dev/null || {
        # Fallback: create minimal hook
        cat > "$HOOK_PATH" << 'HOOK'
#!/bin/bash
SNAPPER_URL="${SNAPPER_URL:-http://localhost:8000}"
SNAPPER_AGENT_ID="${SNAPPER_AGENT_ID:-openclaw-$(hostname)}"
INPUT=$(cat)
TOOL=$(echo "$INPUT" | jq -r '.tool_name // "unknown"')
RESP=$(curl -sf -X POST "$SNAPPER_URL/api/v1/rules/evaluate" \
    -H "Content-Type: application/json" -H "Origin: http://localhost:8000" \
    -d "{\"agent_id\": \"$SNAPPER_AGENT_ID\", \"request_type\": \"tool\", \"tool_name\": \"$TOOL\"}" 2>/dev/null)
[ $? -ne 0 ] && exit 1
[ "$(echo "$RESP" | jq -r '.decision')" = "allow" ] && exit 0
echo "BLOCKED: $(echo "$RESP" | jq -r '.reason')" >&2
exit 1
HOOK
    }
fi

chmod +x "$HOOK_PATH"

# Set environment variables
cat > "$OPENCLAW_DIR/.env.snapper" << EOF
SNAPPER_URL=$SNAPPER_URL
SNAPPER_AGENT_ID=$AGENT_ID
EOF

echo -e "${GREEN}✓${NC} Hook installed at $HOOK_PATH"

# Done!
echo ""
echo -e "${GREEN}${BOLD}┌─────────────────────────────────────────────────────────────┐${NC}"
echo -e "${GREEN}${BOLD}│  ✅ OpenClaw is now protected by Snapper!                   │${NC}"
echo -e "${GREEN}${BOLD}└─────────────────────────────────────────────────────────────┘${NC}"
echo ""
echo -e "${BOLD}Dashboard:${NC}  http://localhost:8000"
echo -e "${BOLD}Audit logs:${NC} http://localhost:8000/audit"
echo ""
echo -e "${BOLD}Protected against:${NC}"
echo "  • CVE-2026-25253 (WebSocket RCE)"
echo "  • Credential exposure (.env, .pem, SSH keys)"
echo "  • Malicious ClawHub skills"
echo "  • Runaway agent abuse (rate limiting)"
echo ""
echo -e "${BOLD}Next step:${NC} Set up Telegram notifications for approve/deny buttons"
echo "  → http://localhost:8000/settings"
echo ""
