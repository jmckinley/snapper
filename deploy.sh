#!/usr/bin/env bash
# Snapper - One-Click Production Deployment Script
#
# Usage:
#   ./deploy.sh                                    # IP-based, self-signed TLS on :8443
#   ./deploy.sh --domain snapper.example.com       # Domain with auto Let's Encrypt
#   ./deploy.sh --port 9443                        # Custom HTTPS port
#   ./deploy.sh --repo https://github.com/you/snapper.git
#
# Options:
#   --domain DOMAIN   Domain name (enables automatic Let's Encrypt TLS)
#   --port PORT       External HTTPS port (default: 443 with domain, 8443 without)
#   --repo URL        Git repository URL (default: jmckinley/snapper)
#   --yes             Skip confirmation prompts (non-interactive mode)
#   --no-openclaw     Skip automatic OpenClaw detection and integration
#
# This script handles the full deployment lifecycle:
#   1. Clone or update the repository
#   2. Generate production .env from template
#   3. Build and start Docker containers
#   4. Run database migrations
#   5. Configure Caddy reverse proxy
#   6. Open firewall ports
#   7. Verify deployment health
#   8. OpenClaw auto-integration (if detected)
#   9. Security posture assessment

set -euo pipefail

# ─── Parse Arguments ─────────────────────────────────────────────────────────
DOMAIN=""
SERVER_HOST=""
SNAPPER_PORT=""
REPO_URL="https://github.com/jmckinley/snapper.git"
NON_INTERACTIVE=false
SKIP_OPENCLAW=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --domain)
            DOMAIN="$2"
            shift 2
            ;;
        --host)
            SERVER_HOST="$2"
            shift 2
            ;;
        --port)
            SNAPPER_PORT="$2"
            shift 2
            ;;
        --repo)
            REPO_URL="$2"
            shift 2
            ;;
        --yes|-y)
            NON_INTERACTIVE=true
            shift
            ;;
        --no-openclaw)
            SKIP_OPENCLAW=true
            shift
            ;;
        --help|-h)
            head -26 "$0" | tail -25
            exit 0
            ;;
        *)
            # Legacy: first positional arg is port
            if [[ -z "$SNAPPER_PORT" && "$1" =~ ^[0-9]+$ ]]; then
                SNAPPER_PORT="$1"
            else
                echo "Unknown option: $1" >&2
                echo "Run ./deploy.sh --help for usage" >&2
                exit 1
            fi
            shift
            ;;
    esac
done

# Default port: 443 for domain (standard HTTPS), 8443 for IP-only
if [[ -z "$SNAPPER_PORT" ]]; then
    if [[ -n "$DOMAIN" ]]; then
        SNAPPER_PORT="443"
    else
        SNAPPER_PORT="8443"
    fi
fi

# ─── Configuration ──────────────────────────────────────────────────────────
INSTALL_DIR="/opt/snapper"
CADDY_CERT_DIR="/etc/caddy/certs"
CADDYFILE="/etc/caddy/Caddyfile"
COMPOSE_CMD="docker compose -f docker-compose.yml -f docker-compose.prod.yml"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log()  { echo -e "${BLUE}[snapper]${NC} $1"; }
ok()   { echo -e "${GREEN}[  ok  ]${NC} $1"; }
warn() { echo -e "${YELLOW}[ warn ]${NC} $1"; }
err()  { echo -e "${RED}[error ]${NC} $1" >&2; }

confirm() {
    # Usage: confirm "Install prerequisites?" || exit 1
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        return 0
    fi
    local prompt="$1"
    read -r -p "$prompt [y/N] " response
    echo ""
    [[ "$response" == "y" || "$response" == "Y" ]]
}

# ─── Preflight Checks ──────────────────────────────────────────────────────
log "Running preflight checks..."

if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root"
    exit 1
fi

# ─── OS / RAM / Installer Helpers ─────────────────────────────────────────

check_os() {
    IS_UBUNTU_DEBIAN=no
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        if [[ "$ID" == "ubuntu" || "$ID" == "debian" || "${ID_LIKE:-}" == *debian* ]]; then
            IS_UBUNTU_DEBIAN=yes
        fi
    fi
}

check_ram() {
    if [[ -f /proc/meminfo ]]; then
        local mem_kb
        mem_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
        local mem_gb=$(( mem_kb / 1024 / 1024 ))
        if [[ $mem_gb -lt 4 ]]; then
            warn "Low RAM detected (~${mem_gb}GB). Snapper recommends 4GB+."
            warn "Consider adding swap:"
            warn "  fallocate -l 2G /swapfile"
            warn "  chmod 600 /swapfile"
            warn "  mkswap /swapfile && swapon /swapfile"
            warn "  echo '/swapfile none swap sw 0 0' >> /etc/fstab"
            echo ""
        fi
    fi
}

install_basic_tools() {
    # Usage: install_basic_tools git curl openssl
    local pkgs=("$@")
    log "Installing basic tools: ${pkgs[*]}..."
    apt-get update -qq
    apt-get install -y -qq "${pkgs[@]}"
    ok "Installed: ${pkgs[*]}"
}

install_docker() {
    log "Installing Docker Engine from official repository..."

    # Remove conflicting packages
    local conflicts=(docker.io docker-doc docker-compose podman-docker containerd runc)
    for pkg in "${conflicts[@]}"; do
        apt-get remove -y -qq "$pkg" 2>/dev/null || true
    done

    # Ensure prerequisites for the repo setup
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl gnupg

    # Add Docker GPG key
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/${ID}/gpg" \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    # Add Docker apt repo
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
      https://download.docker.com/linux/${ID} ${VERSION_CODENAME} stable" \
      > /etc/apt/sources.list.d/docker.list

    # Install Docker packages
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin

    systemctl start docker
    systemctl enable docker

    if docker compose version &>/dev/null; then
        ok "Docker Engine + Compose plugin installed"
    else
        err "Docker installed but 'docker compose' not working"
        exit 1
    fi
}

install_caddy() {
    log "Installing Caddy from official repository..."

    apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl

    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
        | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg

    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
        > /etc/apt/sources.list.d/caddy-stable.list

    apt-get update -qq
    apt-get install -y -qq caddy

    if caddy version &>/dev/null; then
        ok "Caddy installed"
    else
        err "Caddy installation failed"
        exit 1
    fi
}

# ─── Detect and Offer to Install Prerequisites ───────────────────────────

check_os
check_ram

MISSING_BASIC=()
for cmd in git curl openssl; do
    if ! command -v "$cmd" &>/dev/null; then
        MISSING_BASIC+=("$cmd")
    fi
done

NEED_DOCKER=false
if ! command -v docker &>/dev/null || ! docker compose version &>/dev/null; then
    NEED_DOCKER=true
fi

NEED_CADDY=false
if ! command -v caddy &>/dev/null; then
    NEED_CADDY=true
fi

NEED_UFW=false
if ! command -v ufw &>/dev/null; then
    NEED_UFW=true
fi

if [[ ${#MISSING_BASIC[@]} -eq 0 && "$NEED_DOCKER" == "false" && "$NEED_CADDY" == "false" && "$NEED_UFW" == "false" ]]; then
    ok "All prerequisites found"
else
    # ── Required prerequisites ────────────────────────────────────────
    if [[ ${#MISSING_BASIC[@]} -gt 0 || "$NEED_DOCKER" == "true" || "$NEED_CADDY" == "true" ]]; then
        echo ""
        warn "Missing required prerequisites:"
        if [[ ${#MISSING_BASIC[@]} -gt 0 ]]; then
            warn "  - Basic tools: ${MISSING_BASIC[*]}"
        fi
        if [[ "$NEED_DOCKER" == "true" ]]; then
            warn "  - Docker Engine + Compose plugin"
        fi
        if [[ "$NEED_CADDY" == "true" ]]; then
            warn "  - Caddy web server"
        fi
        echo ""

        if [[ "$IS_UBUNTU_DEBIAN" == "yes" ]]; then
            echo -e "This script can install them automatically from official repositories."
            if ! confirm "Install missing prerequisites?"; then
                err "Cannot continue without prerequisites. Install them manually and re-run."
                exit 1
            fi

            # Install in order: basic tools first (curl needed by Docker/Caddy installers)
            if [[ ${#MISSING_BASIC[@]} -gt 0 ]]; then
                install_basic_tools "${MISSING_BASIC[@]}"
            fi
            if [[ "$NEED_DOCKER" == "true" ]]; then
                install_docker
            fi
            if [[ "$NEED_CADDY" == "true" ]]; then
                install_caddy
            fi

            # Final verification
            for cmd in git docker curl openssl caddy; do
                if ! command -v "$cmd" &>/dev/null; then
                    err "Installation completed but '$cmd' still not found"
                    exit 1
                fi
            done
            if ! docker compose version &>/dev/null; then
                err "Installation completed but 'docker compose' still not working"
                exit 1
            fi
            ok "All required prerequisites installed and verified"
        else
            err "Automatic install is only supported on Ubuntu/Debian."
            err "Please install the missing tools manually:"
            err "  Docker: https://docs.docker.com/engine/install/"
            err "  Caddy:  https://caddyserver.com/docs/install"
            exit 1
        fi
    else
        ok "All required prerequisites found"
    fi

    # ── Optional: UFW firewall ────────────────────────────────────────
    if [[ "$NEED_UFW" == "true" ]]; then
        echo ""
        warn "UFW firewall is not installed."
        warn "It's recommended for VPS deployments but not strictly required"
        warn "(you may have iptables, nftables, or a provider-level firewall)."

        if [[ "$IS_UBUNTU_DEBIAN" == "yes" ]]; then
            if confirm "Install UFW?"; then
                log "Installing UFW..."
                apt-get update -qq
                apt-get install -y -qq ufw
                ok "UFW installed"
            else
                warn "Skipping UFW — make sure you have another firewall in place."
            fi
        else
            warn "Install a firewall manually if your provider doesn't offer one."
        fi
    fi
fi

# ─── Resolve Server Identity ─────────────────────────────────────────────
# Determine the public-facing hostname: domain > --host flag > auto-detect IP

if [[ -n "$DOMAIN" ]]; then
    SERVER_LABEL="$DOMAIN"
    log "Using domain: $DOMAIN"
elif [[ -n "$SERVER_HOST" ]]; then
    SERVER_LABEL="$SERVER_HOST"
    log "Using provided host: $SERVER_HOST"
else
    SERVER_LABEL=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    if [[ -z "$SERVER_LABEL" ]]; then
        err "Could not detect server IP automatically."
        err "Re-run with: ./deploy.sh --host YOUR_IP"
        exit 1
    fi
    log "Detected server IP: $SERVER_LABEL"
fi

# Build the external URL
if [[ "$SNAPPER_PORT" == "443" ]]; then
    EXTERNAL_URL="https://${SERVER_LABEL}"
else
    EXTERNAL_URL="https://${SERVER_LABEL}:${SNAPPER_PORT}"
fi

# ─── Step 1: Clone or Update Repository ────────────────────────────────────
log "Setting up repository at $INSTALL_DIR..."

if [[ -d "$INSTALL_DIR/.git" ]]; then
    log "Repository exists, pulling latest changes..."
    cd "$INSTALL_DIR"
    git pull
    ok "Repository updated"
else
    log "Cloning repository..."
    git clone "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
    ok "Repository cloned"
fi

# ─── Step 2: Generate Production .env ──────────────────────────────────────
log "Configuring environment..."

if [[ -f "$INSTALL_DIR/.env" ]]; then
    warn ".env already exists, keeping existing configuration"
    warn "To regenerate, delete $INSTALL_DIR/.env and re-run this script"
else
    SECRET_KEY=$(openssl rand -hex 32)

    log "Generating production .env..."

    # Build ALLOWED_HOSTS: include domain/IP + internal names
    ALLOWED_HOSTS_VALUE="${SERVER_LABEL},localhost,127.0.0.1,app,host.docker.internal"

    cat > "$INSTALL_DIR/.env" <<ENVEOF
# Snapper Production Environment
# Generated by deploy.sh on $(date -u +"%Y-%m-%d %H:%M:%S UTC")

# Security
SECRET_KEY=${SECRET_KEY}

# Database & Cache (Docker internal networking)
DATABASE_URL=postgresql+asyncpg://snapper:snapper@postgres:5432/snapper
REDIS_URL=redis://redis:6379/0
CELERY_BROKER_URL=redis://redis:6379/1
CELERY_RESULT_BACKEND=redis://redis:6379/2

# Security settings (production-hardened defaults)
LEARNING_MODE=false
DENY_BY_DEFAULT=true
REQUIRE_API_KEY=true
REQUIRE_VAULT_AUTH=true
REQUIRE_LOCALHOST_ONLY=false
VALIDATE_WEBSOCKET_ORIGIN=true
ALLOWED_ORIGINS=${EXTERNAL_URL}
ALLOWED_HOSTS=${ALLOWED_HOSTS_VALUE}
CORS_ORIGINS=${EXTERNAL_URL}

# Production mode
DEBUG=false
LOG_LEVEL=INFO
ENVIRONMENT=production

# Notifications (configure after deploy — see docs/TELEGRAM_SETUP.md)
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
ENVEOF

    chmod 600 "$INSTALL_DIR/.env"
    ok "Production .env generated (SECRET_KEY: ${SECRET_KEY:0:8}...)"
    log "  ALLOWED_ORIGINS=${EXTERNAL_URL}"
    log "  ALLOWED_HOSTS=${ALLOWED_HOSTS_VALUE}"
    log "  LEARNING_MODE=false, DENY_BY_DEFAULT=true"
    log "  REQUIRE_API_KEY=true, REQUIRE_VAULT_AUTH=true"
fi

# ─── Step 3: Build and Start Containers ────────────────────────────────────
log "Building and starting containers..."

cd "$INSTALL_DIR"
if ! $COMPOSE_CMD up -d --build --force-recreate; then
    err "Docker Compose failed. Check: $COMPOSE_CMD logs app"
    exit 1
fi

# Wait for postgres and redis to be healthy
log "Waiting for database and cache to be ready..."
RETRIES=0
while ! $COMPOSE_CMD exec -T postgres pg_isready -U snapper -d snapper 2>/dev/null; do
    RETRIES=$((RETRIES + 1))
    if [[ $RETRIES -ge 30 ]]; then
        err "PostgreSQL not ready after 30s. Check: $COMPOSE_CMD logs postgres"
        exit 1
    fi
    sleep 1
done
ok "Containers started"

# ─── Step 4: Run Database Migrations ───────────────────────────────────────
log "Running database migrations..."

if ! $COMPOSE_CMD run --rm app alembic upgrade head; then
    err "Migration failed. Check: $COMPOSE_CMD run --rm app alembic current"
    exit 1
fi
ok "Migrations complete"

# ─── Step 5: Restart App (pick up migrated schema) ─────────────────────────
log "Restarting app container..."

$COMPOSE_CMD up -d --force-recreate
ok "App restarted"

# ─── Step 6: Configure Caddy Reverse Proxy ─────────────────────────────────

if [[ -n "$DOMAIN" ]]; then
    log "Configuring Caddy with automatic Let's Encrypt TLS for $DOMAIN..."
else
    log "Configuring Caddy reverse proxy on port $SNAPPER_PORT..."
fi

if [[ ! -f "$CADDYFILE" ]]; then
    # No existing Caddyfile — create one from scratch
    log "Creating Caddyfile at $CADDYFILE..."
    mkdir -p "$(dirname "$CADDYFILE")"
    echo "# Managed by Snapper deploy.sh" > "$CADDYFILE"
fi

# Determine if Snapper block already exists
CADDY_ALREADY_CONFIGURED=false
if [[ -n "$DOMAIN" ]]; then
    grep -q "^${DOMAIN}" "$CADDYFILE" 2>/dev/null && CADDY_ALREADY_CONFIGURED=true
else
    grep -q ":${SNAPPER_PORT}" "$CADDYFILE" 2>/dev/null && CADDY_ALREADY_CONFIGURED=true
fi

if [[ "$CADDY_ALREADY_CONFIGURED" == "true" ]]; then
    ok "Caddy already configured"
else
    if [[ -n "$DOMAIN" ]]; then
        # Domain mode: Caddy auto-obtains Let's Encrypt certificate
        if [[ "$SNAPPER_PORT" == "443" ]]; then
            cat >> "$CADDYFILE" <<CADDYEOF

${DOMAIN} {
    reverse_proxy localhost:8000
}
CADDYEOF
        else
            cat >> "$CADDYFILE" <<CADDYEOF

${DOMAIN}:${SNAPPER_PORT} {
    reverse_proxy localhost:8000
}
CADDYEOF
        fi
        ok "Caddy configured with automatic Let's Encrypt for $DOMAIN"
    else
        # IP-only mode: self-signed certificate
        if [[ ! -f "$CADDY_CERT_DIR/cert.pem" ]]; then
            log "Generating self-signed TLS certificate..."
            mkdir -p "$CADDY_CERT_DIR"
            openssl req -x509 -newkey rsa:4096 -keyout "$CADDY_CERT_DIR/key.pem" \
                -out "$CADDY_CERT_DIR/cert.pem" -days 365 -nodes \
                -subj "/CN=snapper" 2>/dev/null
            ok "Self-signed certificate generated"
        fi

        cat >> "$CADDYFILE" <<CADDYEOF

:${SNAPPER_PORT} {
    tls ${CADDY_CERT_DIR}/cert.pem ${CADDY_CERT_DIR}/key.pem
    reverse_proxy localhost:8000
}
CADDYEOF
        ok "Caddy configured with self-signed TLS on port $SNAPPER_PORT"
    fi

    if ! caddy reload --config "$CADDYFILE" 2>/dev/null; then
        warn "Caddy reload failed. Validate config: caddy validate --config $CADDYFILE"
    fi
fi

# ─── Step 7: Open Firewall Ports ──────────────────────────────────────────
if command -v ufw &>/dev/null; then
    if ufw status | grep -q "Status: active"; then
        # Always open the HTTPS port
        if ! ufw status | grep -q "${SNAPPER_PORT}/tcp"; then
            log "Opening port $SNAPPER_PORT in UFW..."
            ufw allow "${SNAPPER_PORT}/tcp" >/dev/null
            ok "Firewall port $SNAPPER_PORT opened"
        else
            ok "Firewall port $SNAPPER_PORT already open"
        fi

        # Domain mode needs ports 80+443 for Let's Encrypt ACME challenge
        if [[ -n "$DOMAIN" ]]; then
            if ! ufw status | grep -q "80/tcp"; then
                log "Opening port 80 for Let's Encrypt ACME challenge..."
                ufw allow 80/tcp >/dev/null
                ok "Firewall port 80 opened (ACME)"
            fi
            if [[ "$SNAPPER_PORT" != "443" ]] && ! ufw status | grep -q "443/tcp"; then
                log "Opening port 443 for Let's Encrypt..."
                ufw allow 443/tcp >/dev/null
                ok "Firewall port 443 opened"
            fi
        fi
    fi
fi

warn "If you use Hostinger, Hetzner, or another VPS provider, you may also"
warn "need to open port $SNAPPER_PORT in your provider's firewall panel."
if [[ -n "$DOMAIN" ]]; then
    warn "For Let's Encrypt, ports 80 and 443 must also be open."
fi

# ─── Step 8: Verify Deployment ─────────────────────────────────────────────
log "Verifying deployment..."

# Wait for app to be healthy
sleep 5

# Check internal health
if curl -sf http://127.0.0.1:8000/health >/dev/null 2>&1; then
    ok "App health check passed (internal)"
else
    err "App health check failed on localhost:8000"
    log "Check logs with: cd $INSTALL_DIR && $COMPOSE_CMD logs app"
    exit 1
fi

# Check readiness (DB + Redis)
READY=$(curl -sf http://127.0.0.1:8000/health/ready 2>/dev/null || echo '{}')
if echo "$READY" | grep -q '"status":"ready"'; then
    ok "Database and Redis connected"
else
    warn "Readiness check returned: $READY"
fi

# Check external access via Caddy
if curl -skf "https://127.0.0.1:${SNAPPER_PORT}/health" >/dev/null 2>&1; then
    ok "External access via Caddy working"
else
    if [[ -n "$DOMAIN" ]]; then
        warn "External HTTPS check failed — Let's Encrypt may need a few seconds"
        warn "Verify: curl -k ${EXTERNAL_URL}/health"
    else
        warn "External HTTPS check failed — Caddy may need configuration"
    fi
fi

# ─── Step 9: OpenClaw Integration ─────────────────────────────────────────
if [[ "$SKIP_OPENCLAW" == "false" ]]; then
    log "Checking for OpenClaw..."

    OPENCLAW_DIR=""
    OPENCLAW_CONTAINER=""
    OPENCLAW_HOOKS_DIR=""

    # Check for OpenClaw directory
    for dir in /opt/openclaw "$HOME/.openclaw"; do
        if [[ -d "$dir" ]]; then
            OPENCLAW_DIR="$dir"
            break
        fi
    done

    # Check for running OpenClaw container
    OPENCLAW_CONTAINER=$(docker ps --filter "name=openclaw" --filter "status=running" --format '{{.Names}}' | head -1)

    # Determine hooks directory
    if [[ -n "$OPENCLAW_CONTAINER" ]]; then
        OPENCLAW_HOOKS_DIR=$(docker inspect "$OPENCLAW_CONTAINER" --format '{{range .Mounts}}{{if eq .Destination "/app/hooks"}}{{.Source}}{{end}}{{end}}' 2>/dev/null)
    fi
    if [[ -z "$OPENCLAW_HOOKS_DIR" && -n "$OPENCLAW_DIR" ]]; then
        OPENCLAW_HOOKS_DIR="$OPENCLAW_DIR/hooks"
    fi

    if [[ -n "$OPENCLAW_DIR" || -n "$OPENCLAW_CONTAINER" ]]; then
        log "OpenClaw detected! Configuring integration..."

        # Register agent via quick-register API (also applies OpenClaw templates)
        REG_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST http://127.0.0.1:8000/api/v1/setup/quick-register \
            -H "Content-Type: application/json" \
            -d '{"agent_type":"openclaw","security_profile":"recommended"}' 2>/dev/null)
        HTTP_CODE=$(echo "$REG_RESPONSE" | tail -1)
        REG_BODY=$(echo "$REG_RESPONSE" | sed '$d')

        if [[ "$HTTP_CODE" == "200" ]]; then
            OC_AGENT_ID=$(echo "$REG_BODY" | grep -o '"agent_id":"[^"]*"' | cut -d'"' -f4)
            OC_API_KEY=$(echo "$REG_BODY" | grep -o '"api_key":"[^"]*"' | cut -d'"' -f4)
            OC_RULES=$(echo "$REG_BODY" | grep -o '"rules_applied":[0-9]*' | cut -d: -f2)
            ok "OpenClaw agent registered ($OC_RULES security rules applied)"
        elif [[ "$HTTP_CODE" == "409" ]]; then
            ok "OpenClaw agent already registered (re-run detected)"
        else
            warn "Agent registration failed (HTTP $HTTP_CODE) — configure manually at ${EXTERNAL_URL}/wizard"
        fi

        # Copy shell hooks
        if [[ -n "$OPENCLAW_HOOKS_DIR" ]]; then
            mkdir -p "$OPENCLAW_HOOKS_DIR"
            cp "$INSTALL_DIR/scripts/openclaw-hooks/"*.sh "$OPENCLAW_HOOKS_DIR/" 2>/dev/null && \
                chmod +x "$OPENCLAW_HOOKS_DIR/"*.sh
            ok "Shell hooks installed to $OPENCLAW_HOOKS_DIR"
        fi

        # Inject SNAPPER env vars into OpenClaw's .env (only on fresh registration)
        if [[ -n "${OC_API_KEY:-}" && -n "$OPENCLAW_DIR" ]]; then
            OC_ENV="$OPENCLAW_DIR/.env"
            if [[ -f "$OC_ENV" ]]; then
                sed -i '/^SNAPPER_URL=/d; /^SNAPPER_API_KEY=/d' "$OC_ENV"
            fi
            echo "SNAPPER_URL=http://127.0.0.1:8000" >> "$OC_ENV"
            echo "SNAPPER_API_KEY=$OC_API_KEY" >> "$OC_ENV"
            ok "SNAPPER_URL and SNAPPER_API_KEY written to $OC_ENV"
        fi

        # Copy snapper-guard plugin
        if [[ -n "$OPENCLAW_DIR" ]]; then
            PLUGIN_DEST="$OPENCLAW_DIR/extensions/snapper-guard"
            if [[ ! -d "$PLUGIN_DEST" ]]; then
                mkdir -p "$PLUGIN_DEST"
                cp "$INSTALL_DIR/plugins/snapper-guard/"* "$PLUGIN_DEST/" 2>/dev/null
                ok "snapper-guard plugin installed to $PLUGIN_DEST"
            else
                ok "snapper-guard plugin already installed"
            fi
        fi

        # Offer to restart OpenClaw gateway to activate hooks + env vars
        if [[ -n "$OPENCLAW_CONTAINER" ]]; then
            if confirm "Restart OpenClaw gateway to activate Snapper integration?"; then
                docker restart "$OPENCLAW_CONTAINER"
                ok "OpenClaw gateway restarted"
            else
                warn "Remember to restart OpenClaw manually to activate hooks"
            fi
        fi
    else
        log "OpenClaw not detected on this server"
        log "You can register agents later at ${EXTERNAL_URL}/wizard"
    fi
fi

# ─── Step 10: Security Posture Assessment ────────────────────────────────
echo ""
log "Running security posture assessment..."
echo ""

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

sec_pass() { echo -e "  ${GREEN}PASS${NC}  $1"; PASS_COUNT=$((PASS_COUNT + 1)); }
sec_warn() { echo -e "  ${YELLOW}WARN${NC}  $1"; WARN_COUNT=$((WARN_COUNT + 1)); }
sec_fail() { echo -e "  ${RED}FAIL${NC}  $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }

# Docker deployment
if docker compose version &>/dev/null; then
    sec_pass "Running in Docker containers"
else
    sec_fail "Docker not detected — Snapper must run in Docker"
fi

# App port binding (check if bound to 127.0.0.1 only)
APP_PORT_BINDING=$($COMPOSE_CMD port app 8000 2>/dev/null || echo "")
if echo "$APP_PORT_BINDING" | grep -q "^127\.0\.0\.1:"; then
    sec_pass "App bound to 127.0.0.1 (not externally accessible)"
elif echo "$APP_PORT_BINDING" | grep -q "^0\.0\.0\.0:"; then
    sec_fail "App bound to 0.0.0.0 — accessible from network, bypassing TLS"
    echo -e "         Fix: Use docker-compose.prod.yml (binds to 127.0.0.1)"
else
    sec_warn "Could not detect app port binding"
fi

# PostgreSQL not exposed
# `docker compose port` returns ":0" when no host port is mapped
PG_PORT_BINDING=$($COMPOSE_CMD port postgres 5432 2>/dev/null || echo "")
if [[ -z "$PG_PORT_BINDING" || "$PG_PORT_BINDING" == ":0" ]]; then
    sec_pass "PostgreSQL not exposed to host (Docker-internal only)"
else
    sec_fail "PostgreSQL exposed on $PG_PORT_BINDING — no auth by default!"
    echo -e "         Fix: Remove ports from postgres service in docker-compose"
fi

# Redis not exposed
REDIS_PORT_BINDING=$($COMPOSE_CMD port redis 6379 2>/dev/null || echo "")
if [[ -z "$REDIS_PORT_BINDING" || "$REDIS_PORT_BINDING" == ":0" ]]; then
    sec_pass "Redis not exposed to host (Docker-internal only)"
else
    sec_fail "Redis exposed on $REDIS_PORT_BINDING — no auth by default!"
    echo -e "         Fix: Remove ports from redis service in docker-compose"
fi

# SECRET_KEY strength
if [[ -f "$INSTALL_DIR/.env" ]]; then
    SK=$(grep "^SECRET_KEY=" "$INSTALL_DIR/.env" 2>/dev/null | cut -d= -f2)
    if [[ -z "$SK" ]]; then
        sec_fail "SECRET_KEY is empty"
    elif [[ "$SK" == "development-secret-key-change-in-production" ]]; then
        sec_fail "SECRET_KEY is the development default — change it!"
    elif [[ ${#SK} -lt 32 ]]; then
        sec_fail "SECRET_KEY is too short (${#SK} chars, need 32+)"
    else
        sec_pass "SECRET_KEY is set (${#SK} chars)"
    fi
fi

# TLS / Caddy
if curl -skf "https://127.0.0.1:${SNAPPER_PORT}/health" >/dev/null 2>&1; then
    if [[ -n "$DOMAIN" ]]; then
        sec_pass "TLS termination working (Let's Encrypt via Caddy)"
    else
        sec_pass "TLS termination working (Caddy on port $SNAPPER_PORT)"
    fi
else
    sec_fail "TLS not working on port $SNAPPER_PORT — no HTTPS access"
    echo -e "         Fix: Configure Caddy with TLS certificate"
fi

# Firewall
if command -v ufw &>/dev/null; then
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        sec_pass "UFW firewall is active"
        # Check that port 8000 is NOT open
        if ufw status 2>/dev/null | grep -q "8000"; then
            sec_warn "Port 8000 is open in UFW — only $SNAPPER_PORT should be exposed"
        fi
    else
        sec_warn "UFW is installed but not active"
    fi
else
    sec_warn "UFW not installed — ensure another firewall is in place"
fi

# DENY_BY_DEFAULT / LEARNING_MODE / REQUIRE_API_KEY / REQUIRE_VAULT_AUTH
if [[ -f "$INSTALL_DIR/.env" ]]; then
    DBD=$(grep "^DENY_BY_DEFAULT=" "$INSTALL_DIR/.env" 2>/dev/null | cut -d= -f2 | tr '[:upper:]' '[:lower:]')
    LM=$(grep "^LEARNING_MODE=" "$INSTALL_DIR/.env" 2>/dev/null | cut -d= -f2 | tr '[:upper:]' '[:lower:]')

    if [[ "$LM" == "true" || -z "$LM" ]]; then
        sec_warn "Learning mode is ON — violations are logged but not blocked"
        echo -e "         Action: Set LEARNING_MODE=false when ready to enforce"
    else
        sec_pass "Learning mode is OFF — rules are enforced"
    fi

    if [[ "$DBD" == "true" ]]; then
        sec_pass "Deny-by-default is ON"
    else
        sec_warn "Deny-by-default is OFF — unknown requests are allowed"
        echo -e "         Action: Set DENY_BY_DEFAULT=true for enforcement"
    fi

    # REQUIRE_API_KEY
    RAK=$(grep "^REQUIRE_API_KEY=" "$INSTALL_DIR/.env" 2>/dev/null | cut -d= -f2 | tr '[:upper:]' '[:lower:]')
    if [[ "$RAK" == "true" ]]; then
        sec_pass "API key authentication required"
    else
        sec_warn "API key authentication not required"
        echo -e "         Action: Set REQUIRE_API_KEY=true for production"
    fi

    # REQUIRE_VAULT_AUTH
    RVA=$(grep "^REQUIRE_VAULT_AUTH=" "$INSTALL_DIR/.env" 2>/dev/null | cut -d= -f2 | tr '[:upper:]' '[:lower:]')
    if [[ "$RVA" == "true" ]]; then
        sec_pass "Vault write authentication required"
    else
        sec_warn "Vault writes don't require authentication"
        echo -e "         Action: Set REQUIRE_VAULT_AUTH=true for production"
    fi

    # Telegram
    TG_TOKEN=$(grep "^TELEGRAM_BOT_TOKEN=" "$INSTALL_DIR/.env" 2>/dev/null | cut -d= -f2)
    if [[ -n "$TG_TOKEN" ]]; then
        sec_pass "Telegram bot configured for approval alerts"
    else
        sec_warn "Telegram not configured — no approval notifications"
        echo -e "         Action: Add TELEGRAM_BOT_TOKEN to .env"
    fi

    # ALLOWED_HOSTS / ALLOWED_ORIGINS
    AH=$(grep "^ALLOWED_HOSTS=" "$INSTALL_DIR/.env" 2>/dev/null | cut -d= -f2)
    AO=$(grep "^ALLOWED_ORIGINS=" "$INSTALL_DIR/.env" 2>/dev/null | cut -d= -f2)
    if [[ -n "$AH" && "$AH" != "localhost" ]]; then
        sec_pass "ALLOWED_HOSTS configured"
    else
        sec_warn "ALLOWED_HOSTS may need your server IP or domain"
    fi
    if [[ -n "$AO" && "$AO" != "http://localhost:8000" ]]; then
        sec_pass "ALLOWED_ORIGINS configured"
    else
        sec_warn "ALLOWED_ORIGINS may need your server URL"
    fi
fi

# OpenClaw integration
if [[ "$SKIP_OPENCLAW" == "false" ]]; then
    if [[ -n "${OC_AGENT_ID:-}" ]]; then
        sec_pass "OpenClaw agent registered and rules applied"
    elif docker ps --filter "name=openclaw" --format '{{.Names}}' 2>/dev/null | grep -q openclaw; then
        sec_warn "OpenClaw detected but integration not configured"
    fi
fi

# Non-root user in container
APP_USER=$($COMPOSE_CMD exec -T app whoami 2>/dev/null || echo "unknown")
if [[ "$APP_USER" == "snapper" ]]; then
    sec_pass "App running as non-root user (snapper)"
elif [[ "$APP_USER" == "root" ]]; then
    sec_fail "App running as root inside container!"
    echo -e "         Fix: Use production Dockerfile target"
fi

# Print summary
echo ""
echo -e "  ─────────────────────────────────────"
echo -e "  ${GREEN}$PASS_COUNT passed${NC}  ${YELLOW}$WARN_COUNT warnings${NC}  ${RED}$FAIL_COUNT failed${NC}"

if [[ $FAIL_COUNT -gt 0 ]]; then
    echo ""
    echo -e "  ${RED}Fix the failures above before exposing Snapper to the network.${NC}"
elif [[ $WARN_COUNT -gt 0 ]]; then
    echo ""
    echo -e "  ${YELLOW}Review warnings above. See docs/SECURITY.md for details.${NC}"
else
    echo ""
    echo -e "  ${GREEN}All security checks passed!${NC}"
fi

# ─── Done ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Snapper deployed successfully!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Dashboard:  ${BLUE}${EXTERNAL_URL}/${NC}"
echo -e "  API Docs:   ${BLUE}${EXTERNAL_URL}/api/docs${NC}"
echo -e "  Health:     ${BLUE}${EXTERNAL_URL}/health${NC}"
echo ""
echo -e "  Manage:     cd $INSTALL_DIR"
echo -e "  Logs:       $COMPOSE_CMD logs -f"
echo -e "  Stop:       $COMPOSE_CMD down"
echo -e "  Update:     git pull && $COMPOSE_CMD up -d --build --force-recreate"
echo ""
echo -e "  ${YELLOW}Next steps:${NC}"
if [[ -n "${OC_AGENT_ID:-}" ]]; then
    echo -e "    1. Open ${BLUE}${EXTERNAL_URL}/${NC} to see the dashboard"
    echo -e "    2. Set up Telegram alerts: see docs/TELEGRAM_SETUP.md"
    echo -e "    3. Test: Tell your OpenClaw agent to 'run rm -rf /' (should be blocked)"
else
    echo -e "    1. Open ${BLUE}${EXTERNAL_URL}/wizard${NC} to register your first agent"
    echo -e "    2. Set up Telegram alerts: see docs/TELEGRAM_SETUP.md"
    echo -e "    3. Run security check anytime: python3 scripts/snapper-cli.py security-check"
fi
echo ""
