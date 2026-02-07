#!/usr/bin/env bash
# Snapper - One-Click Production Deployment Script
# Usage: ./deploy.sh [--host HOST] [--port PORT] [--repo URL]
#
# This script handles the full deployment lifecycle:
#   1. Clone or update the repository
#   2. Generate production .env from template
#   3. Build and start Docker containers
#   4. Run database migrations
#   5. Configure Caddy reverse proxy
#   6. Open firewall port
#   7. Verify deployment health

set -euo pipefail

# ─── Configuration ──────────────────────────────────────────────────────────
INSTALL_DIR="/opt/snapper"
REPO_URL="https://github.com/jmckinley/snapper.git"
CADDY_CERT_DIR="/etc/caddy/certs"
CADDYFILE="/etc/caddy/Caddyfile"
SNAPPER_PORT="${1:-8443}"  # External HTTPS port
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

if [[ ${#MISSING_BASIC[@]} -eq 0 && "$NEED_DOCKER" == "false" && "$NEED_CADDY" == "false" ]]; then
    ok "All prerequisites found"
else
    echo ""
    warn "Missing prerequisites detected:"
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
        read -r -p "Install missing prerequisites? [y/N] " INSTALL_CONFIRM
        echo ""

        if [[ "${INSTALL_CONFIRM,,}" != "y" ]]; then
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
        ok "All prerequisites installed and verified"
    else
        err "Automatic install is only supported on Ubuntu/Debian."
        err "Please install the missing tools manually:"
        err "  Docker: https://docs.docker.com/engine/install/"
        err "  Caddy:  https://caddyserver.com/docs/install"
        exit 1
    fi
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
    # Detect the server's public IP
    SERVER_IP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

    if [[ -z "$SERVER_IP" ]]; then
        err "Could not detect server IP automatically."
        err "Re-run with: SERVER_IP=your.ip.here ./deploy.sh"
        exit 1
    fi

    SECRET_KEY=$(openssl rand -hex 32)

    log "Generating .env for server IP: $SERVER_IP"

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

# Security settings
DENY_BY_DEFAULT=true
REQUIRE_LOCALHOST_ONLY=false
ALLOWED_ORIGINS=https://${SERVER_IP}:${SNAPPER_PORT}
ALLOWED_HOSTS=${SERVER_IP},localhost,app
CORS_ORIGINS=https://${SERVER_IP}:${SNAPPER_PORT}

# Production mode
DEBUG=false
LOG_LEVEL=INFO
ENVIRONMENT=production

# Notifications (configure as needed)
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
ENVEOF

    chmod 600 "$INSTALL_DIR/.env"
    ok "Production .env generated (SECRET_KEY: ${SECRET_KEY:0:8}...)"
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
log "Configuring Caddy reverse proxy on port $SNAPPER_PORT..."

if [[ ! -f "$CADDYFILE" ]]; then
    warn "Caddyfile not found at $CADDYFILE, skipping Caddy configuration"
    warn "You'll need to manually configure your reverse proxy"
else
    # Check if snapper block already exists
    if grep -q ":${SNAPPER_PORT}" "$CADDYFILE" 2>/dev/null; then
        ok "Caddy already configured for port $SNAPPER_PORT"
    else
        # Generate self-signed cert if none exists
        if [[ ! -f "$CADDY_CERT_DIR/cert.pem" ]]; then
            log "Generating self-signed TLS certificate..."
            mkdir -p "$CADDY_CERT_DIR"
            openssl req -x509 -newkey rsa:4096 -keyout "$CADDY_CERT_DIR/key.pem" \
                -out "$CADDY_CERT_DIR/cert.pem" -days 365 -nodes \
                -subj "/CN=snapper" 2>/dev/null
            ok "Self-signed certificate generated"
        fi

        # Append Snapper block to Caddyfile
        cat >> "$CADDYFILE" <<CADDYEOF

:${SNAPPER_PORT} {
    tls ${CADDY_CERT_DIR}/cert.pem ${CADDY_CERT_DIR}/key.pem
    reverse_proxy localhost:8000
}
CADDYEOF

        if ! caddy reload --config "$CADDYFILE" 2>/dev/null; then
            warn "Caddy reload failed. Validate config: caddy validate --config $CADDYFILE"
        fi
        ok "Caddy configured"
    fi
fi

# ─── Step 7: Open Firewall Port ────────────────────────────────────────────
if command -v ufw &>/dev/null; then
    if ufw status | grep -q "Status: active"; then
        if ! ufw status | grep -q "${SNAPPER_PORT}/tcp"; then
            log "Opening port $SNAPPER_PORT in UFW..."
            ufw allow "${SNAPPER_PORT}/tcp" >/dev/null
            ok "Firewall port $SNAPPER_PORT opened"
        else
            ok "Firewall port $SNAPPER_PORT already open"
        fi
    fi
fi

warn "If you use Hostinger, Hetzner, or another VPS provider, you may also"
warn "need to open port $SNAPPER_PORT in your provider's firewall panel."

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
    warn "External HTTPS check failed — Caddy may need configuration"
fi

# ─── Done ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Snapper deployed successfully!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Dashboard:  ${BLUE}https://${SERVER_IP:-localhost}:${SNAPPER_PORT}/${NC}"
echo -e "  API Docs:   ${BLUE}https://${SERVER_IP:-localhost}:${SNAPPER_PORT}/api/docs${NC}"
echo -e "  Health:     ${BLUE}https://${SERVER_IP:-localhost}:${SNAPPER_PORT}/health${NC}"
echo ""
echo -e "  Manage:     cd $INSTALL_DIR"
echo -e "  Logs:       $COMPOSE_CMD logs -f"
echo -e "  Stop:       $COMPOSE_CMD down"
echo -e "  Update:     git pull && $COMPOSE_CMD up -d --build --force-recreate"
echo ""
