#!/bin/bash
# Snapper - One-Command Install Script
# Usage: curl -fsSL https://raw.githubusercontent.com/snapper/snapper/main/install.sh | bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print banner
echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo "║        Snapper - Security Made Simple         ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"

# Check for Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is required but not installed.${NC}"
    echo "Please install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi
echo -e "${GREEN}✓ Docker found${NC}"

# Check for Docker Compose
if ! docker compose version &> /dev/null && ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}Error: Docker Compose is required but not installed.${NC}"
    echo "Please install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi
echo -e "${GREEN}✓ Docker Compose found${NC}"

# Determine compose command
if docker compose version &> /dev/null; then
    COMPOSE_CMD="docker compose"
else
    COMPOSE_CMD="docker-compose"
fi

# Set installation directory
INSTALL_DIR="${SNAPPER_DIR:-$HOME/snapper}"

echo -e "\n${YELLOW}Installing to: ${INSTALL_DIR}${NC}"

# Clone repository (or download if git not available)
if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}Directory exists. Updating...${NC}"
    cd "$INSTALL_DIR"
    if [ -d ".git" ]; then
        git pull origin main 2>/dev/null || true
    fi
else
    if command -v git &> /dev/null; then
        echo -e "${BLUE}Cloning repository...${NC}"
        git clone https://github.com/snapper/snapper.git "$INSTALL_DIR"
    else
        echo -e "${BLUE}Downloading release...${NC}"
        mkdir -p "$INSTALL_DIR"
        curl -fsSL https://github.com/snapper/snapper/archive/main.tar.gz | \
            tar -xz -C "$INSTALL_DIR" --strip-components=1
    fi
    cd "$INSTALL_DIR"
fi

# Generate secure secret key
echo -e "\n${BLUE}Generating secure configuration...${NC}"
SECRET_KEY=$(openssl rand -hex 32 2>/dev/null || head -c 64 /dev/urandom | base64 | tr -d '/+=' | head -c 64)

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    cat > .env << EOF
# Snapper Configuration
# Generated on $(date)

# Security key (DO NOT SHARE)
SECRET_KEY=$SECRET_KEY

# Database
DATABASE_URL=postgresql+asyncpg://snapper:snapper@postgres:5432/snapper

# Redis
REDIS_URL=redis://redis:6379/0
CELERY_BROKER_URL=redis://redis:6379/1
CELERY_RESULT_BACKEND=redis://redis:6379/2

# Security settings (recommended defaults)
DENY_BY_DEFAULT=true
VALIDATE_WEBSOCKET_ORIGIN=true
REQUIRE_LOCALHOST_ONLY=false
ALLOWED_ORIGINS=http://localhost:8000,http://127.0.0.1:8000
ALLOWED_HOSTS=localhost,127.0.0.1,app

# Debug mode (disable in production)
DEBUG=true
LOG_LEVEL=INFO
EOF
    echo -e "${GREEN}✓ Configuration created${NC}"
else
    echo -e "${YELLOW}Configuration already exists, keeping existing .env${NC}"
fi

# Pull Docker images
echo -e "\n${BLUE}Pulling Docker images...${NC}"
$COMPOSE_CMD pull

# Build and start services
echo -e "\n${BLUE}Starting services...${NC}"
$COMPOSE_CMD up -d

# Wait for services to be healthy
echo -e "\n${YELLOW}Waiting for services to start...${NC}"
sleep 5

# Check health
MAX_RETRIES=30
RETRY_COUNT=0
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
        break
    fi
    echo -n "."
    sleep 2
    RETRY_COUNT=$((RETRY_COUNT + 1))
done
echo ""

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    echo -e "${RED}Warning: Services may not be fully started yet.${NC}"
    echo "Check status with: cd $INSTALL_DIR && $COMPOSE_CMD logs"
else
    echo -e "${GREEN}✓ Services are healthy${NC}"
fi

# Apply database migrations
echo -e "\n${BLUE}Applying database migrations...${NC}"
$COMPOSE_CMD exec -T app alembic upgrade head 2>/dev/null || true

# Apply default security rules (optional)
echo -e "\n${BLUE}Applying default security rules...${NC}"
$COMPOSE_CMD exec -T app python -m app.scripts.apply_security_defaults 2>/dev/null || true

# Print success message
echo -e "\n${GREEN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo "║          Installation Complete!                              ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "  ${BLUE}Dashboard:${NC}      http://localhost:8000"
echo -e "  ${BLUE}API Docs:${NC}       http://localhost:8000/api/docs"
echo -e "  ${BLUE}Setup Wizard:${NC}   http://localhost:8000/wizard"
echo ""
echo -e "  ${YELLOW}Quick commands:${NC}"
echo "    View logs:    cd $INSTALL_DIR && $COMPOSE_CMD logs -f"
echo "    Stop:         cd $INSTALL_DIR && $COMPOSE_CMD down"
echo "    Restart:      cd $INSTALL_DIR && $COMPOSE_CMD restart"
echo ""
echo -e "  ${GREEN}Next steps:${NC}"
echo "    1. Open http://localhost:8000/wizard to set up security rules"
echo "    2. Register your AI agents"
echo "    3. Configure alert notifications in Settings"
echo ""
echo -e "${BLUE}Thank you for using Snapper!${NC}"
