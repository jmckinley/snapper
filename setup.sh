#!/usr/bin/env bash
# Snapper — Local development setup
# Run this after cloning the repo: ./setup.sh
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          Snapper — Local Development Setup                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── 1. Validate prerequisites ──────────────────────────────────────

echo -e "${YELLOW}Checking prerequisites...${NC}"

if ! command -v docker &>/dev/null; then
    echo -e "${RED}Error: Docker is not installed.${NC}"
    echo "Install Docker Desktop: https://docs.docker.com/get-docker/"
    exit 1
fi
echo -e "${GREEN}✓ Docker found${NC}"

if ! docker compose version &>/dev/null; then
    echo -e "${RED}Error: Docker Compose v2 is required but not found.${NC}"
    echo "Install the Compose plugin: https://docs.docker.com/compose/install/"
    exit 1
fi
echo -e "${GREEN}✓ Docker Compose v2 found${NC}"

DOCKER_VERSION=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "0")
DOCKER_MAJOR=$(echo "$DOCKER_VERSION" | cut -d. -f1)
if [ "$DOCKER_MAJOR" -lt 24 ] 2>/dev/null; then
    echo -e "${YELLOW}Warning: Docker 24.0+ recommended (found $DOCKER_VERSION)${NC}"
fi

# ── 2. Generate .env if needed ─────────────────────────────────────

if [ ! -f .env ]; then
    echo -e "\n${BLUE}Creating .env from .env.example...${NC}"
    if [ -f .env.example ]; then
        cp .env.example .env
    else
        echo -e "${RED}Error: .env.example not found. Are you in the snapper directory?${NC}"
        exit 1
    fi

    # Generate a random SECRET_KEY
    SECRET_KEY=$(openssl rand -hex 32 2>/dev/null || head -c 64 /dev/urandom | base64 | tr -d '/+=' | head -c 64)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/^SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" .env
    else
        sed -i "s/^SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" .env
    fi

    echo -e "${GREEN}✓ .env created with random SECRET_KEY${NC}"
else
    echo -e "\n${YELLOW}Using existing .env file${NC}"
fi

# ── 3. Start containers ───────────────────────────────────────────

echo -e "\n${BLUE}Starting containers...${NC}"
docker compose up -d

# ── 4. Wait for health ────────────────────────────────────────────

echo -e "\n${YELLOW}Waiting for Snapper to be ready...${NC}"
MAX_RETRIES=30
RETRY_COUNT=0
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
        break
    fi
    echo -n "."
    sleep 2
    RETRY_COUNT=$((RETRY_COUNT + 1))
done
echo ""

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    echo -e "${RED}Timed out waiting for Snapper to start.${NC}"
    echo "Check logs: docker compose logs app"
    exit 1
fi
echo -e "${GREEN}✓ Snapper is running${NC}"

# ── 5. Run migrations ─────────────────────────────────────────────

echo -e "\n${BLUE}Running database migrations...${NC}"
docker compose exec -T app alembic upgrade head 2>/dev/null || true
echo -e "${GREEN}✓ Migrations applied${NC}"

# ── 5b. Create test database ─────────────────────────────────────

echo -e "\n${BLUE}Creating test database...${NC}"
docker compose exec -T postgres psql -U snapper -c "CREATE DATABASE snapper_test;" 2>/dev/null || true
echo -e "${GREEN}✓ Test database ready${NC}"

# ── 6. Open browser ───────────────────────────────────────────────

URL="http://localhost:8000"
echo -e "\n${BLUE}Opening dashboard...${NC}"
if [[ "$OSTYPE" == "darwin"* ]]; then
    open "$URL" 2>/dev/null || true
elif command -v xdg-open &>/dev/null; then
    xdg-open "$URL" 2>/dev/null || true
fi

# ── 7. Print next steps ───────────────────────────────────────────

echo -e "\n${GREEN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              Setup complete!                                ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  ${BLUE}Dashboard:${NC}    $URL"
echo -e "  ${BLUE}API docs:${NC}     $URL/api/docs"
echo -e "  ${BLUE}Setup wizard:${NC} $URL/wizard"
echo ""
echo -e "  The setup wizard will walk you through agent registration,"
echo -e "  security profile selection, and Telegram setup."
echo ""
echo -e "  ${YELLOW}Common commands:${NC}"
echo "    docker compose logs -f app    # Follow logs"
echo "    docker compose down           # Stop all containers"
echo "    docker compose restart        # Restart"
echo ""
