#!/bin/bash
# Snapper - One-Command Install Script
# Usage: curl -fsSL https://raw.githubusercontent.com/jmckinley/snapper/main/install.sh | bash

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
        git clone https://github.com/jmckinley/snapper.git "$INSTALL_DIR"
    else
        echo -e "${BLUE}Downloading release...${NC}"
        mkdir -p "$INSTALL_DIR"
        curl -fsSL https://github.com/jmckinley/snapper/archive/main.tar.gz | \
            tar -xz -C "$INSTALL_DIR" --strip-components=1
    fi
    cd "$INSTALL_DIR"
fi

# Hand off to setup.sh for the rest (start containers, health check, migrations)
echo -e "\n${BLUE}Running setup...${NC}"
bash ./setup.sh

echo ""
echo -e "  ${GREEN}Next steps:${NC}"
echo "    1. Open http://localhost:8000/wizard to set up security rules"
echo "    2. Register your AI agents"
echo "    3. Configure alert notifications in Settings"
echo "    4. Store PII via Telegram: /vault add \"My Card\" credit_card"
echo "    5. For browser PII protection, install snapper-guard plugin"
echo ""
echo -e "${BLUE}Thank you for using Snapper!${NC}"
