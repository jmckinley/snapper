#!/bin/bash
# Run Playwright E2E tests for Snapper
#
# Usage:
#   ./scripts/run-e2e-tests.sh              # Run all E2E tests headless
#   ./scripts/run-e2e-tests.sh --headed     # Run with browser visible
#   ./scripts/run-e2e-tests.sh --debug      # Run in debug mode
#
# For live API-level integration tests (rule engine, approvals, PII vault):
#   bash scripts/e2e_live_test.sh
#
# Prerequisites:
#   - App must be running (docker compose up -d)
#   - Playwright browsers must be installed

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Base URL (can be overridden)
export E2E_BASE_URL="${E2E_BASE_URL:-http://localhost:8000}"

echo -e "${GREEN}Snapper E2E Tests${NC}"
echo "========================="
echo "Base URL: $E2E_BASE_URL"
echo ""

# Check if app is running
echo -n "Checking app health... "
if curl -sf "$E2E_BASE_URL/health" > /dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
    echo ""
    echo "The app doesn't appear to be running at $E2E_BASE_URL"
    echo "Start it with: docker compose up -d"
    exit 1
fi

# Check if Playwright is installed
echo -n "Checking Playwright... "
if python -c "import playwright" 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${YELLOW}Installing...${NC}"
    pip install playwright pytest-playwright
fi

# Check if browsers are installed
echo -n "Checking Playwright browsers... "
if playwright install --dry-run chromium 2>&1 | grep -q "already"; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${YELLOW}Installing browsers...${NC}"
    playwright install chromium
fi

echo ""
echo "Running E2E tests..."
echo "========================="

# Run tests
pytest tests/e2e -v "$@"

echo ""
echo -e "${GREEN}E2E tests complete!${NC}"
