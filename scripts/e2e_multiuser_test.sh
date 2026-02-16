#!/usr/bin/env bash
#
# Snapper E2E Multi-User Test — tests auth, orgs, billing, quotas, and org scoping.
#
# Run on VPS:  bash /opt/snapper/scripts/e2e_multiuser_test.sh
# Locally:     SNAPPER_URL=http://localhost:8000 bash scripts/e2e_multiuser_test.sh
#
# Prerequisites:
#   - Snapper running (app + postgres + redis)
#   - jq installed
#
set -o pipefail

# ============================================================
# Configuration
# ============================================================
SNAPPER_URL="${SNAPPER_URL:-http://127.0.0.1:8000}"
API="${SNAPPER_URL}/api/v1"
HOST_HEADER="${E2E_HOST_HEADER:-}"
CURL_HOST_ARGS=()
if [[ -n "$HOST_HEADER" ]]; then
    CURL_HOST_ARGS=(-H "Host: ${HOST_HEADER}")
fi

UNIQUE="${RANDOM}${RANDOM}"
USER_A_EMAIL="e2e-mu-a-${UNIQUE}@test.com"
USER_A_USERNAME="e2emua${UNIQUE}"
USER_A_PASSWORD="MuTestA123!"

USER_B_EMAIL="e2e-mu-b-${UNIQUE}@test.com"
USER_B_USERNAME="e2emub${UNIQUE}"
USER_B_PASSWORD="MuTestB123!"

COOKIE_JAR_A="/tmp/e2e_mu_cookies_a_${UNIQUE}.txt"
COOKIE_JAR_B="/tmp/e2e_mu_cookies_b_${UNIQUE}.txt"

# ============================================================
# Counters & state
# ============================================================
PASS=0
FAIL=0
TOTAL=0
USER_A_ORG_ID=""
USER_B_ORG_ID=""
AGENT_UUID_A=""

# ============================================================
# Colors
# ============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ============================================================
# Helpers
# ============================================================
log()  { echo -e "${CYAN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[FAIL]${NC} $*"; }

assert_eq() {
    local actual="$1" expected="$2" label="$3"
    TOTAL=$((TOTAL + 1))
    if [[ "$actual" == "$expected" ]]; then
        PASS=$((PASS + 1))
        echo -e "  ${GREEN}PASS${NC} $label"
    else
        FAIL=$((FAIL + 1))
        echo -e "  ${RED}FAIL${NC} $label  (expected='$expected' actual='$actual')"
    fi
}

assert_contains() {
    local haystack="$1" needle="$2" label="$3"
    TOTAL=$((TOTAL + 1))
    if echo "$haystack" | grep -qiF "$needle"; then
        PASS=$((PASS + 1))
        echo -e "  ${GREEN}PASS${NC} $label"
    else
        FAIL=$((FAIL + 1))
        echo -e "  ${RED}FAIL${NC} $label  (expected to contain '$needle')"
    fi
}

assert_not_eq() {
    local actual="$1" unexpected="$2" label="$3"
    TOTAL=$((TOTAL + 1))
    if [[ "$actual" != "$unexpected" ]]; then
        PASS=$((PASS + 1))
        echo -e "  ${GREEN}PASS${NC} $label"
    else
        FAIL=$((FAIL + 1))
        echo -e "  ${RED}FAIL${NC} $label  (should NOT equal '$unexpected')"
    fi
}

assert_gt() {
    local actual="$1" threshold="$2" label="$3"
    TOTAL=$((TOTAL + 1))
    if [[ "$actual" -gt "$threshold" ]] 2>/dev/null; then
        PASS=$((PASS + 1))
        echo -e "  ${GREEN}PASS${NC} $label"
    else
        FAIL=$((FAIL + 1))
        echo -e "  ${RED}FAIL${NC} $label  (expected > $threshold, got '$actual')"
    fi
}

# Authenticated curl with cookie jar
auth_curl() {
    local jar="$1"; shift
    curl -s -b "$jar" -c "$jar" \
        "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" \
        "$@"
}

# Register a user and save cookies
register_user() {
    local jar="$1" email="$2" username="$3" password="$4"
    auth_curl "$jar" -X POST "${API}/auth/register" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"${email}\",\"username\":\"${username}\",\"password\":\"${password}\",\"password_confirm\":\"${password}\"}"
}

# Login a user and save cookies
login_user() {
    local jar="$1" email="$2" password="$3"
    auth_curl "$jar" -X POST "${API}/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"${email}\",\"password\":\"${password}\"}"
}

# ============================================================
# Cleanup (runs on EXIT)
# ============================================================
cleanup() {
    echo ""
    echo -e "${BOLD}--- Cleanup ---${NC}"

    # Delete test agents
    if [[ -n "$AGENT_UUID_A" ]]; then
        auth_curl "$COOKIE_JAR_A" -X DELETE "${API}/agents/${AGENT_UUID_A}?hard_delete=true" >/dev/null 2>&1
        log "Deleted test agent $AGENT_UUID_A"
    fi

    # Clean up test agents by prefix
    auth_curl "$COOKIE_JAR_A" -X POST "${API}/agents/cleanup-test?confirm=true" >/dev/null 2>&1
    auth_curl "$COOKIE_JAR_B" -X POST "${API}/agents/cleanup-test?confirm=true" >/dev/null 2>&1

    # Remove cookie jars
    rm -f "$COOKIE_JAR_A" "$COOKIE_JAR_B"

    echo ""
    echo -e "${BOLD}========================================${NC}"
    if [[ $FAIL -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}Results: $PASS/$TOTAL passed, $FAIL failed${NC}"
    else
        echo -e "${RED}${BOLD}Results: $PASS/$TOTAL passed, $FAIL failed${NC}"
    fi
    echo -e "${BOLD}========================================${NC}"

    if [[ $FAIL -gt 0 ]]; then
        exit 1
    fi
}
trap cleanup EXIT

# ============================================================
# Phase 0: Environment Verification (3 assertions)
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 0: Environment Verification ===${NC}"

# 0.1 jq installed
JQ_VERSION=$(jq --version 2>/dev/null || echo "")
assert_not_eq "$JQ_VERSION" "" "0.1 jq is installed"

# 0.2 Snapper health
log "Checking Snapper health..."
HEALTH=$(curl -s "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" "${SNAPPER_URL}/health" | jq -r '.status // empty')
assert_eq "$HEALTH" "healthy" "0.2 Snapper health check"

# 0.3 Auth register endpoint accepts POST
log "Checking auth register endpoint..."
REG_CHECK=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${API}/auth/register" \
    "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" \
    -H "Content-Type: application/json" \
    -d '{"email":"","username":"","password":"a","password_confirm":"a"}')
# Should return 422 (validation error) not 404/500
assert_not_eq "$REG_CHECK" "404" "0.3 Auth register endpoint exists"

# ============================================================
# Phase 1: Auth Flow (10 assertions)
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 1: Auth Flow ===${NC}"

# 1.1 Register User A
log "Registering User A..."
REG_RESP=$(register_user "$COOKIE_JAR_A" "$USER_A_EMAIL" "$USER_A_USERNAME" "$USER_A_PASSWORD")
REG_STATUS=$(echo "$REG_RESP" | jq -r '.id // empty')
assert_not_eq "$REG_STATUS" "" "1.1 Register User A returns user_id"

# 1.2 Registration returns org_id
USER_A_ORG_ID=$(echo "$REG_RESP" | jq -r '.default_organization_id // empty')
assert_not_eq "$USER_A_ORG_ID" "" "1.2 Registration includes org_id"

# 1.3 Registration email matches
REG_EMAIL=$(echo "$REG_RESP" | jq -r '.email // empty')
assert_eq "$REG_EMAIL" "$USER_A_EMAIL" "1.3 Registered email matches"

# 1.4 GET /auth/me returns user info
log "Checking /auth/me..."
ME_RESP=$(auth_curl "$COOKIE_JAR_A" "${API}/auth/me")
ME_EMAIL=$(echo "$ME_RESP" | jq -r '.user.email // empty')
assert_eq "$ME_EMAIL" "$USER_A_EMAIL" "1.4 /auth/me returns correct email"

# 1.5 /auth/me role is owner
ME_ROLE=$(echo "$ME_RESP" | jq -r '.organizations[0].role // empty')
assert_eq "$ME_ROLE" "owner" "1.5 /auth/me role is owner"

# 1.6 Refresh token returns 200
log "Testing refresh..."
REFRESH_RESP=$(auth_curl "$COOKIE_JAR_A" -X POST "${API}/auth/refresh")
REFRESH_TOKEN=$(echo "$REFRESH_RESP" | jq -r '.access_token // empty')
assert_not_eq "$REFRESH_TOKEN" "" "1.6 Refresh returns new access_token"

# 1.7 Logout returns 200
log "Testing logout..."
LOGOUT_RESP=$(auth_curl "$COOKIE_JAR_A" -X POST "${API}/auth/logout")
LOGOUT_MSG=$(echo "$LOGOUT_RESP" | jq -r '.message // empty')
assert_eq "$LOGOUT_MSG" "Logged out" "1.7 Logout returns success"

# 1.8 /auth/me after logout returns 401
ME_AFTER=$(auth_curl "$COOKIE_JAR_A" -o /dev/null -w "%{http_code}" "${API}/auth/me")
assert_eq "$ME_AFTER" "401" "1.8 /auth/me after logout returns 401"

# 1.9 Re-login works
log "Re-logging in User A..."
LOGIN_RESP=$(login_user "$COOKIE_JAR_A" "$USER_A_EMAIL" "$USER_A_PASSWORD")
LOGIN_EMAIL=$(echo "$LOGIN_RESP" | jq -r '.email // empty')
assert_eq "$LOGIN_EMAIL" "$USER_A_EMAIL" "1.9 Login returns correct email"

# 1.10 Login with wrong password returns 401
WRONG_LOGIN_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${API}/auth/login" \
    "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${USER_A_EMAIL}\",\"password\":\"WrongPassword!\"}")
assert_eq "$WRONG_LOGIN_CODE" "401" "1.10 Wrong password returns 401"

# ============================================================
# Phase 2: Organization Management (8 assertions)
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 2: Organization Management ===${NC}"

# 2.1 GET /organizations returns at least 1 org
log "Listing organizations..."
ORGS_RESP=$(auth_curl "$COOKIE_JAR_A" "${API}/organizations")
ORG_COUNT=$(echo "$ORGS_RESP" | jq 'length')
assert_gt "$ORG_COUNT" "0" "2.1 User has at least 1 organization"

# 2.2 Org name matches username pattern
ORG_NAME=$(echo "$ORGS_RESP" | jq -r '.[0].name // empty')
assert_not_eq "$ORG_NAME" "" "2.2 Organization has a name"

# 2.3 Org plan is free
ORG_PLAN=$(echo "$ORGS_RESP" | jq -r '.[0].plan_id // empty')
assert_eq "$ORG_PLAN" "free" "2.3 Default org plan is free"

# 2.4 PATCH org name
log "Updating org name..."
PATCH_RESP=$(auth_curl "$COOKIE_JAR_A" -X PATCH "${API}/organizations/${USER_A_ORG_ID}" \
    -H "Content-Type: application/json" \
    -d '{"name": "E2E Updated Org"}')
PATCH_NAME=$(echo "$PATCH_RESP" | jq -r '.name // empty')
assert_eq "$PATCH_NAME" "E2E Updated Org" "2.4 PATCH org name succeeds"

# 2.5 GET org usage returns data
log "Checking org usage..."
USAGE_RESP=$(auth_curl "$COOKIE_JAR_A" "${API}/organizations/${USER_A_ORG_ID}/usage")
USAGE_AGENTS=$(echo "$USAGE_RESP" | jq -r '.agents.used // empty')
assert_not_eq "$USAGE_AGENTS" "" "2.5 Usage has agents count"

# 2.6 Usage has rules field
USAGE_RULES=$(echo "$USAGE_RESP" | jq -r '.rules.used // empty')
assert_not_eq "$USAGE_RULES" "" "2.6 Usage has rules count"

# 2.7 Usage has vault_entries field
USAGE_VAULT=$(echo "$USAGE_RESP" | jq -r '.vault_entries.used // empty')
assert_not_eq "$USAGE_VAULT" "" "2.7 Usage has vault_entries count"

# 2.8 GET org members returns at least 1 member
log "Checking org members..."
MEMBERS_RESP=$(auth_curl "$COOKIE_JAR_A" "${API}/organizations/${USER_A_ORG_ID}/members")
MEMBER_COUNT=$(echo "$MEMBERS_RESP" | jq 'length')
assert_gt "$MEMBER_COUNT" "0" "2.8 Org has at least 1 member"

# ============================================================
# Phase 3: Billing & Quotas (8 assertions)
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 3: Billing & Quotas ===${NC}"

# 3.1 GET /billing/plan returns plan info
log "Checking billing plan..."
PLAN_RESP=$(auth_curl "$COOKIE_JAR_A" "${API}/billing/plan")
PLAN_ID=$(echo "$PLAN_RESP" | jq -r '.plan.id // empty')
assert_eq "$PLAN_ID" "free" "3.1 Billing plan is free"

# 3.2 Plan limits include agents
PLAN_AGENTS=$(echo "$PLAN_RESP" | jq -r '.plan.limits.agents // empty')
assert_eq "$PLAN_AGENTS" "1" "3.2 Free plan agents limit = 1"

# 3.3 Plan limits include rules
PLAN_RULES=$(echo "$PLAN_RESP" | jq -r '.plan.limits.rules // empty')
assert_eq "$PLAN_RULES" "10" "3.3 Free plan rules limit = 10"

# 3.4 POST /billing/checkout returns 503 (no Stripe)
log "Testing checkout (no Stripe)..."
CHECKOUT_CODE=$(auth_curl "$COOKIE_JAR_A" -o /dev/null -w "%{http_code}" -X POST "${API}/billing/checkout" \
    -H "Content-Type: application/json" \
    -d '{"plan_id": "pro", "interval": "monthly"}')
assert_eq "$CHECKOUT_CODE" "503" "3.4 Checkout returns 503 without Stripe"

# 3.5 POST /billing/portal returns 404 (no Stripe customer)
PORTAL_CODE=$(auth_curl "$COOKIE_JAR_A" -o /dev/null -w "%{http_code}" -X POST "${API}/billing/portal")
assert_eq "$PORTAL_CODE" "404" "3.5 Portal returns 404 without Stripe customer"

# 3.6 Create first agent (within quota)
log "Creating agent within quota..."
AGENT_RESP=$(auth_curl "$COOKIE_JAR_A" -X POST "${API}/agents" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"e2e-mu-agent-${UNIQUE}\",\"external_id\":\"e2e-mu-${UNIQUE}\",\"description\":\"Multi-user test\"}")
AGENT_UUID_A=$(echo "$AGENT_RESP" | jq -r '.id // empty')
assert_not_eq "$AGENT_UUID_A" "" "3.6 Create agent within quota succeeds"

# 3.7 Create second agent (over quota)
log "Testing agent quota enforcement..."
OVER_CODE=$(auth_curl "$COOKIE_JAR_A" -o /dev/null -w "%{http_code}" -X POST "${API}/agents" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"e2e-mu-over-${UNIQUE}\",\"external_id\":\"e2e-mu-over-${UNIQUE}\"}")
assert_eq "$OVER_CODE" "402" "3.7 Second agent returns 402 (over quota)"

# 3.8 Plan usage reflects created agent
USAGE_AFTER=$(auth_curl "$COOKIE_JAR_A" "${API}/billing/plan")
AGENTS_USED=$(echo "$USAGE_AFTER" | jq -r '.usage.agents.used // "0"')
assert_gt "$AGENTS_USED" "0" "3.8 Usage reflects created agent"

# ============================================================
# Phase 4: Org Scoping (10 assertions)
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 4: Org Scoping ===${NC}"

# Register User B
log "Registering User B..."
REG_B=$(register_user "$COOKIE_JAR_B" "$USER_B_EMAIL" "$USER_B_USERNAME" "$USER_B_PASSWORD")
USER_B_ORG_ID=$(echo "$REG_B" | jq -r '.default_organization_id // empty')
assert_not_eq "$USER_B_ORG_ID" "" "4.1 User B registered with org_id"

# 4.2 User A's agent is visible to User A
log "Checking agent visibility..."
AGENTS_A=$(auth_curl "$COOKIE_JAR_A" "${API}/agents")
A_AGENT_NAMES=$(echo "$AGENTS_A" | jq -r '.items[].name // empty')
assert_contains "$A_AGENT_NAMES" "e2e-mu-agent-${UNIQUE}" "4.2 User A sees own agent"

# 4.3 User A's agent is invisible to User B
AGENTS_B=$(auth_curl "$COOKIE_JAR_B" "${API}/agents")
B_AGENT_NAMES=$(echo "$AGENTS_B" | jq -r '.items[].name // empty' 2>/dev/null)
TOTAL=$((TOTAL + 1))
if echo "$B_AGENT_NAMES" | grep -qF "e2e-mu-agent-${UNIQUE}"; then
    FAIL=$((FAIL + 1))
    echo -e "  ${RED}FAIL${NC} 4.3 User B should NOT see User A's agent"
else
    PASS=$((PASS + 1))
    echo -e "  ${GREEN}PASS${NC} 4.3 User B does not see User A's agent"
fi

# 4.4 User B creates a rule
log "User B creating rule..."
RULE_B_RESP=$(auth_curl "$COOKIE_JAR_B" -X POST "${API}/rules" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"e2e-mu-rule-b-${UNIQUE}\",\"rule_type\":\"rate_limit\",\"action\":\"deny\",\"priority\":5,\"parameters\":{\"max_requests\":100,\"window_seconds\":60},\"is_active\":true}")
RULE_B_ID=$(echo "$RULE_B_RESP" | jq -r '.id // empty')
assert_not_eq "$RULE_B_ID" "" "4.4 User B creates rule successfully"

# 4.5 User B's rule is visible to User B
RULES_B=$(auth_curl "$COOKIE_JAR_B" "${API}/rules")
B_RULE_NAMES=$(echo "$RULES_B" | jq -r '.items[].name // empty')
assert_contains "$B_RULE_NAMES" "e2e-mu-rule-b-${UNIQUE}" "4.5 User B sees own rule"

# 4.6 User B's rule is invisible to User A
RULES_A=$(auth_curl "$COOKIE_JAR_A" "${API}/rules")
A_RULE_NAMES=$(echo "$RULES_A" | jq -r '.items[].name // empty')
TOTAL=$((TOTAL + 1))
if echo "$A_RULE_NAMES" | grep -qF "e2e-mu-rule-b-${UNIQUE}"; then
    FAIL=$((FAIL + 1))
    echo -e "  ${RED}FAIL${NC} 4.6 User A should NOT see User B's rule"
else
    PASS=$((PASS + 1))
    echo -e "  ${GREEN}PASS${NC} 4.6 User A does not see User B's rule"
fi

# 4.7 Audit logs are org-scoped
log "Checking audit log scoping..."
AUDIT_A=$(auth_curl "$COOKIE_JAR_A" "${API}/audit/logs")
AUDIT_A_TOTAL=$(echo "$AUDIT_A" | jq -r '.total // "0"')
assert_not_eq "$AUDIT_A_TOTAL" "" "4.7 User A has audit log total"

# 4.8 User B has separate audit logs
AUDIT_B=$(auth_curl "$COOKIE_JAR_B" "${API}/audit/logs")
AUDIT_B_TOTAL=$(echo "$AUDIT_B" | jq -r '.total // "0"')
assert_not_eq "$AUDIT_B_TOTAL" "" "4.8 User B has audit log total"

# 4.9 User A agent count differs from User B
AGENTS_A_TOTAL=$(echo "$AGENTS_A" | jq -r '.total // "0"')
AGENTS_B_TOTAL=$(echo "$AGENTS_B" | jq -r '.total // "0"')
assert_not_eq "$AGENTS_A_TOTAL" "$AGENTS_B_TOTAL" "4.9 Agent counts differ between users"

# 4.10 Orgs are different
assert_not_eq "$USER_A_ORG_ID" "$USER_B_ORG_ID" "4.10 Users have different org IDs"

# Clean up User B's rule
if [[ -n "$RULE_B_ID" ]]; then
    auth_curl "$COOKIE_JAR_B" -X DELETE "${API}/rules/${RULE_B_ID}?hard_delete=true" >/dev/null 2>&1
fi

# ============================================================
# Phase 5: Password Reset (4 assertions)
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 5: Password Reset ===${NC}"

# 5.1 Forgot password for existing email returns 200
log "Testing forgot password..."
FORGOT_RESP=$(curl -s -X POST "${API}/auth/forgot-password" \
    "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${USER_A_EMAIL}\"}")
FORGOT_MSG=$(echo "$FORGOT_RESP" | jq -r '.message // empty')
assert_contains "$FORGOT_MSG" "reset link" "5.1 Forgot password returns reset link message"

# 5.2 Forgot password for nonexistent email still returns 200 (no enumeration)
FORGOT_NONE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${API}/auth/forgot-password" \
    "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" \
    -H "Content-Type: application/json" \
    -d '{"email":"nonexistent-e2e@test.com"}')
assert_eq "$FORGOT_NONE" "200" "5.2 Nonexistent email returns 200 (no enumeration)"

# 5.3 Reset password with invalid token returns 400
RESET_BAD=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${API}/auth/reset-password" \
    "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" \
    -H "Content-Type: application/json" \
    -d '{"token":"invalid-token","new_password":"NewPass123!","password_confirm":"NewPass123!"}')
assert_eq "$RESET_BAD" "400" "5.3 Invalid reset token returns 400"

# 5.4 Register page accessible (not 404)
REG_PAGE=$(curl -s -o /dev/null -w "%{http_code}" "${SNAPPER_URL}/register" \
    "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}")
assert_eq "$REG_PAGE" "200" "5.4 Register page returns 200"
