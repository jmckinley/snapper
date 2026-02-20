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

META_ADMIN_EMAIL="e2e-meta-${UNIQUE}@mckinleylabs.com"
META_ADMIN_USERNAME="e2emeta${UNIQUE}"
META_ADMIN_PASSWORD="MetaAdmin123!"

COOKIE_JAR_A="/tmp/e2e_mu_cookies_a_${UNIQUE}.txt"
COOKIE_JAR_B="/tmp/e2e_mu_cookies_b_${UNIQUE}.txt"
COOKIE_JAR_META="/tmp/e2e_mu_cookies_meta_${UNIQUE}.txt"

# ============================================================
# Counters & state
# ============================================================
PASS=0
FAIL=0
TOTAL=0
USER_A_ORG_ID=""
USER_B_ORG_ID=""
AGENT_UUID_A=""
META_USER_ID=""
META_ORG_ID=""
PROVISIONED_ORG_ID=""
POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-snapper-postgres-1}"
REDIS_CONTAINER="${REDIS_CONTAINER:-snapper-redis-1}"

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

# Flush rate limit keys (prevents 429s between test phases)
# Key format: rate_limit:{prefix}:{client_ip} — sorted set (sliding window)
# Client IP varies by Docker network config, so delete all matching keys
flush_rate_keys() {
    local keys
    keys=$(docker exec "$REDIS_CONTAINER" redis-cli KEYS "rate_limit:*" 2>/dev/null)
    if [[ -n "$keys" ]]; then
        echo "$keys" | while read -r key; do
            [[ -n "$key" ]] && docker exec "$REDIS_CONTAINER" redis-cli DEL "$key" >/dev/null 2>&1
        done
    fi
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

    # Clean up provisioned org (if created)
    if [[ -n "$PROVISIONED_ORG_ID" ]]; then
        auth_curl "$COOKIE_JAR_META" -X PATCH "${API}/meta/orgs/${PROVISIONED_ORG_ID}" \
            -H "Content-Type: application/json" \
            -d '{"is_active": false}' >/dev/null 2>&1
        log "Deactivated provisioned org $PROVISIONED_ORG_ID"
    fi

    # Remove cookie jars
    rm -f "$COOKIE_JAR_A" "$COOKIE_JAR_B" "$COOKIE_JAR_META"

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

# 3.2 Plan limits include agents (bumped for pilots: 25)
PLAN_AGENTS=$(echo "$PLAN_RESP" | jq -r '.plan.limits.agents // empty')
assert_eq "$PLAN_AGENTS" "25" "3.2 Free plan agents limit = 25"

# 3.3 Plan limits include rules (bumped for pilots: 250)
PLAN_RULES=$(echo "$PLAN_RESP" | jq -r '.plan.limits.rules // empty')
assert_eq "$PLAN_RULES" "250" "3.3 Free plan rules limit = 250"

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

# 3.7 Create second agent (within bumped quota of 25)
log "Testing second agent creation (within quota)..."
OVER_CODE=$(auth_curl "$COOKIE_JAR_A" -o /dev/null -w "%{http_code}" -X POST "${API}/agents" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"e2e-mu-agent2-${UNIQUE}\",\"external_id\":\"e2e-mu-agent2-${UNIQUE}\"}")
assert_eq "$OVER_CODE" "201" "3.7 Second agent within free plan quota"

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

# 4.5 User B's rule is visible to User B (fetch by ID to avoid pagination)
RULE_B_GET=$(auth_curl "$COOKIE_JAR_B" "${API}/rules/${RULE_B_ID}")
RULE_B_NAME=$(echo "$RULE_B_GET" | jq -r '.name // empty')
assert_eq "$RULE_B_NAME" "e2e-mu-rule-b-${UNIQUE}" "4.5 User B sees own rule"

# 4.6 User B's rule is invisible to User A (fetch by ID — should 404 or return different org)
RULE_A_CODE=$(auth_curl "$COOKIE_JAR_A" -o /dev/null -w "%{http_code}" "${API}/rules/${RULE_B_ID}")
TOTAL=$((TOTAL + 1))
if [[ "$RULE_A_CODE" == "404" || "$RULE_A_CODE" == "403" ]]; then
    PASS=$((PASS + 1))
    echo -e "  ${GREEN}PASS${NC} 4.6 User A cannot access User B's rule ($RULE_A_CODE)"
else
    FAIL=$((FAIL + 1))
    echo -e "  ${RED}FAIL${NC} 4.6 User A should NOT see User B's rule (got $RULE_A_CODE)"
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

# ============================================================
# Phase 6: Meta Admin Setup (4 assertions)
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 6: Meta Admin Setup ===${NC}"

# 6.1 Register meta admin user
log "Registering meta admin user..."
META_REG=$(register_user "$COOKIE_JAR_META" "$META_ADMIN_EMAIL" "$META_ADMIN_USERNAME" "$META_ADMIN_PASSWORD")
META_USER_ID=$(echo "$META_REG" | jq -r '.id // empty')
assert_not_eq "$META_USER_ID" "" "6.1 Meta admin user registered"

META_ORG_ID=$(echo "$META_REG" | jq -r '.default_organization_id // empty')

# 6.2 Promote user to meta admin via direct SQL
log "Promoting user to meta admin..."
docker exec "$POSTGRES_CONTAINER" psql -U snapper -d snapper -c \
    "UPDATE users SET is_meta_admin = true WHERE id = '${META_USER_ID}';" >/dev/null 2>&1
PROMOTE_EXIT=$?
TOTAL=$((TOTAL + 1))
if [[ $PROMOTE_EXIT -eq 0 ]]; then
    PASS=$((PASS + 1))
    echo -e "  ${GREEN}PASS${NC} 6.2 Promoted user to meta admin via SQL"
else
    FAIL=$((FAIL + 1))
    echo -e "  ${RED}FAIL${NC} 6.2 Failed to promote user (exit=$PROMOTE_EXIT)"
fi

# 6.3 Logout and re-login to get JWT with meta claim
log "Re-logging in to get meta JWT..."
auth_curl "$COOKIE_JAR_META" -X POST "${API}/auth/logout" >/dev/null 2>&1
META_LOGIN=$(login_user "$COOKIE_JAR_META" "$META_ADMIN_EMAIL" "$META_ADMIN_PASSWORD")
META_LOGIN_EMAIL=$(echo "$META_LOGIN" | jq -r '.email // empty')
assert_eq "$META_LOGIN_EMAIL" "$META_ADMIN_EMAIL" "6.3 Meta admin re-login succeeds"

# 6.4 Regular user gets 403 on /meta/stats
log "Verifying regular user blocked from meta endpoints..."
META_BLOCKED=$(auth_curl "$COOKIE_JAR_A" -o /dev/null -w "%{http_code}" "${API}/meta/stats")
assert_eq "$META_BLOCKED" "403" "6.4 Regular user gets 403 on /meta/stats"

# ============================================================
# Phase 7: Platform Stats & Org Listing (6 assertions)
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 7: Platform Stats & Org Listing ===${NC}"
flush_rate_keys

# 7.1 GET /meta/stats returns platform stats
log "Fetching platform stats..."
STATS_RESP=$(auth_curl "$COOKIE_JAR_META" "${API}/meta/stats")
STATS_ORGS=$(echo "$STATS_RESP" | jq -r '.total_organizations // empty')
assert_not_eq "$STATS_ORGS" "" "7.1 Platform stats has total_organizations"

# 7.2 Stats has total_users
STATS_USERS=$(echo "$STATS_RESP" | jq -r '.total_users // empty')
assert_not_eq "$STATS_USERS" "" "7.2 Platform stats has total_users"

# 7.3 Stats has total_agents
STATS_AGENTS=$(echo "$STATS_RESP" | jq -r '.total_agents // empty')
assert_not_eq "$STATS_AGENTS" "" "7.3 Platform stats has total_agents"

# 7.4 GET /meta/orgs returns org list
log "Listing all organizations..."
ORGS_RESP=$(auth_curl "$COOKIE_JAR_META" "${API}/meta/orgs")
ORGS_COUNT=$(echo "$ORGS_RESP" | jq 'length')
assert_gt "$ORGS_COUNT" "1" "7.4 Meta admin sees >1 orgs (all users' orgs)"

# 7.5 GET /meta/orgs with search filter
ORGS_SEARCH=$(auth_curl "$COOKIE_JAR_META" "${API}/meta/orgs?search=e2e")
SEARCH_COUNT=$(echo "$ORGS_SEARCH" | jq 'length')
assert_gt "$SEARCH_COUNT" "0" "7.5 Org search with filter returns results"

# 7.6 GET /meta/orgs with plan filter
ORGS_FREE=$(auth_curl "$COOKIE_JAR_META" "${API}/meta/orgs?plan_id=free")
FREE_COUNT=$(echo "$ORGS_FREE" | jq 'length')
assert_gt "$FREE_COUNT" "0" "7.6 Org filter by plan returns results"

# ============================================================
# Phase 8: Org Detail & Update (6 assertions)
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 8: Org Detail & Update ===${NC}"
flush_rate_keys

# 8.1 GET /meta/orgs/{org_id} returns detail
log "Fetching org detail..."
ORG_DETAIL=$(auth_curl "$COOKIE_JAR_META" "${API}/meta/orgs/${USER_A_ORG_ID}")
DETAIL_NAME=$(echo "$ORG_DETAIL" | jq -r '.name // empty')
assert_not_eq "$DETAIL_NAME" "" "8.1 Org detail has name"

# 8.2 Org detail has usage
DETAIL_USAGE=$(echo "$ORG_DETAIL" | jq -r '.usage // empty')
assert_not_eq "$DETAIL_USAGE" "" "8.2 Org detail has usage"

# 8.3 Org detail has recent_audit
DETAIL_AUDIT=$(echo "$ORG_DETAIL" | jq -r '.recent_audit // empty')
assert_not_eq "$DETAIL_AUDIT" "" "8.3 Org detail has recent_audit"

# 8.4 PATCH /meta/orgs/{org_id} updates name
log "Updating org name via meta admin..."
PATCH_RESP=$(auth_curl "$COOKIE_JAR_META" -X PATCH "${API}/meta/orgs/${USER_A_ORG_ID}" \
    -H "Content-Type: application/json" \
    -d '{"name": "E2E Meta Updated"}')
PATCH_NAME=$(echo "$PATCH_RESP" | jq -r '.name // empty')
assert_eq "$PATCH_NAME" "E2E Meta Updated" "8.4 Meta admin can update org name"

# 8.5 PATCH /meta/orgs/{org_id} updates allowed_email_domains
log "Setting email domains..."
DOMAINS_RESP=$(auth_curl "$COOKIE_JAR_META" -X PATCH "${API}/meta/orgs/${USER_A_ORG_ID}" \
    -H "Content-Type: application/json" \
    -d '{"allowed_email_domains": ["test.com", "example.com"]}')
DOMAINS_SET=$(echo "$DOMAINS_RESP" | jq -r '.allowed_email_domains | length')
assert_eq "$DOMAINS_SET" "2" "8.5 Email domains updated to 2"

# 8.6 PATCH /meta/orgs/{org_id} sets max_seats
log "Setting max_seats..."
SEATS_RESP=$(auth_curl "$COOKIE_JAR_META" -X PATCH "${API}/meta/orgs/${USER_A_ORG_ID}" \
    -H "Content-Type: application/json" \
    -d '{"max_seats": 10}')
SEATS_VAL=$(echo "$SEATS_RESP" | jq -r '.max_seats // empty')
assert_eq "$SEATS_VAL" "10" "8.6 Max seats set to 10"

# ============================================================
# Phase 9: Provision Org (6 assertions)
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 9: Provision Org ===${NC}"
flush_rate_keys

# 9.1 Provision org with pro plan
log "Provisioning new org..."
PROV_RESP=$(auth_curl "$COOKIE_JAR_META" -X POST "${API}/meta/provision-org" \
    -H "Content-Type: application/json" \
    -d "{
        \"name\": \"E2E Provisioned Corp ${UNIQUE}\",
        \"plan_id\": \"pro\",
        \"owner_email\": \"owner-${UNIQUE}@testcorp.com\",
        \"allowed_email_domains\": [\"testcorp.com\"],
        \"max_seats\": 5
    }")
PROVISIONED_ORG_ID=$(echo "$PROV_RESP" | jq -r '.id // empty')
assert_not_eq "$PROVISIONED_ORG_ID" "" "9.1 Provision org returns org ID"

# 9.2 Provisioned org has correct name
PROV_NAME=$(echo "$PROV_RESP" | jq -r '.name // empty')
assert_contains "$PROV_NAME" "E2E Provisioned Corp" "9.2 Provisioned org has correct name"

# 9.3 Provisioned org has pro plan
PROV_PLAN=$(echo "$PROV_RESP" | jq -r '.plan_id // empty')
assert_eq "$PROV_PLAN" "pro" "9.3 Provisioned org has pro plan"

# 9.4 Provisioned org has invitation_token
PROV_TOKEN=$(echo "$PROV_RESP" | jq -r '.invitation_token // empty')
assert_not_eq "$PROV_TOKEN" "" "9.4 Provisioned org has invitation_token"

# 9.5 Provisioned org has allowed_email_domains
PROV_DOMAINS=$(echo "$PROV_RESP" | jq -r '.allowed_email_domains | length')
assert_eq "$PROV_DOMAINS" "1" "9.5 Provisioned org has 1 email domain"

# 9.6 Invalid plan returns 400
log "Testing invalid plan..."
BAD_PLAN_CODE=$(auth_curl "$COOKIE_JAR_META" -o /dev/null -w "%{http_code}" \
    -X POST "${API}/meta/provision-org" \
    -H "Content-Type: application/json" \
    -d '{"name":"Bad Plan Org","plan_id":"nonexistent","owner_email":"bad@test.com"}')
assert_eq "$BAD_PLAN_CODE" "400" "9.6 Invalid plan returns 400"

# ============================================================
# Phase 10: Feature Flags (3 assertions)
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 10: Feature Flags ===${NC}"
flush_rate_keys

# 10.1 PATCH /meta/orgs/{org_id}/features toggles flags
log "Toggling feature flags..."
FLAGS_RESP=$(auth_curl "$COOKIE_JAR_META" -X PATCH \
    "${API}/meta/orgs/${USER_A_ORG_ID}/features" \
    -H "Content-Type: application/json" \
    -d '{"features": {"sso": true, "audit_export": true}}')
SSO_FLAG=$(echo "$FLAGS_RESP" | jq -r '.feature_overrides.sso // empty')
assert_eq "$SSO_FLAG" "true" "10.1 SSO feature flag enabled"

# 10.2 Audit export flag set
AUDIT_FLAG=$(echo "$FLAGS_RESP" | jq -r '.feature_overrides.audit_export // empty')
assert_eq "$AUDIT_FLAG" "true" "10.2 Audit export feature flag enabled"

# 10.3 Can disable a flag
FLAGS2_RESP=$(auth_curl "$COOKIE_JAR_META" -X PATCH \
    "${API}/meta/orgs/${USER_A_ORG_ID}/features" \
    -H "Content-Type: application/json" \
    -d '{"features": {"sso": false}}')
TOTAL=$((TOTAL + 1))
if echo "$FLAGS2_RESP" | jq -e '.feature_overrides.sso == false' >/dev/null 2>&1; then
    PASS=$((PASS + 1))
    echo -e "  ${GREEN}PASS${NC} 10.3 SSO feature flag disabled"
else
    FAIL=$((FAIL + 1))
    echo -e "  ${RED}FAIL${NC} 10.3 SSO feature flag disabled (got: $(echo "$FLAGS2_RESP" | jq '.feature_overrides.sso'))"
fi

# ============================================================
# Phase 11: Impersonation (5 assertions)
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 11: Impersonation ===${NC}"
flush_rate_keys

# 11.1 Start impersonation of User A's org
log "Starting impersonation..."
IMP_RESP=$(auth_curl "$COOKIE_JAR_META" -X POST "${API}/meta/impersonate" \
    -H "Content-Type: application/json" \
    -d "{\"org_id\": \"${USER_A_ORG_ID}\"}")
IMP_ORG=$(echo "$IMP_RESP" | jq -r '.org_id // empty')
assert_eq "$IMP_ORG" "$USER_A_ORG_ID" "11.1 Impersonation returns target org_id"

# 11.2 Impersonation response has org_name
IMP_NAME=$(echo "$IMP_RESP" | jq -r '.org_name // empty')
assert_not_eq "$IMP_NAME" "" "11.2 Impersonation returns org_name"

# 11.3 During impersonation, can see User A's agents
log "Verifying impersonated context..."
IMP_AGENTS=$(auth_curl "$COOKIE_JAR_META" "${API}/agents")
IMP_AGENT_NAMES=$(echo "$IMP_AGENTS" | jq -r '.items[].name // empty' 2>/dev/null)
assert_contains "$IMP_AGENT_NAMES" "e2e-mu-agent-${UNIQUE}" "11.3 Impersonation sees target org's agents"

# 11.4 Stop impersonation
log "Stopping impersonation..."
STOP_RESP=$(auth_curl "$COOKIE_JAR_META" -X POST "${API}/meta/stop-impersonation")
STOP_MSG=$(echo "$STOP_RESP" | jq -r '.message // empty')
assert_contains "$STOP_MSG" "stopped" "11.4 Stop impersonation succeeds"

# 11.5 After stopping, /meta/stats still accessible (back to own context)
STATS_AFTER=$(auth_curl "$COOKIE_JAR_META" -o /dev/null -w "%{http_code}" "${API}/meta/stats")
assert_eq "$STATS_AFTER" "200" "11.5 Meta admin retains access after stop impersonation"

# ============================================================
# Phase 12: User Management (5 assertions)
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 12: User Management ===${NC}"
flush_rate_keys

# 12.1 GET /meta/users returns user list
log "Listing all users..."
USERS_RESP=$(auth_curl "$COOKIE_JAR_META" "${API}/meta/users")
USERS_COUNT=$(echo "$USERS_RESP" | jq 'if type == "array" then length else .items // [] | length end')
assert_gt "$USERS_COUNT" "1" "12.1 Meta admin sees >1 users"

# 12.2 Search users by email
USERS_SEARCH=$(auth_curl "$COOKIE_JAR_META" "${API}/meta/users?search=${USER_A_EMAIL%%@*}")
SEARCH_USERS_COUNT=$(echo "$USERS_SEARCH" | jq 'length')
assert_gt "$SEARCH_USERS_COUNT" "0" "12.2 User search by email returns results"

# 12.3 Search result contains correct email
SEARCH_EMAIL=$(echo "$USERS_SEARCH" | jq -r '.[0].email // empty')
assert_eq "$SEARCH_EMAIL" "$USER_A_EMAIL" "12.3 Search result has matching email"

# Get User A's user ID for suspend test
USER_A_ID=$(echo "$USERS_SEARCH" | jq -r '.[0].id // empty')

# 12.4 Suspend user
log "Suspending User A..."
if [[ -n "$USER_A_ID" ]]; then
    SUSPEND_RESP=$(auth_curl "$COOKIE_JAR_META" -X PATCH "${API}/meta/users/${USER_A_ID}" \
        -H "Content-Type: application/json" \
        -d '{"is_active": false}')
    TOTAL=$((TOTAL + 1))
    if echo "$SUSPEND_RESP" | jq -e '.changes.is_active.new == false' >/dev/null 2>&1; then
        PASS=$((PASS + 1))
        echo -e "  ${GREEN}PASS${NC} 12.4 Suspend user sets is_active=false"
    else
        FAIL=$((FAIL + 1))
        echo -e "  ${RED}FAIL${NC} 12.4 Suspend user sets is_active=false (resp: $(echo "$SUSPEND_RESP" | head -c 200))"
    fi
else
    TOTAL=$((TOTAL + 1))
    FAIL=$((FAIL + 1))
    echo -e "  ${RED}FAIL${NC} 12.4 Could not find User A's ID for suspend"
fi

# 12.5 Re-activate user
log "Re-activating User A..."
if [[ -n "$USER_A_ID" ]]; then
    REACTIVATE_RESP=$(auth_curl "$COOKIE_JAR_META" -X PATCH "${API}/meta/users/${USER_A_ID}" \
        -H "Content-Type: application/json" \
        -d '{"is_active": true}')
    REACT_ACTIVE=$(echo "$REACTIVATE_RESP" | jq -r '.changes.is_active.new // empty')
    assert_eq "$REACT_ACTIVE" "true" "12.5 Re-activate user sets is_active=true"
else
    TOTAL=$((TOTAL + 1))
    FAIL=$((FAIL + 1))
    echo -e "  ${RED}FAIL${NC} 12.5 Could not re-activate User A"
fi

# ============================================================
# Phase 13: Cross-Org Audit Search (3 assertions)
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 13: Cross-Org Audit Search ===${NC}"
flush_rate_keys

# 13.1 GET /meta/audit returns audit entries
log "Searching cross-org audit..."
AUDIT_RESP=$(auth_curl "$COOKIE_JAR_META" "${API}/meta/audit?limit=10")
AUDIT_COUNT=$(echo "$AUDIT_RESP" | jq 'if type == "array" then length else .items // [] | length end')
assert_gt "$AUDIT_COUNT" "0" "13.1 Cross-org audit returns entries"

# 13.2 Audit entries have required fields
AUDIT_FIRST_ACTION=$(echo "$AUDIT_RESP" | jq -r '.[0].action // empty')
assert_not_eq "$AUDIT_FIRST_ACTION" "" "13.2 Audit entries have action field"

# 13.3 Filter audit by org_id
AUDIT_FILTERED=$(auth_curl "$COOKIE_JAR_META" "${API}/meta/audit?org_id=${USER_A_ORG_ID}&limit=5")
AUDIT_FILT_COUNT=$(echo "$AUDIT_FILTERED" | jq 'length')
assert_gt "$AUDIT_FILT_COUNT" "0" "13.3 Audit filter by org_id returns entries"

# ============================================================
# Phase 14: Meta Admin Access Control (4 assertions)
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 14: Meta Admin Access Control ===${NC}"

# 14.1 Regular User A cannot access /meta/orgs
META_A_CODE=$(auth_curl "$COOKIE_JAR_A" -o /dev/null -w "%{http_code}" "${API}/meta/orgs")
assert_eq "$META_A_CODE" "403" "14.1 Regular user blocked from /meta/orgs"

# 14.2 Regular User B cannot access /meta/users
META_B_CODE=$(auth_curl "$COOKIE_JAR_B" -o /dev/null -w "%{http_code}" "${API}/meta/users")
assert_eq "$META_B_CODE" "403" "14.2 Regular user blocked from /meta/users"

# 14.3 Unauthenticated request returns 401
UNAUTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${API}/meta/stats" \
    "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}")
assert_eq "$UNAUTH_CODE" "401" "14.3 Unauthenticated request returns 401"

# 14.4 Regular user cannot provision org
PROV_BLOCKED=$(auth_curl "$COOKIE_JAR_A" -o /dev/null -w "%{http_code}" \
    -X POST "${API}/meta/provision-org" \
    -H "Content-Type: application/json" \
    -d '{"name":"Blocked Org","plan_id":"free","owner_email":"x@y.com"}')
assert_eq "$PROV_BLOCKED" "403" "14.4 Regular user blocked from provisioning"
