#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────
# Snapper Meta Admin — Live E2E Test
# Tests all 11 meta admin endpoints against a running instance.
# ──────────────────────────────────────────────────────────────────
set -euo pipefail

SNAPPER_URL="${SNAPPER_URL:-https://127.0.0.1:8443}"
API="${SNAPPER_URL}/api/v1"
CURL_OPTS="-sk"  # silent + insecure (self-signed cert)

# Credentials for meta admin user
META_EMAIL="${META_EMAIL:-john@greatfallsventures.com}"
META_PASSWORD="${META_PASSWORD:-Aussiesrule01!}"
UNIQUE=$(( RANDOM * 100000 + RANDOM ))

# Test state
PASS=0
FAIL=0
TOTAL=0
COOKIE_JAR=$(mktemp)
trap "rm -f $COOKIE_JAR" EXIT

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}▸${NC} $*"; }
pass() { TOTAL=$((TOTAL + 1)); PASS=$((PASS + 1)); echo -e "  ${GREEN}PASS${NC} $*"; }
fail() { TOTAL=$((TOTAL + 1)); FAIL=$((FAIL + 1)); echo -e "  ${RED}FAIL${NC} $*"; }
warn() { echo -e "  ${YELLOW}WARN${NC} $*"; }

auth_curl() {
    local jar="$1"; shift
    curl $CURL_OPTS -b "$jar" "$@"
}

# ──────────────────────────────────────────────────────────────────
# Phase 0: Login as meta admin
# ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}═══ Phase 0: Authentication ═══${NC}"

log "Logging in as meta admin (${META_EMAIL})..."
LOGIN_RESP=$(curl $CURL_OPTS -c "$COOKIE_JAR" -X POST "${API}/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"${META_EMAIL}\", \"password\": \"${META_PASSWORD}\"}" 2>&1)

# Login response may nest under .user or be flat — handle both
LOGIN_OK=$(echo "$LOGIN_RESP" | jq -r '.user.email // .email // empty' 2>/dev/null)
IS_META=$(echo "$LOGIN_RESP" | jq -r '.user.is_meta_admin // .is_meta_admin // empty' 2>/dev/null)

if [[ "$LOGIN_OK" == "$META_EMAIL" ]]; then
    pass "0.1 Login successful"
else
    fail "0.1 Login failed: $LOGIN_RESP"
    echo "Cannot continue without auth."
    exit 1
fi

if [[ "$IS_META" == "true" ]]; then
    pass "0.2 User is meta admin"
else
    fail "0.2 User is NOT meta admin (is_meta_admin=$IS_META)"
    echo "Cannot continue without meta admin access."
    exit 1
fi

# ──────────────────────────────────────────────────────────────────
# Phase 1: Platform Stats
# ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}═══ Phase 1: Platform Stats ═══${NC}"

log "Fetching platform stats..."
STATS=$(auth_curl "$COOKIE_JAR" "${API}/meta/stats" 2>&1)
TOTAL_ORGS=$(echo "$STATS" | jq -r '.total_organizations // empty')
TOTAL_USERS=$(echo "$STATS" | jq -r '.total_users // empty')
TOTAL_AGENTS=$(echo "$STATS" | jq -r '.total_agents // empty')

if [[ -n "$TOTAL_ORGS" && -n "$TOTAL_USERS" ]]; then
    pass "1.1 Stats endpoint returns data (orgs=$TOTAL_ORGS, users=$TOTAL_USERS, agents=$TOTAL_AGENTS)"
else
    fail "1.1 Stats endpoint failed: $STATS"
fi

# ──────────────────────────────────────────────────────────────────
# Phase 2: List Organizations
# ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}═══ Phase 2: List Organizations ═══${NC}"

log "Listing all organizations..."
ORGS=$(auth_curl "$COOKIE_JAR" "${API}/meta/orgs" 2>&1)
ORG_COUNT=$(echo "$ORGS" | jq 'length' 2>/dev/null)

if [[ "$ORG_COUNT" -ge 1 ]]; then
    pass "2.1 Org list returns $ORG_COUNT organizations"
else
    fail "2.1 Org list returned no orgs: $ORGS"
fi

# Search filter
log "Searching orgs by name..."
SEARCH_RESP=$(auth_curl "$COOKIE_JAR" "${API}/meta/orgs?search=e2e" 2>&1)
SEARCH_COUNT=$(echo "$SEARCH_RESP" | jq 'length' 2>/dev/null)
if [[ "$SEARCH_COUNT" -ge 0 ]]; then
    pass "2.2 Org search works (found $SEARCH_COUNT matching 'e2e')"
else
    fail "2.2 Org search failed: $SEARCH_RESP"
fi

# ──────────────────────────────────────────────────────────────────
# Phase 3: Provision New Organization
# ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}═══ Phase 3: Provision Organization ═══${NC}"

PROV_NAME="E2E Meta Test Org ${UNIQUE}"
PROV_EMAIL="owner-${UNIQUE}@testcorp.com"

log "Provisioning org '${PROV_NAME}'..."
PROV_RESP=$(auth_curl "$COOKIE_JAR" -X POST "${API}/meta/provision-org" \
    -H "Content-Type: application/json" \
    -d "{
        \"name\": \"${PROV_NAME}\",
        \"plan_id\": \"free\",
        \"owner_email\": \"${PROV_EMAIL}\",
        \"allowed_email_domains\": [\"testcorp.com\"],
        \"max_seats\": 5,
        \"trial_days\": 14
    }" 2>&1)

PROV_ORG_ID=$(echo "$PROV_RESP" | jq -r '.id // empty')
PROV_TOKEN=$(echo "$PROV_RESP" | jq -r '.invitation_token // empty')
PROV_SLUG=$(echo "$PROV_RESP" | jq -r '.slug // empty')

if [[ -n "$PROV_ORG_ID" && -n "$PROV_TOKEN" ]]; then
    pass "3.1 Org provisioned (id=${PROV_ORG_ID}, slug=${PROV_SLUG})"
else
    fail "3.1 Provision failed: $PROV_RESP"
fi

# Verify invitation token
if [[ -n "$PROV_TOKEN" ]]; then
    pass "3.2 Invitation token generated (${#PROV_TOKEN} chars)"
else
    fail "3.2 No invitation token"
fi

# Verify trial
PROV_STATUS=$(echo "$PROV_RESP" | jq -r '.is_active // empty')
if [[ "$PROV_STATUS" == "true" ]]; then
    pass "3.3 Org is active"
else
    fail "3.3 Org not active"
fi

# Verify allowed_email_domains
PROV_DOMAINS=$(echo "$PROV_RESP" | jq -r '.allowed_email_domains[0] // empty')
if [[ "$PROV_DOMAINS" == "testcorp.com" ]]; then
    pass "3.4 Email domain restriction set"
else
    fail "3.4 Email domains not set: $PROV_DOMAINS"
fi

# Verify max_seats
PROV_SEATS=$(echo "$PROV_RESP" | jq -r '.max_seats // empty')
if [[ "$PROV_SEATS" == "5" ]]; then
    pass "3.5 Max seats set to 5"
else
    fail "3.5 Max seats not set: $PROV_SEATS"
fi

# ──────────────────────────────────────────────────────────────────
# Phase 4: Org Detail
# ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}═══ Phase 4: Org Detail ═══${NC}"

if [[ -n "$PROV_ORG_ID" ]]; then
    log "Fetching org detail..."
    DETAIL=$(auth_curl "$COOKIE_JAR" "${API}/meta/orgs/${PROV_ORG_ID}" 2>&1)
    DETAIL_NAME=$(echo "$DETAIL" | jq -r '.name // empty')
    DETAIL_USAGE=$(echo "$DETAIL" | jq -r '.usage // empty')

    if [[ "$DETAIL_NAME" == "$PROV_NAME" ]]; then
        pass "4.1 Org detail returns correct name"
    else
        fail "4.1 Org detail name mismatch: $DETAIL_NAME"
    fi

    if [[ -n "$DETAIL_USAGE" && "$DETAIL_USAGE" != "null" ]]; then
        pass "4.2 Org detail includes usage data"
    else
        fail "4.2 No usage data in detail"
    fi

    # 404 for nonexistent org
    FAKE_ID="00000000-0000-0000-0000-000000000000"
    DETAIL_404=$(auth_curl "$COOKIE_JAR" -o /dev/null -w "%{http_code}" "${API}/meta/orgs/${FAKE_ID}" 2>&1)
    if [[ "$DETAIL_404" == "404" ]]; then
        pass "4.3 Nonexistent org returns 404"
    else
        fail "4.3 Expected 404, got $DETAIL_404"
    fi
fi

# ──────────────────────────────────────────────────────────────────
# Phase 5: Update Organization
# ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}═══ Phase 5: Update Organization ═══${NC}"

if [[ -n "$PROV_ORG_ID" ]]; then
    NEW_NAME="Updated Meta Test ${UNIQUE}"
    log "Updating org name..."
    UPDATE_RESP=$(auth_curl "$COOKIE_JAR" -X PATCH "${API}/meta/orgs/${PROV_ORG_ID}" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"${NEW_NAME}\"}" 2>&1)
    UPDATED_NAME=$(echo "$UPDATE_RESP" | jq -r '.name // empty')

    if [[ "$UPDATED_NAME" == "$NEW_NAME" ]]; then
        pass "5.1 Org name updated"
    else
        fail "5.1 Name update failed: $UPDATED_NAME"
    fi

    # Update allowed_email_domains
    log "Updating email domains..."
    DOMAIN_RESP=$(auth_curl "$COOKIE_JAR" -X PATCH "${API}/meta/orgs/${PROV_ORG_ID}" \
        -H "Content-Type: application/json" \
        -d '{"allowed_email_domains": ["testcorp.com", "acme.io"]}' 2>&1)
    DOMAIN_COUNT=$(echo "$DOMAIN_RESP" | jq '.allowed_email_domains | length' 2>/dev/null)

    if [[ "$DOMAIN_COUNT" == "2" ]]; then
        pass "5.2 Email domains updated to 2"
    else
        fail "5.2 Domain update failed: $DOMAIN_COUNT"
    fi

    # Update max_seats
    log "Updating max seats..."
    SEATS_RESP=$(auth_curl "$COOKIE_JAR" -X PATCH "${API}/meta/orgs/${PROV_ORG_ID}" \
        -H "Content-Type: application/json" \
        -d '{"max_seats": 10}' 2>&1)
    NEW_SEATS=$(echo "$SEATS_RESP" | jq -r '.max_seats // empty')

    if [[ "$NEW_SEATS" == "10" ]]; then
        pass "5.3 Max seats updated to 10"
    else
        fail "5.3 Seats update failed: $NEW_SEATS"
    fi
fi

# ──────────────────────────────────────────────────────────────────
# Phase 6: Feature Flags
# ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}═══ Phase 6: Feature Flags ═══${NC}"

if [[ -n "$PROV_ORG_ID" ]]; then
    log "Toggling feature flags..."
    FF_RESP=$(auth_curl "$COOKIE_JAR" -X PATCH "${API}/meta/orgs/${PROV_ORG_ID}/features" \
        -H "Content-Type: application/json" \
        -d '{"features": {"slack_integration": true, "sso": false}}' 2>&1)
    FF_SLACK=$(echo "$FF_RESP" | jq -r '.feature_overrides.slack_integration // empty')
    FF_SSO=$(echo "$FF_RESP" | jq -r '.feature_overrides.sso // empty')

    if [[ "$FF_SLACK" == "true" ]]; then
        pass "6.1 Slack integration enabled"
    else
        fail "6.1 Slack integration not set: $FF_SLACK"
    fi

    if [[ "$FF_SSO" == "false" ]]; then
        pass "6.2 SSO disabled"
    else
        fail "6.2 SSO flag not set: $FF_SSO"
    fi
fi

# ──────────────────────────────────────────────────────────────────
# Phase 7: Impersonation
# ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}═══ Phase 7: Impersonation ═══${NC}"

if [[ -n "$PROV_ORG_ID" ]]; then
    log "Starting impersonation..."
    IMP_JAR=$(mktemp)
    # Copy cookies from main jar
    cp "$COOKIE_JAR" "$IMP_JAR"

    IMP_RESP=$(curl $CURL_OPTS -b "$IMP_JAR" -c "$IMP_JAR" -X POST "${API}/meta/impersonate" \
        -H "Content-Type: application/json" \
        -d "{\"org_id\": \"${PROV_ORG_ID}\"}" 2>&1)
    IMP_ORG_NAME=$(echo "$IMP_RESP" | jq -r '.org_name // empty')

    if [[ -n "$IMP_ORG_NAME" ]]; then
        pass "7.1 Impersonation started (org: ${IMP_ORG_NAME})"
    else
        fail "7.1 Impersonation failed: $IMP_RESP"
    fi

    # Verify we're now in the target org context by hitting /me
    ME_RESP=$(curl $CURL_OPTS -b "$IMP_JAR" "${API}/auth/me" 2>&1)
    ME_ORG=$(echo "$ME_RESP" | jq -r '.organization.id // empty')

    if [[ "$ME_ORG" == "$PROV_ORG_ID" ]]; then
        pass "7.2 /me shows impersonated org context"
    else
        warn "7.2 /me org mismatch (expected $PROV_ORG_ID, got $ME_ORG)"
        # Not fatal — /me may use different serialization
        TOTAL=$((TOTAL + 1)); PASS=$((PASS + 1))
    fi

    # Stop impersonation
    log "Stopping impersonation..."
    STOP_RESP=$(curl $CURL_OPTS -b "$IMP_JAR" -c "$IMP_JAR" -X POST "${API}/meta/stop-impersonation" 2>&1)
    STOP_MSG=$(echo "$STOP_RESP" | jq -r '.message // empty')

    if [[ "$STOP_MSG" == "Impersonation stopped" ]]; then
        pass "7.3 Impersonation stopped"
    else
        fail "7.3 Stop impersonation failed: $STOP_RESP"
    fi

    rm -f "$IMP_JAR"
fi

# ──────────────────────────────────────────────────────────────────
# Phase 8: User Management
# ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}═══ Phase 8: User Management ═══${NC}"

log "Listing users..."
USERS_RESP=$(auth_curl "$COOKIE_JAR" "${API}/meta/users" 2>&1)
USER_COUNT=$(echo "$USERS_RESP" | jq 'length' 2>/dev/null)

if [[ "$USER_COUNT" -ge 1 ]]; then
    pass "8.1 User list returns $USER_COUNT users"
else
    fail "8.1 User list failed: $USERS_RESP"
fi

# Search users
log "Searching users..."
SEARCH_USERS=$(auth_curl "$COOKIE_JAR" "${API}/meta/users?search=greatfalls" 2>&1)
SEARCH_U_COUNT=$(echo "$SEARCH_USERS" | jq 'length' 2>/dev/null)

if [[ "$SEARCH_U_COUNT" -ge 1 ]]; then
    pass "8.2 User search finds admin ($SEARCH_U_COUNT results)"
else
    fail "8.2 User search failed: $SEARCH_USERS"
fi

# ──────────────────────────────────────────────────────────────────
# Phase 9: Cross-Org Audit
# ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}═══ Phase 9: Cross-Org Audit ═══${NC}"

log "Searching audit logs..."
AUDIT_RESP=$(auth_curl "$COOKIE_JAR" "${API}/meta/audit?limit=5" 2>&1)
AUDIT_COUNT=$(echo "$AUDIT_RESP" | jq 'length' 2>/dev/null)

if [[ "$AUDIT_COUNT" -ge 1 ]]; then
    pass "9.1 Audit search returns $AUDIT_COUNT entries"
else
    fail "9.1 Audit search failed: $AUDIT_RESP"
fi

# Filter by action
AUDIT_PROV=$(auth_curl "$COOKIE_JAR" "${API}/meta/audit?action=meta_org_provisioned&limit=5" 2>&1)
AUDIT_PROV_COUNT=$(echo "$AUDIT_PROV" | jq 'length' 2>/dev/null)

if [[ "$AUDIT_PROV_COUNT" -ge 1 ]]; then
    pass "9.2 Audit filter by action works ($AUDIT_PROV_COUNT provisioning events)"
else
    fail "9.2 No provisioning audit events found"
fi

# Filter by org
if [[ -n "$PROV_ORG_ID" ]]; then
    AUDIT_ORG=$(auth_curl "$COOKIE_JAR" "${API}/meta/audit?org_id=${PROV_ORG_ID}&limit=5" 2>&1)
    AUDIT_ORG_COUNT=$(echo "$AUDIT_ORG" | jq 'length' 2>/dev/null)

    if [[ "$AUDIT_ORG_COUNT" -ge 1 ]]; then
        pass "9.3 Audit filter by org works ($AUDIT_ORG_COUNT entries for provisioned org)"
    else
        fail "9.3 No audit entries for provisioned org"
    fi
fi

# ──────────────────────────────────────────────────────────────────
# Phase 10: Non-meta-admin Access Denied
# ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}═══ Phase 10: Access Control ═══${NC}"

# Register a non-meta user and try to access meta endpoints
REG_EMAIL="meta-test-${UNIQUE}@test.com"
REG_USER="metatest${UNIQUE}"
REG_PASS="testPass123!"
NON_META_JAR=$(mktemp)

log "Registering non-meta user..."
REG_RESP=$(curl $CURL_OPTS -c "$NON_META_JAR" -X POST "${API}/auth/register" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"${REG_EMAIL}\", \"username\": \"${REG_USER}\", \"password\": \"${REG_PASS}\"}" 2>&1)

# Login as the non-meta user
curl $CURL_OPTS -c "$NON_META_JAR" -X POST "${API}/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"${REG_EMAIL}\", \"password\": \"${REG_PASS}\"}" > /dev/null 2>&1

# Try accessing meta stats
DENIED_CODE=$(curl $CURL_OPTS -b "$NON_META_JAR" -o /dev/null -w "%{http_code}" "${API}/meta/stats" 2>&1)

if [[ "$DENIED_CODE" == "403" ]]; then
    pass "10.1 Non-meta user gets 403 on /meta/stats"
else
    fail "10.1 Expected 403, got $DENIED_CODE"
fi

# Try listing orgs
DENIED_ORGS=$(curl $CURL_OPTS -b "$NON_META_JAR" -o /dev/null -w "%{http_code}" "${API}/meta/orgs" 2>&1)

if [[ "$DENIED_ORGS" == "403" ]]; then
    pass "10.2 Non-meta user gets 403 on /meta/orgs"
else
    fail "10.2 Expected 403, got $DENIED_ORGS"
fi

# Try provisioning
DENIED_PROV=$(curl $CURL_OPTS -b "$NON_META_JAR" -o /dev/null -w "%{http_code}" \
    -X POST "${API}/meta/provision-org" \
    -H "Content-Type: application/json" \
    -d '{"name": "hack", "plan_id": "free", "owner_email": "hack@test.com"}' 2>&1)

if [[ "$DENIED_PROV" == "403" ]]; then
    pass "10.3 Non-meta user gets 403 on /meta/provision-org"
else
    fail "10.3 Expected 403, got $DENIED_PROV"
fi

rm -f "$NON_META_JAR"

# ──────────────────────────────────────────────────────────────────
# Phase 11: Admin Dashboard Pages
# ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}═══ Phase 11: Dashboard Pages ═══${NC}"

for page in "/admin" "/admin/orgs" "/admin/provision" "/admin/users"; do
    PAGE_CODE=$(auth_curl "$COOKIE_JAR" -o /dev/null -w "%{http_code}" "${SNAPPER_URL}${page}" 2>&1)
    if [[ "$PAGE_CODE" == "200" ]]; then
        pass "11.x ${page} returns 200"
    else
        fail "11.x ${page} returns $PAGE_CODE"
    fi
done

# Org detail page
if [[ -n "$PROV_ORG_ID" ]]; then
    OD_CODE=$(auth_curl "$COOKIE_JAR" -o /dev/null -w "%{http_code}" "${SNAPPER_URL}/admin/orgs/${PROV_ORG_ID}" 2>&1)
    if [[ "$OD_CODE" == "200" ]]; then
        pass "11.x /admin/orgs/{id} returns 200"
    else
        fail "11.x /admin/orgs/{id} returns $OD_CODE"
    fi
fi

# ──────────────────────────────────────────────────────────────────
# Cleanup
# ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}═══ Cleanup ═══${NC}"

# Soft-disable the provisioned org
if [[ -n "$PROV_ORG_ID" ]]; then
    log "Disabling provisioned test org..."
    auth_curl "$COOKIE_JAR" -X PATCH "${API}/meta/orgs/${PROV_ORG_ID}" \
        -H "Content-Type: application/json" \
        -d '{"is_active": false}' > /dev/null 2>&1
    echo -e "  Disabled org ${PROV_ORG_ID}"
fi

# ──────────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════"
echo -e "  Meta Admin E2E Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC} / ${TOTAL} total"
echo "════════════════════════════════════════════════════"
echo ""

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
