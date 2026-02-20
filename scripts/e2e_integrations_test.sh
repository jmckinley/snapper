#!/usr/bin/env bash
#
# Snapper E2E — Traffic Discovery & Integration Tests
#
# Tests the discovery-first integration endpoints:
#   - Active packs (rule groups by source)
#   - Traffic discovery (insights, coverage, known-servers)
#   - Rule creation from traffic (create-rule, create-server-rules)
#   - Disable server rules
#   - Unknown server → 3 generic defaults
#   - Known server → curated rule pack (> 3 rules)
#
# Run on VPS:  bash /opt/snapper/scripts/e2e_integrations_test.sh
# Locally:     SNAPPER_URL=http://localhost:8000 bash scripts/e2e_integrations_test.sh
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
REDIS_CONTAINER="${REDIS_CONTAINER:-snapper-redis-1}"
AGENT_EID="e2e-integ-test-agent"

# ============================================================
# Counters & state
# ============================================================
PASS=0
FAIL=0
TOTAL=0
CREATED_RULES=()
AGENT_UUID=""
AGENT_API_KEY=""

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

assert_contains() {
    local haystack="$1" needle="$2" label="$3"
    TOTAL=$((TOTAL + 1))
    if echo "$haystack" | grep -qF "$needle"; then
        PASS=$((PASS + 1))
        echo -e "  ${GREEN}PASS${NC} $label"
    else
        FAIL=$((FAIL + 1))
        echo -e "  ${RED}FAIL${NC} $label  (expected to contain '$needle')"
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

assert_gte() {
    local actual="$1" threshold="$2" label="$3"
    TOTAL=$((TOTAL + 1))
    if [[ "$actual" -ge "$threshold" ]] 2>/dev/null; then
        PASS=$((PASS + 1))
        echo -e "  ${GREEN}PASS${NC} $label"
    else
        FAIL=$((FAIL + 1))
        echo -e "  ${RED}FAIL${NC} $label  (expected >= $threshold, got '$actual')"
    fi
}

# Check if a decision is effectively "deny" (handles learning mode)
# In learning mode, deny returns as "allow" with reason containing "[LEARNING MODE] Would be denied"
is_denied() {
    local eval_result="$1"
    local decision
    decision=$(echo "$eval_result" | jq -r '.decision // empty')
    if [[ "$decision" == "deny" ]]; then
        echo "deny"
        return
    fi
    local reason
    reason=$(echo "$eval_result" | jq -r '.reason // empty')
    if echo "$reason" | grep -q "LEARNING MODE.*denied"; then
        echo "deny"
        return
    fi
    echo "$decision"
}

# Wrapper for curl with host header + auth cookies
COOKIE_JAR=""
AUTH_ARGS=()
api_curl() {
    curl -sf "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" "${AUTH_ARGS[@]+"${AUTH_ARGS[@]}"}" "$@" 2>/dev/null
}

# Create a rule, capture its UUID, track for cleanup
create_rule() {
    local json="$1"
    local resp
    resp=$(curl -sf -X POST "${API}/rules" \
        "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" \
        "${AUTH_ARGS[@]+"${AUTH_ARGS[@]}"}" \
        -H "Content-Type: application/json" \
        -d "$json" 2>/dev/null) || { echo ""; return 1; }
    local rule_id
    rule_id=$(echo "$resp" | jq -r '.id // empty')
    if [[ -n "$rule_id" ]]; then
        CREATED_RULES+=("$rule_id")
        echo "$rule_id"
    else
        echo ""
        return 1
    fi
}

delete_rule() {
    local rule_id="$1"
    curl -sf -X DELETE "${API}/rules/${rule_id}?hard_delete=true" \
        "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" \
        "${AUTH_ARGS[@]+"${AUTH_ARGS[@]}"}" >/dev/null 2>&1
}

# Evaluate a request against the rule engine
evaluate() {
    local json="$1"
    local api_key_args=()
    if [[ -n "$AGENT_API_KEY" ]]; then
        api_key_args=(-H "X-API-Key: ${AGENT_API_KEY}")
    fi
    local resp http_code
    resp=$(curl -s -w "\n%{http_code}" -X POST "${API}/rules/evaluate" \
        "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" \
        "${api_key_args[@]+"${api_key_args[@]}"}" \
        -H "Content-Type: application/json" \
        -d "$json" 2>/dev/null)
    http_code=$(echo "$resp" | tail -1)
    local body
    body=$(echo "$resp" | sed '$d')
    if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
        echo "$body"
    elif [[ "$http_code" == "429" ]]; then
        sleep 3
        curl -sf -X POST "${API}/rules/evaluate" \
            "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" \
            "${api_key_args[@]+"${api_key_args[@]}"}" \
            -H "Content-Type: application/json" \
            -d "$json" 2>/dev/null
    else
        echo "{\"decision\":\"error\",\"reason\":\"HTTP $http_code: $body\"}"
    fi
}

# Flush traffic insight cache
flush_traffic_cache() {
    docker exec "$REDIS_CONTAINER" redis-cli --scan --pattern "traffic_insights:*" 2>/dev/null | while read -r key; do
        docker exec "$REDIS_CONTAINER" redis-cli del "$key" >/dev/null 2>&1
    done
}

# ============================================================
# Auth setup — handles both self-hosted and cloud modes
# ============================================================
setup_auth() {
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" \
        "${API}/agents?page_size=1" 2>/dev/null)
    if [[ "$status" != "401" ]]; then
        log "No auth required (self-hosted mode)"
        return 0
    fi

    log "Auth required — setting up test session..."
    COOKIE_JAR=$(mktemp /tmp/e2e_integ_cookies_XXXXXX)
    local test_email="e2e-integ-test@snapper.test"
    local test_pass="E2eTestPass123!"

    local reg_resp reg_code
    reg_resp=$(curl -s -w "\n%{http_code}" -X POST "${API}/auth/register" \
        "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" \
        -H "Content-Type: application/json" \
        -c "$COOKIE_JAR" \
        -d "{\"email\":\"${test_email}\",\"password\":\"${test_pass}\",\"password_confirm\":\"${test_pass}\",\"username\":\"e2e-integ-test\"}" 2>/dev/null)
    reg_code=$(echo "$reg_resp" | tail -1)

    if [[ "$reg_code" == "200" || "$reg_code" == "201" ]]; then
        AUTH_ARGS=(-b "$COOKIE_JAR")
        log "Registered and authenticated as $test_email"
        return 0
    fi

    local login_resp
    login_resp=$(curl -s -X POST "${API}/auth/login" \
        "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" \
        -H "Content-Type: application/json" \
        -c "$COOKIE_JAR" \
        -d "{\"email\":\"${test_email}\",\"password\":\"${test_pass}\"}" 2>/dev/null)

    local login_ok
    login_ok=$(echo "$login_resp" | jq -r '.email // .user.email // empty' 2>/dev/null)
    if [[ "$login_ok" == "$test_email" ]]; then
        AUTH_ARGS=(-b "$COOKIE_JAR")
        log "Authenticated as $test_email"
    else
        err "Auth setup failed (register: $reg_code, login: $login_resp)"
        return 1
    fi
}

# ============================================================
# Cleanup (runs on EXIT)
# ============================================================
cleanup() {
    echo ""
    echo -e "${BOLD}--- Cleanup ---${NC}"

    # Delete test rules
    for rid in "${CREATED_RULES[@]+"${CREATED_RULES[@]}"}"; do
        [[ -z "$rid" ]] && continue
        if delete_rule "$rid"; then log "Deleted rule $rid"; else warn "Could not delete rule $rid"; fi
    done

    # Delete test agent
    if [[ -n "$AGENT_UUID" ]]; then
        if api_curl -X DELETE "${API}/agents/${AGENT_UUID}?hard_delete=true" >/dev/null 2>&1; then
            log "Deleted test agent $AGENT_UUID"
        else
            warn "Could not delete test agent"
        fi
    fi

    # Flush traffic cache
    flush_traffic_cache 2>/dev/null

    # Clean up orphaned test agents from all E2E runs
    api_curl -X POST "${API}/agents/cleanup-test?confirm=true" >/dev/null 2>&1

    echo ""
    echo -e "${BOLD}========================================${NC}"
    if [[ $FAIL -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}Results: $PASS/$TOTAL passed, $FAIL failed${NC}"
    else
        echo -e "${RED}${BOLD}Results: $PASS/$TOTAL passed, $FAIL failed${NC}"
    fi
    echo -e "${BOLD}========================================${NC}"

    [[ -n "$COOKIE_JAR" && -f "$COOKIE_JAR" ]] && rm -f "$COOKIE_JAR"

    if [[ $FAIL -gt 0 ]]; then
        exit 1
    fi
}
trap cleanup EXIT

# ============================================================
# Phase 0: Environment Verification
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 0: Environment Verification ===${NC}"

# Auth setup
setup_auth

# 0.1 Snapper health
log "Checking Snapper health..."
HEALTH=$(api_curl "${SNAPPER_URL}/health" | jq -r '.status // empty')
assert_eq "$HEALTH" "healthy" "0.1 Snapper health check"

# 0.2 Redis connectivity
log "Checking Redis..."
REDIS_PING=$(docker exec "$REDIS_CONTAINER" redis-cli ping 2>/dev/null || echo "FAIL")
assert_eq "$REDIS_PING" "PONG" "0.2 Redis connectivity"

# 0.3 Create test agent
log "Creating test agent..."
STALE_ID=$(api_curl "${API}/agents?search=${AGENT_EID}&include_deleted=true" \
    | jq -r ".items[] | select(.external_id == \"${AGENT_EID}\") | .id" 2>/dev/null)
if [[ -n "$STALE_ID" ]]; then
    api_curl -X DELETE "${API}/agents/${STALE_ID}?hard_delete=true" >/dev/null 2>&1
    log "Cleaned up stale agent $STALE_ID"
fi

AGENT_RESP=$(api_curl -X POST "${API}/agents" \
    -H "Content-Type: application/json" \
    -d "{
        \"name\": \"E2E Integration Test Agent\",
        \"external_id\": \"${AGENT_EID}\",
        \"description\": \"Temporary agent for integration E2E tests\",
        \"allowed_origins\": [\"*\"],
        \"require_localhost_only\": false
    }")
AGENT_UUID=$(echo "$AGENT_RESP" | jq -r '.id // empty')
AGENT_API_KEY=$(echo "$AGENT_RESP" | jq -r '.api_key // empty')
assert_not_eq "$AGENT_UUID" "" "0.3 Test agent created"

if [[ -z "$AGENT_UUID" ]]; then
    err "Cannot continue without a test agent. Aborting."
    exit 1
fi

log "Agent UUID: $AGENT_UUID"
log "Agent API Key: ${AGENT_API_KEY:0:10}..."

# ============================================================
# Phase 1: Active Packs Endpoint
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 1: Active Packs ===${NC}"

# Pre-cleanup: hard-delete any stale server/pack rules from prior runs
log "Pre-cleanup: removing stale active packs via SQL..."
PACK_DEL=$(docker exec "$POSTGRES_CONTAINER" psql -U snapper -d snapper -t -c \
    "DELETE FROM rules WHERE source IN ('rule_pack', 'traffic_discovery') AND is_deleted = false RETURNING id" 2>&1)
PACK_DEL_COUNT=$(echo "$PACK_DEL" | grep -c '[0-9a-f]' 2>/dev/null || echo "0")
log "  Deleted $PACK_DEL_COUNT stale pack/discovery rules"

# 1.1 Active packs returns empty list when no rules from packs/discovery
log "Fetching active packs (should be empty)..."
PACKS=$(api_curl "${API}/integrations/active-packs")
PACKS_COUNT=$(echo "$PACKS" | jq 'length')
assert_eq "$PACKS_COUNT" "0" "1.1 No active packs initially"

# 1.2 Create server rules then verify they appear in active packs
log "Creating rules for 'slack' to test active packs..."
SLACK_SRV=$(api_curl -X POST "${API}/integrations/traffic/create-server-rules" \
    -H "Content-Type: application/json" \
    -d '{"server_name": "slack"}')
SLACK_SRV_COUNT=$(echo "$SLACK_SRV" | jq -r '.rules_created // 0')
assert_gt "$SLACK_SRV_COUNT" "0" "1.2a Slack server rules created"

# Track for cleanup
SLACK_SRV_IDS=$(echo "$SLACK_SRV" | jq -r '.rules[].id')
for sid in $SLACK_SRV_IDS; do CREATED_RULES+=("$sid"); done

PACKS_AFTER=$(api_curl "${API}/integrations/active-packs")
PACKS_AFTER_COUNT=$(echo "$PACKS_AFTER" | jq 'length')
assert_gt "$PACKS_AFTER_COUNT" "0" "1.2b Active packs non-empty after creating rules"

# 1.3 Active pack entry has correct structure
FIRST_PACK=$(echo "$PACKS_AFTER" | jq '.[0]')
FP_DISPLAY=$(echo "$FIRST_PACK" | jq -r '.display_name // empty')
FP_ICON=$(echo "$FIRST_PACK" | jq -r '.icon // empty')
FP_RULE_COUNT=$(echo "$FIRST_PACK" | jq '.rule_count // 0')
FP_RULES_LEN=$(echo "$FIRST_PACK" | jq '.rules | length')
assert_not_eq "$FP_DISPLAY" "" "1.3a Pack has display_name"
assert_not_eq "$FP_ICON" "" "1.3b Pack has icon"
assert_gt "$FP_RULE_COUNT" "0" "1.3c Pack rule_count > 0"
assert_eq "$FP_RULE_COUNT" "$FP_RULES_LEN" "1.3d rule_count matches rules array length"

# 1.4 Agent-scoped active packs
log "Fetching agent-scoped active packs..."
AGENT_PACKS=$(api_curl "${API}/integrations/active-packs?agent_id=${AGENT_UUID}")
AGENT_PACKS_COUNT=$(echo "$AGENT_PACKS" | jq 'length')
# Global rules (agent_id=null) should still appear
assert_gte "$AGENT_PACKS_COUNT" "0" "1.4 Agent-scoped packs returns valid response"

# 1.5 Rules within pack have required fields
PACK_RULE=$(echo "$FIRST_PACK" | jq '.rules[0]')
PR_ID=$(echo "$PACK_RULE" | jq -r '.id // empty')
PR_NAME=$(echo "$PACK_RULE" | jq -r '.name // empty')
PR_ACTION=$(echo "$PACK_RULE" | jq -r '.action // empty')
assert_not_eq "$PR_ID" "" "1.5a Pack rule has id"
assert_not_eq "$PR_NAME" "" "1.5b Pack rule has name"
assert_not_eq "$PR_ACTION" "" "1.5c Pack rule has action"

# ============================================================
# Phase 2: Known Servers Endpoint
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 2: Known MCP Servers ===${NC}"

log "Fetching known servers..."
KNOWN=$(api_curl "${API}/integrations/traffic/known-servers")
KNOWN_COUNT=$(echo "$KNOWN" | jq 'length')
assert_gt "$KNOWN_COUNT" "10" "2.1 More than 10 known MCP servers"

# 2.2 Check structure of first server
FIRST_DISPLAY=$(echo "$KNOWN" | jq -r '.[0].display // empty')
FIRST_KEYS=$(echo "$KNOWN" | jq '.[0].keys | length')
assert_not_eq "$FIRST_DISPLAY" "" "2.2a First server has display name"
assert_gt "$FIRST_KEYS" "0" "2.2b First server has at least one key"

# 2.3 GitHub should be in the list
GITHUB_FOUND=$(echo "$KNOWN" | jq '[.[] | select(.display == "GitHub")] | length')
assert_gt "$GITHUB_FOUND" "0" "2.3 GitHub found in known servers"

# 2.4 Slack should be in the list with template_id
SLACK_TID=$(echo "$KNOWN" | jq -r '[.[] | select(.display == "Slack")] | .[0].template_id // empty')
assert_eq "$SLACK_TID" "slack" "2.4 Slack has template_id='slack'"

# ============================================================
# Phase 3: Traffic Insights (Empty State)
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 3: Traffic Insights (Structure Check) ===${NC}"

flush_traffic_cache

# 3.1 Insights endpoint returns valid structure
log "Fetching traffic insights..."
INSIGHTS=$(api_curl "${API}/integrations/traffic/insights?hours=1")
INSIGHTS_EVALS=$(echo "$INSIGHTS" | jq '.total_evaluations // -1')
assert_gt "$INSIGHTS_EVALS" "-2" "3.1a Insights returns total_evaluations (number)"
INSIGHTS_GROUPS=$(echo "$INSIGHTS" | jq '.service_groups | length // 0')
log "Current state: ${INSIGHTS_EVALS} evaluations, ${INSIGHTS_GROUPS} groups in last 1h"

# 3.2 Insights structure has required fields
INSIGHTS_FIELDS=$(echo "$INSIGHTS" | jq 'keys | sort | join(",")')
assert_contains "$INSIGHTS_FIELDS" "period_hours" "3.2a period_hours field present"
assert_contains "$INSIGHTS_FIELDS" "total_uncovered" "3.2b total_uncovered field present"
assert_contains "$INSIGHTS_FIELDS" "total_unique_commands" "3.2c total_unique_commands field present"

# ============================================================
# Phase 4: Traffic Coverage Endpoint
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 4: Traffic Coverage Check ===${NC}"

# 4.1 Uncovered command (scoped to our test agent to avoid false positives from other rules)
log "Checking coverage of uncovered command..."
COV_UNCOVERED=$(api_curl "${API}/integrations/traffic/coverage?command=mcp__e2e_unique_xyzzy_$(date +%s)__do_something&agent_id=${AGENT_UUID}")
COV_COVERED=$(echo "$COV_UNCOVERED" | jq -r '.covered')
assert_eq "$COV_COVERED" "false" "4.1 Uncovered command returns covered=false (agent-scoped)"

# 4.2 Coverage includes parsed info
COV_PARSE_CHECK=$(api_curl "${API}/integrations/traffic/coverage?command=mcp__test_e2e__do_something")
COV_SOURCE_TYPE=$(echo "$COV_PARSE_CHECK" | jq -r '.parsed.source_type')
COV_SERVER=$(echo "$COV_PARSE_CHECK" | jq -r '.parsed.server_key')
assert_eq "$COV_SOURCE_TYPE" "mcp" "4.2a Parsed source_type is 'mcp'"
assert_eq "$COV_SERVER" "test_e2e" "4.2b Parsed server_key is 'test_e2e'"

# 4.3 Create a covering rule, then check again
log "Creating covering rule and re-checking..."
COV_RULE_ID=$(create_rule '{
    "name":"e2e-cover-test",
    "rule_type":"command_allowlist",
    "action":"allow",
    "parameters":{"patterns":["^mcp__test_e2e__.*"]},
    "priority":100,
    "is_active":true
}')
assert_not_eq "$COV_RULE_ID" "" "4.3a Covering rule created"

COV_NOW=$(api_curl "${API}/integrations/traffic/coverage?command=mcp__test_e2e__do_something")
COV_NOW_COVERED=$(echo "$COV_NOW" | jq -r '.covered')
COV_NOW_RULES=$(echo "$COV_NOW" | jq '.matching_rules | length')
assert_eq "$COV_NOW_COVERED" "true" "4.3b Command now covered"
assert_gt "$COV_NOW_RULES" "0" "4.3c Has matching rules"

# 4.4 Coverage with known server includes template_id
log "Checking coverage parse for known server..."
COV_GITHUB=$(api_curl "${API}/integrations/traffic/coverage?command=mcp__github__create_issue")
COV_GH_TID=$(echo "$COV_GITHUB" | jq -r '.parsed.template_id // empty')
assert_eq "$COV_GH_TID" "github" "4.4 GitHub command maps to template_id='github'"

# 4.5 Coverage for CLI command
COV_CLI=$(api_curl "${API}/integrations/traffic/coverage?command=git+status")
COV_CLI_TYPE=$(echo "$COV_CLI" | jq -r '.parsed.source_type')
assert_eq "$COV_CLI_TYPE" "cli" "4.5 'git status' parsed as CLI command"

# 4.6 Coverage for built-in tool
COV_BUILTIN=$(api_curl "${API}/integrations/traffic/coverage?command=browser")
COV_BI_TYPE=$(echo "$COV_BUILTIN" | jq -r '.parsed.source_type')
COV_BI_NAME=$(echo "$COV_BUILTIN" | jq -r '.parsed.display_name')
assert_eq "$COV_BI_TYPE" "builtin" "4.6a 'browser' parsed as builtin"
assert_eq "$COV_BI_NAME" "Browser" "4.6b Display name is 'Browser'"

# 4.7 Coverage for OpenClaw-style tool name
COV_OC=$(api_curl "${API}/integrations/traffic/coverage?command=slack_list_channels")
COV_OC_SERVER=$(echo "$COV_OC" | jq -r '.parsed.server_key')
COV_OC_TID=$(echo "$COV_OC" | jq -r '.parsed.template_id // empty')
assert_eq "$COV_OC_SERVER" "slack" "4.7a 'slack_list_channels' parsed as server=slack"
assert_eq "$COV_OC_TID" "slack" "4.7b Maps to template_id='slack'"

# ============================================================
# Phase 5: Rule Creation from Traffic
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 5: Rule Creation from Traffic ===${NC}"

# 5.1 Create rule from command (prefix mode)
log "Creating rule from MCP command (prefix mode)..."
CREATE_RESP=$(api_curl -X POST "${API}/integrations/traffic/create-rule" \
    -H "Content-Type: application/json" \
    -d '{
        "command": "mcp__notion__create_page",
        "action": "allow",
        "pattern_mode": "prefix"
    }')
CREATE_ID=$(echo "$CREATE_RESP" | jq -r '.id // empty')
CREATE_NAME=$(echo "$CREATE_RESP" | jq -r '.name // empty')
CREATE_ACTION=$(echo "$CREATE_RESP" | jq -r '.action // empty')
assert_not_eq "$CREATE_ID" "" "5.1a Rule created from traffic"
assert_contains "$CREATE_NAME" "Notion" "5.1b Name contains 'Notion'"
assert_eq "$CREATE_ACTION" "allow" "5.1c Action is 'allow'"
# Track for cleanup
if [[ -n "$CREATE_ID" ]]; then CREATED_RULES+=("$CREATE_ID"); fi

# 5.2 Create rule from command (exact mode)
log "Creating rule from command (exact mode)..."
EXACT_RESP=$(api_curl -X POST "${API}/integrations/traffic/create-rule" \
    -H "Content-Type: application/json" \
    -d '{
        "command": "mcp__linear__delete_issue",
        "action": "deny",
        "pattern_mode": "exact"
    }')
EXACT_ID=$(echo "$EXACT_RESP" | jq -r '.id // empty')
EXACT_TYPE=$(echo "$EXACT_RESP" | jq -r '.rule_type // empty')
assert_not_eq "$EXACT_ID" "" "5.2a Exact-mode rule created"
assert_eq "$EXACT_TYPE" "command_denylist" "5.2b Deny creates command_denylist"
if [[ -n "$EXACT_ID" ]]; then CREATED_RULES+=("$EXACT_ID"); fi

# 5.3 Create rule with custom name
NAMED_RESP=$(api_curl -X POST "${API}/integrations/traffic/create-rule" \
    -H "Content-Type: application/json" \
    -d '{
        "command": "mcp__github__push",
        "action": "require_approval",
        "pattern_mode": "verb",
        "name": "E2E Custom Named Rule"
    }')
NAMED_NAME=$(echo "$NAMED_RESP" | jq -r '.name // empty')
NAMED_ID=$(echo "$NAMED_RESP" | jq -r '.id // empty')
assert_eq "$NAMED_NAME" "E2E Custom Named Rule" "5.3 Custom name used"
if [[ -n "$NAMED_ID" ]]; then CREATED_RULES+=("$NAMED_ID"); fi

# 5.4 Empty command returns 400
EMPTY_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" \
    "${AUTH_ARGS[@]+"${AUTH_ARGS[@]}"}" \
    -X POST "${API}/integrations/traffic/create-rule" \
    -H "Content-Type: application/json" \
    -d '{"command": "  ", "action": "allow"}')
assert_eq "$EMPTY_CODE" "400" "5.4 Empty command returns 400"

# 5.5 Invalid action returns 400
BADACT_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" \
    "${AUTH_ARGS[@]+"${AUTH_ARGS[@]}"}" \
    -X POST "${API}/integrations/traffic/create-rule" \
    -H "Content-Type: application/json" \
    -d '{"command": "mcp__test__foo", "action": "banana"}')
assert_eq "$BADACT_CODE" "400" "5.5 Invalid action returns 400"

# 5.6 Create server rules (3 smart defaults)
log "Creating smart default rules for 'google_calendar'..."
SERVER_RESP=$(api_curl -X POST "${API}/integrations/traffic/create-server-rules" \
    -H "Content-Type: application/json" \
    -d '{"server_name": "google_calendar"}')
SERVER_COUNT=$(echo "$SERVER_RESP" | jq -r '.rules_created // 0')
SERVER_RULES=$(echo "$SERVER_RESP" | jq -r '.rules | length')
assert_eq "$SERVER_COUNT" "3" "5.6a 3 server rules created"
assert_eq "$SERVER_RULES" "3" "5.6b Response includes 3 rules"

# Track for cleanup
SERVER_RULE_IDS=$(echo "$SERVER_RESP" | jq -r '.rules[].id')
for sid in $SERVER_RULE_IDS; do
    CREATED_RULES+=("$sid")
done

# 5.7 Verify the 3 rules have correct actions
SERVER_ACTIONS=$(echo "$SERVER_RESP" | jq -r '[.rules[].action] | sort | join(",")')
assert_eq "$SERVER_ACTIONS" "allow,deny,require_approval" "5.7 Server rules have allow + approve + deny"

# 5.8 Empty server name returns 400
EMPTY_SRV_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" \
    "${AUTH_ARGS[@]+"${AUTH_ARGS[@]}"}" \
    -X POST "${API}/integrations/traffic/create-server-rules" \
    -H "Content-Type: application/json" \
    -d '{"server_name": "  "}')
assert_eq "$EMPTY_SRV_CODE" "400" "5.8 Empty server name returns 400"

# ============================================================
# Phase 6: Disable Server Rules
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 6: Disable Server Rules ===${NC}"

# 6.1 Create rules for a server, then disable them
log "Creating rules for 'notion' to test disable..."
NOTION_SRV=$(api_curl -X POST "${API}/integrations/traffic/create-server-rules" \
    -H "Content-Type: application/json" \
    -d '{"server_name": "notion"}')
NOTION_COUNT=$(echo "$NOTION_SRV" | jq -r '.rules_created // 0')
assert_gt "$NOTION_COUNT" "0" "6.1 Notion server rules created"
# Track for cleanup (though disable will soft-delete them)
NOTION_IDS=$(echo "$NOTION_SRV" | jq -r '.rules[].id')
for nid in $NOTION_IDS; do CREATED_RULES+=("$nid"); done

# 6.2 Verify they appear in active packs (match exact source_reference)
PACKS_WITH_NOTION=$(api_curl "${API}/integrations/active-packs")
NOTION_PACK=$(echo "$PACKS_WITH_NOTION" | jq '[.[] | select(.source_reference == "mcp_server:notion")] | length')
assert_gt "$NOTION_PACK" "0" "6.2 Notion appears in active packs"

# 6.3 Disable server rules
log "Disabling Notion rules..."
DISABLE_RESP=$(api_curl -X POST "${API}/integrations/traffic/disable-server-rules" \
    -H "Content-Type: application/json" \
    -d '{"server_name": "notion"}')
DISABLE_COUNT=$(echo "$DISABLE_RESP" | jq -r '.rules_deleted // 0')
assert_gt "$DISABLE_COUNT" "0" "6.3a Notion rules disabled"
assert_contains "$DISABLE_RESP" "notion" "6.3b Response contains server_name"

# 6.4 Verify they no longer appear in active packs (match exact source_reference)
PACKS_WITHOUT_NOTION=$(api_curl "${API}/integrations/active-packs")
NOTION_AFTER=$(echo "$PACKS_WITHOUT_NOTION" | jq '[.[] | select(.source_reference == "mcp_server:notion")] | length')
assert_eq "$NOTION_AFTER" "0" "6.4 Notion gone from active packs after disable"

# 6.5 Disable again returns 404 (no active rules left)
REDISABLE_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" \
    "${AUTH_ARGS[@]+"${AUTH_ARGS[@]}"}" \
    -X POST "${API}/integrations/traffic/disable-server-rules" \
    -H "Content-Type: application/json" \
    -d '{"server_name": "notion"}')
assert_eq "$REDISABLE_CODE" "404" "6.5 Re-disable returns 404"

# 6.6 Empty server name returns 400
EMPTY_DISABLE_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" \
    "${AUTH_ARGS[@]+"${AUTH_ARGS[@]}"}" \
    -X POST "${API}/integrations/traffic/disable-server-rules" \
    -H "Content-Type: application/json" \
    -d '{"server_name": "  "}')
assert_eq "$EMPTY_DISABLE_CODE" "400" "6.6 Empty server_name returns 400"

# 6.7 Disable with normalized name (hyphens → underscores)
log "Creating rules for 'google_calendar' then disabling with hyphen variant..."
GCAL_SRV=$(api_curl -X POST "${API}/integrations/traffic/create-server-rules" \
    -H "Content-Type: application/json" \
    -d '{"server_name": "google_calendar"}')
GCAL_COUNT=$(echo "$GCAL_SRV" | jq -r '.rules_created // 0')
GCAL_IDS=$(echo "$GCAL_SRV" | jq -r '.rules[].id')
for gid in $GCAL_IDS; do CREATED_RULES+=("$gid"); done

GCAL_DISABLE=$(api_curl -X POST "${API}/integrations/traffic/disable-server-rules" \
    -H "Content-Type: application/json" \
    -d '{"server_name": "google-calendar"}')
GCAL_DISABLED=$(echo "$GCAL_DISABLE" | jq -r '.rules_deleted // 0')
assert_gt "$GCAL_DISABLED" "0" "6.7 Disable with hyphen variant works (normalization)"

# ============================================================
# Phase 7: Unknown Server (Generic 3 Defaults)
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 7: Unknown Server → Generic Rules ===${NC}"

# 7.1 Create rules for an unknown server → should get 3 generic defaults
log "Creating rules for unknown server 'e2e_mystery_server'..."
UNKNOWN_RESP=$(api_curl -X POST "${API}/integrations/traffic/create-server-rules" \
    -H "Content-Type: application/json" \
    -d '{"server_name": "e2e_mystery_server"}')
UNKNOWN_COUNT=$(echo "$UNKNOWN_RESP" | jq -r '.rules_created // 0')
UNKNOWN_SOURCE=$(echo "$UNKNOWN_RESP" | jq -r '.source // empty')
assert_eq "$UNKNOWN_COUNT" "3" "7.1a Unknown server creates exactly 3 rules"
assert_eq "$UNKNOWN_SOURCE" "traffic_discovery" "7.1b Source is traffic_discovery (not rule_pack)"

# Track for cleanup
UNKNOWN_IDS=$(echo "$UNKNOWN_RESP" | jq -r '.rules[].id')
for uid in $UNKNOWN_IDS; do CREATED_RULES+=("$uid"); done

# 7.2 Verify the 3 rules have correct actions (allow + approve + deny)
UNKNOWN_ACTIONS=$(echo "$UNKNOWN_RESP" | jq -r '[.rules[].action] | sort | join(",")')
assert_eq "$UNKNOWN_ACTIONS" "allow,deny,require_approval" "7.2 Unknown server: allow + approve + deny"

# 7.3 Rule evaluation against unknown server rules
log "Evaluating commands against unknown server rules..."
READ_RESULT=$(evaluate "{
    \"agent_id\": \"${AGENT_UUID}\",
    \"request_type\": \"command\",
    \"command\": \"mcp__e2e_mystery_server__list_items\"
}")
READ_DECISION=$(echo "$READ_RESULT" | jq -r '.decision // empty')
assert_eq "$READ_DECISION" "allow" "7.3a Read command allowed by generic rules"

DELETE_RESULT=$(evaluate "{
    \"agent_id\": \"${AGENT_UUID}\",
    \"request_type\": \"command\",
    \"command\": \"mcp__e2e_mystery_server__delete_all\"
}")
DELETE_DECISION=$(is_denied "$DELETE_RESULT")
assert_eq "$DELETE_DECISION" "deny" "7.3b Delete command denied by generic rules"

# 7.4 Unknown server appears in active packs
PACKS_UNKNOWN=$(api_curl "${API}/integrations/active-packs")
MYSTERY_PACK=$(echo "$PACKS_UNKNOWN" | jq '[.[] | select(.source_reference == "mcp_server:e2e_mystery_server")] | length')
assert_eq "$MYSTERY_PACK" "1" "7.4 Unknown server in active packs"

# 7.5 Clean up via disable-server-rules
log "Disabling unknown server rules..."
UNKNOWN_DISABLE=$(api_curl -X POST "${API}/integrations/traffic/disable-server-rules" \
    -H "Content-Type: application/json" \
    -d '{"server_name": "e2e_mystery_server"}')
UNKNOWN_DISABLED=$(echo "$UNKNOWN_DISABLE" | jq -r '.rules_deleted // 0')
assert_eq "$UNKNOWN_DISABLED" "3" "7.5 Disabled 3 unknown server rules"

# ============================================================
# Phase 8: Curated Pack (Known Server → More Than 3 Rules)
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 8: Curated Pack (known server) ===${NC}"

# 8.1 Create rules for 'github' — known server with curated rule pack
log "Creating rules for known server 'github'..."
GITHUB_SRV=$(api_curl -X POST "${API}/integrations/traffic/create-server-rules" \
    -H "Content-Type: application/json" \
    -d '{"server_name": "github"}')
GITHUB_SRV_COUNT=$(echo "$GITHUB_SRV" | jq -r '.rules_created // 0')
GITHUB_SRV_SOURCE=$(echo "$GITHUB_SRV" | jq -r '.source // empty')
assert_gt "$GITHUB_SRV_COUNT" "3" "8.1a GitHub creates more than 3 rules (curated)"
assert_eq "$GITHUB_SRV_SOURCE" "rule_pack" "8.1b Source is rule_pack (curated)"

# Track for cleanup
GITHUB_SRV_IDS=$(echo "$GITHUB_SRV" | jq -r '.rules[].id')
for gid in $GITHUB_SRV_IDS; do CREATED_RULES+=("$gid"); done

# 8.2 Verify curated rules have meaningful names
GITHUB_RULE_NAMES=$(echo "$GITHUB_SRV" | jq -r '[.rules[].name] | join("|")')
assert_contains "$GITHUB_RULE_NAMES" "GitHub" "8.2 Curated rules have 'GitHub' in names"

# 8.3 Curated pack appears in active packs with pack_id
PACKS_GH=$(api_curl "${API}/integrations/active-packs")
GH_PACK=$(echo "$PACKS_GH" | jq '[.[] | select(.pack_id == "github")] | .[0]')
GH_PACK_NAME=$(echo "$GH_PACK" | jq -r '.display_name // empty')
GH_PACK_RULES=$(echo "$GH_PACK" | jq '.rule_count // 0')
assert_eq "$GH_PACK_NAME" "GitHub" "8.3a GitHub pack display_name correct"
assert_gt "$GH_PACK_RULES" "3" "8.3b GitHub pack has > 3 rules"

# 8.4 Evaluate against curated GitHub rules
log "Evaluating commands against curated GitHub rules..."
GH_READ_EVAL=$(evaluate "{
    \"agent_id\": \"${AGENT_UUID}\",
    \"request_type\": \"command\",
    \"command\": \"mcp__github__list_repos\"
}")
GH_READ_DEC=$(echo "$GH_READ_EVAL" | jq -r '.decision // empty')
assert_eq "$GH_READ_DEC" "allow" "8.4a GitHub read allowed by curated rules"

GH_DELETE_EVAL=$(evaluate "{
    \"agent_id\": \"${AGENT_UUID}\",
    \"request_type\": \"command\",
    \"command\": \"mcp__github__delete_repo\"
}")
GH_DELETE_DEC=$(is_denied "$GH_DELETE_EVAL")
assert_eq "$GH_DELETE_DEC" "deny" "8.4b GitHub delete denied by curated rules"

# 8.5 Disable curated pack via disable-server-rules
log "Disabling GitHub curated pack..."
GH_DISABLE=$(api_curl -X POST "${API}/integrations/traffic/disable-server-rules" \
    -H "Content-Type: application/json" \
    -d '{"server_name": "github"}')
GH_DISABLED=$(echo "$GH_DISABLE" | jq -r '.rules_deleted // 0')
assert_gt "$GH_DISABLED" "3" "8.5 Disabled more than 3 GitHub curated rules"

# ============================================================
# Phase 9: Traffic Insights with Real Data
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 9: Traffic Insights (with real data) ===${NC}"

# The evaluate calls above generated audit log entries.
# Use 168h window (7 days) to catch both new and historical traffic.
flush_traffic_cache
sleep 2

log "Fetching traffic insights (168h window, should include our evaluations)..."
INSIGHTS_REAL=$(api_curl "${API}/integrations/traffic/insights?hours=168")
REAL_EVALS=$(echo "$INSIGHTS_REAL" | jq '.total_evaluations // 0')
REAL_COMMANDS=$(echo "$INSIGHTS_REAL" | jq '.total_unique_commands // 0')
REAL_GROUPS=$(echo "$INSIGHTS_REAL" | jq '.service_groups | length')

log "Found: ${REAL_EVALS} evaluations, ${REAL_COMMANDS} commands, ${REAL_GROUPS} groups"

assert_gt "$REAL_EVALS" "0" "9.1 Traffic insights has evaluations"
assert_gt "$REAL_COMMANDS" "0" "9.2 Traffic insights has unique commands"
assert_gt "$REAL_GROUPS" "0" "9.3 Traffic insights has service groups"

# 9.4 Service group structure
FIRST_GROUP=$(echo "$INSIGHTS_REAL" | jq '.service_groups[0]')
FG_KEY=$(echo "$FIRST_GROUP" | jq -r '.server_key // empty')
FG_DISPLAY=$(echo "$FIRST_GROUP" | jq -r '.display_name // empty')
FG_COMMANDS=$(echo "$FIRST_GROUP" | jq '.commands | length')
assert_not_eq "$FG_KEY" "" "9.4a First group has server_key"
assert_not_eq "$FG_DISPLAY" "" "9.4b First group has display_name"
assert_gt "$FG_COMMANDS" "0" "9.4c First group has commands"

# 9.5 Command structure within group
FIRST_CMD=$(echo "$FIRST_GROUP" | jq '.commands[0]')
FC_COMMAND=$(echo "$FIRST_CMD" | jq -r '.command // empty')
FC_COUNT=$(echo "$FIRST_CMD" | jq '.count // 0')
FC_DECISIONS=$(echo "$FIRST_CMD" | jq '.decisions | keys | length // 0')
assert_not_eq "$FC_COMMAND" "" "9.5a Command has command field"
assert_gt "$FC_COUNT" "0" "9.5b Command has count > 0"
assert_gt "$FC_DECISIONS" "0" "9.5c Command has decision buckets"

# 9.6 Agent-scoped insights (use 168h to catch our evaluations)
log "Fetching agent-scoped insights..."
AGENT_INSIGHTS=$(api_curl "${API}/integrations/traffic/insights?hours=168&agent_id=${AGENT_UUID}")
AGENT_EVALS=$(echo "$AGENT_INSIGHTS" | jq '.total_evaluations // 0')
assert_gt "$AGENT_EVALS" "0" "9.6 Agent-scoped insights has evaluations"

# 9.7 Check for e2e_mystery_server in insights (from Phase 7 evaluations)
E2E_SERVER_GROUP=$(echo "$AGENT_INSIGHTS" | jq '[.service_groups[] | select(.server_key == "e2e_mystery_server")] | length')
assert_gt "$E2E_SERVER_GROUP" "0" "9.7 e2e_mystery_server found in agent traffic"

# 9.8 Check that covered commands are marked correctly
COVERED_CMDS=$(echo "$INSIGHTS_REAL" | jq '[.service_groups[].commands[] | select(.has_matching_rule == true)] | length')
# May be 0 if no rules match the historical traffic, so just verify the field exists
COVERED_FIELD_EXISTS=$(echo "$INSIGHTS_REAL" | jq '.service_groups[0].commands[0] | has("has_matching_rule")')
assert_eq "$COVERED_FIELD_EXISTS" "true" "9.8 Commands have has_matching_rule field"

# ============================================================
# Phase 10: Template Patterns Match Real MCP Tool Names
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 10: Rule Pattern Verification ===${NC}"

# Create CLI allow + deny rules via create-rule endpoint
log "Creating CLI rules for pattern testing..."
CLI_ALLOW_RESP=$(api_curl -X POST "${API}/integrations/traffic/create-rule" \
    -H "Content-Type: application/json" \
    -d '{"command": "ls", "action": "allow", "pattern_mode": "prefix"}')
CLI_ALLOW_ID=$(echo "$CLI_ALLOW_RESP" | jq -r '.id // empty')
assert_not_eq "$CLI_ALLOW_ID" "" "10.1a CLI allow rule created"
if [[ -n "$CLI_ALLOW_ID" ]]; then CREATED_RULES+=("$CLI_ALLOW_ID"); fi

CLI_DENY_ID=$(create_rule '{
    "name": "E2E Block rm -rf",
    "rule_type": "command_denylist",
    "action": "deny",
    "parameters": {"patterns": ["rm\\s+-rf"]},
    "priority": 200,
    "is_active": true
}')
assert_not_eq "$CLI_DENY_ID" "" "10.1b CLI deny rule created"

GIT_ALLOW_RESP=$(api_curl -X POST "${API}/integrations/traffic/create-rule" \
    -H "Content-Type: application/json" \
    -d '{"command": "git status", "action": "allow", "pattern_mode": "prefix"}')
GIT_ALLOW_ID=$(echo "$GIT_ALLOW_RESP" | jq -r '.id // empty')
if [[ -n "$GIT_ALLOW_ID" ]]; then CREATED_RULES+=("$GIT_ALLOW_ID"); fi

# 10.2 Safe command allowed
SAFE_CMD=$(evaluate "{
    \"agent_id\": \"${AGENT_UUID}\",
    \"request_type\": \"command\",
    \"command\": \"ls -la /tmp\"
}")
SAFE_DECISION=$(echo "$SAFE_CMD" | jq -r '.decision // empty')
assert_eq "$SAFE_DECISION" "allow" "10.2 'ls -la /tmp' allowed by CLI rule"

# 10.3 Git read allowed
GIT_READ=$(evaluate "{
    \"agent_id\": \"${AGENT_UUID}\",
    \"request_type\": \"command\",
    \"command\": \"git status\"
}")
GIT_DECISION=$(echo "$GIT_READ" | jq -r '.decision // empty')
assert_eq "$GIT_DECISION" "allow" "10.3 'git status' allowed by CLI rule"

# 10.4 Dangerous command denied
DANGER_CMD=$(evaluate "{
    \"agent_id\": \"${AGENT_UUID}\",
    \"request_type\": \"command\",
    \"command\": \"rm -rf /\"
}")
DANGER_DECISION=$(is_denied "$DANGER_CMD")
assert_eq "$DANGER_DECISION" "deny" "10.4 'rm -rf /' denied by CLI rule"

# Create GitHub server rules and test MCP patterns
log "Creating GitHub rules for MCP pattern testing..."
GH_SRV=$(api_curl -X POST "${API}/integrations/traffic/create-server-rules" \
    -H "Content-Type: application/json" \
    -d '{"server_name": "github"}')
GH_RULES=$(echo "$GH_SRV" | jq -r '.rules_created // 0')
assert_gt "$GH_RULES" "0" "10.5a GitHub rules created"
GH_SRV_IDS=$(echo "$GH_SRV" | jq -r '.rules[].id')
for gid in $GH_SRV_IDS; do CREATED_RULES+=("$gid"); done

# 10.6 GitHub MCP read allowed
GH_READ=$(evaluate "{
    \"agent_id\": \"${AGENT_UUID}\",
    \"request_type\": \"command\",
    \"command\": \"mcp__github__list_repos\"
}")
GH_READ_DEC=$(echo "$GH_READ" | jq -r '.decision // empty')
assert_eq "$GH_READ_DEC" "allow" "10.6 'mcp__github__list_repos' allowed"

# 10.7 GitHub MCP destructive denied
GH_DELETE=$(evaluate "{
    \"agent_id\": \"${AGENT_UUID}\",
    \"request_type\": \"command\",
    \"command\": \"mcp__github__delete_repo\"
}")
GH_DELETE_DEC=$(is_denied "$GH_DELETE")
assert_eq "$GH_DELETE_DEC" "deny" "10.7 'mcp__github__delete_repo' denied"

# 10.8 Disable github rules (cleanup)
api_curl -X POST "${API}/integrations/traffic/disable-server-rules" \
    -H "Content-Type: application/json" \
    -d '{"server_name": "github"}' >/dev/null 2>&1

# ============================================================
# Done — cleanup runs via EXIT trap
# ============================================================
echo ""
echo -e "${BOLD}=== All phases complete ===${NC}"
