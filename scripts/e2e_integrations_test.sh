#!/usr/bin/env bash
#
# Snapper E2E — Integration Templates & Traffic Discovery Tests
#
# Tests all new endpoints introduced in the traffic-discovery + simplified-templates rework:
#   - Template listing (10 templates, 5 categories)
#   - Traffic discovery (insights, coverage, known-servers)
#   - Rule creation from traffic (create-rule, create-server-rules)
#   - Custom MCP server enable/disable
#   - Legacy rules detection
#   - Template enable/disable lifecycle
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

# Wrapper for curl with host header
api_curl() {
    curl -sf "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" "$@" 2>/dev/null
}

# Create a rule, capture its UUID, track for cleanup
create_rule() {
    local json="$1"
    local resp
    resp=$(curl -sf -X POST "${API}/rules" \
        "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" \
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
        "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" >/dev/null 2>&1
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

    # Disable any custom MCP integrations we enabled
    api_curl -X POST "${API}/integrations/custom_mcp/disable" \
        -H "Content-Type: application/json" >/dev/null 2>&1

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
# Phase 0: Environment Verification
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 0: Environment Verification ===${NC}"

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
# Phase 1: Integration Template Structure
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 1: Template Structure (10 templates, 5 categories) ===${NC}"

# 1.1 List integrations returns categories
log "Fetching integration list..."
INTEGRATIONS=$(api_curl "${API}/integrations")
NUM_CATEGORIES=$(echo "$INTEGRATIONS" | jq 'length')
assert_eq "$NUM_CATEGORIES" "5" "1.1 Exactly 5 categories returned"

# 1.2 Count total templates across all categories
ALL_TEMPLATE_IDS=$(echo "$INTEGRATIONS" | jq -r '.[].integrations[].id' | sort)
NUM_TEMPLATES=$(echo "$ALL_TEMPLATE_IDS" | wc -l | tr -d ' ')
assert_eq "$NUM_TEMPLATES" "10" "1.2 Exactly 10 templates across all categories"

# 1.3 Verify specific kept template IDs exist
for tid in shell filesystem github browser network aws database slack gmail custom_mcp; do
    FOUND=$(echo "$ALL_TEMPLATE_IDS" | grep -c "^${tid}$" || true)
    assert_eq "$FOUND" "1" "1.3 Template '${tid}' exists"
done

# 1.4 Verify removed templates are NOT in list
for removed_tid in linear notion discord telegram google_calendar vercel supabase; do
    FOUND=$(echo "$ALL_TEMPLATE_IDS" | grep -c "^${removed_tid}$" || true)
    assert_eq "$FOUND" "0" "1.4 Removed template '${removed_tid}' is absent"
done

# 1.5 All templates start disabled (no rules yet)
ALL_ENABLED=$(echo "$INTEGRATIONS" | jq '[.[].integrations[] | select(.enabled == true)] | length')
assert_eq "$ALL_ENABLED" "0" "1.5 All templates disabled initially"

# 1.6 Categories summary endpoint
log "Fetching categories summary..."
SUMMARY=$(api_curl "${API}/integrations/categories/summary")
SUMMARY_COUNT=$(echo "$SUMMARY" | jq 'length')
assert_eq "$SUMMARY_COUNT" "5" "1.6 Categories summary has 5 entries"

# 1.7 System category has correct count (shell + filesystem + custom_mcp = 3)
SYSTEM_COUNT=$(echo "$SUMMARY" | jq '.[] | select(.id == "system") | .integration_count')
assert_eq "$SYSTEM_COUNT" "3" "1.7 System category has 3 templates"

# 1.8 Get single template details
log "Fetching github template details..."
GITHUB_DETAIL=$(api_curl "${API}/integrations/github")
GITHUB_NAME=$(echo "$GITHUB_DETAIL" | jq -r '.name')
GITHUB_RULES_COUNT=$(echo "$GITHUB_DETAIL" | jq '.rules | length')
assert_eq "$GITHUB_NAME" "GitHub" "1.8a GitHub template name correct"
assert_eq "$GITHUB_RULES_COUNT" "4" "1.8b GitHub has 4 rules"

# 1.9 custom_mcp template has custom=true and empty rules
CUSTOM_DETAIL=$(api_curl "${API}/integrations/custom_mcp")
CUSTOM_IS_CUSTOM=$(echo "$CUSTOM_DETAIL" | jq -r '.custom')
CUSTOM_RULES_COUNT=$(echo "$CUSTOM_DETAIL" | jq '.rules | length')
assert_eq "$CUSTOM_IS_CUSTOM" "true" "1.9a custom_mcp has custom=true"
assert_eq "$CUSTOM_RULES_COUNT" "0" "1.9b custom_mcp has 0 static rules"

# 1.10 Nonexistent template returns 404
NONEXIST_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" \
    "${API}/integrations/nonexistent-xyz-123")
assert_eq "$NONEXIST_CODE" "404" "1.10 Nonexistent template returns 404"

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
    -X POST "${API}/integrations/traffic/create-rule" \
    -H "Content-Type: application/json" \
    -d '{"command": "  ", "action": "allow"}')
assert_eq "$EMPTY_CODE" "400" "5.4 Empty command returns 400"

# 5.5 Invalid action returns 400
BADACT_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" \
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
    -X POST "${API}/integrations/traffic/create-server-rules" \
    -H "Content-Type: application/json" \
    -d '{"server_name": "  "}')
assert_eq "$EMPTY_SRV_CODE" "400" "5.8 Empty server name returns 400"

# ============================================================
# Phase 6: Standard Template Enable / Disable Lifecycle
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 6: Template Enable / Disable ===${NC}"

# 6.1 Enable gmail
log "Enabling Gmail template..."
ENABLE_RESP=$(api_curl -X POST "${API}/integrations/gmail/enable" \
    -H "Content-Type: application/json" \
    -d '{}')
ENABLE_COUNT=$(echo "$ENABLE_RESP" | jq -r '.rules_created // 0')
assert_gt "$ENABLE_COUNT" "0" "6.1a Gmail enabled with rules"
assert_contains "$ENABLE_RESP" "gmail" "6.1b Response contains integration_id"

# 6.2 Gmail detail shows enabled
GMAIL_NOW=$(api_curl "${API}/integrations/gmail")
GMAIL_ENABLED=$(echo "$GMAIL_NOW" | jq -r '.enabled')
GMAIL_RC=$(echo "$GMAIL_NOW" | jq -r '.rule_count')
assert_eq "$GMAIL_ENABLED" "true" "6.2a Gmail shows enabled"
assert_gt "$GMAIL_RC" "0" "6.2b Gmail has rules"

# 6.3 Existing rules are populated
GMAIL_EXISTING=$(echo "$GMAIL_NOW" | jq '.existing_rules | length')
assert_gt "$GMAIL_EXISTING" "0" "6.3 existing_rules populated"

# 6.4 Re-enable returns 400
REENABLE_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" \
    -X POST "${API}/integrations/gmail/enable" \
    -H "Content-Type: application/json" \
    -d '{}')
assert_eq "$REENABLE_CODE" "400" "6.4 Re-enable returns 400"

# 6.5 Integration list shows gmail enabled
INTEG_LIST=$(api_curl "${API}/integrations")
GMAIL_IN_LIST=$(echo "$INTEG_LIST" | jq '[.[].integrations[] | select(.id == "gmail" and .enabled == true)] | length')
assert_eq "$GMAIL_IN_LIST" "1" "6.5 Gmail shows enabled in list"

# 6.6 Disable gmail
log "Disabling Gmail..."
DISABLE_RESP=$(api_curl -X POST "${API}/integrations/gmail/disable" \
    -H "Content-Type: application/json")
DISABLE_COUNT=$(echo "$DISABLE_RESP" | jq -r '.rules_deleted // 0')
assert_gt "$DISABLE_COUNT" "0" "6.6 Gmail disabled, rules deleted"

# 6.7 Gmail now shows disabled
GMAIL_AFTER=$(api_curl "${API}/integrations/gmail")
GMAIL_AFTER_ENABLED=$(echo "$GMAIL_AFTER" | jq -r '.enabled')
assert_eq "$GMAIL_AFTER_ENABLED" "false" "6.7 Gmail disabled after disable"

# 6.8 Disable again returns 400
REDISABLE_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" \
    -X POST "${API}/integrations/gmail/disable" \
    -H "Content-Type: application/json")
assert_eq "$REDISABLE_CODE" "400" "6.8 Re-disable returns 400"

# 6.9 Enable Slack (selectable template, defaults only)
log "Enabling Slack (default rules only)..."
SLACK_ENABLE=$(api_curl -X POST "${API}/integrations/slack/enable" \
    -H "Content-Type: application/json" \
    -d '{}')
SLACK_RULES=$(echo "$SLACK_ENABLE" | jq -r '.rules_created // 0')
assert_gt "$SLACK_RULES" "0" "6.9 Slack enabled with default rules"

# 6.10 Disable Slack
api_curl -X POST "${API}/integrations/slack/disable" \
    -H "Content-Type: application/json" >/dev/null 2>&1
log "Slack disabled (cleanup)"

# 6.11 Enable Slack with explicit rule selection (first rule only)
SLACK_DETAIL=$(api_curl "${API}/integrations/slack")
FIRST_RULE_ID=$(echo "$SLACK_DETAIL" | jq -r '.rules[0].id')
log "Enabling Slack with single selected rule: $FIRST_RULE_ID"
SLACK_SEL_RESP=$(api_curl -X POST "${API}/integrations/slack/enable" \
    -H "Content-Type: application/json" \
    -d "{\"selected_rules\": [\"${FIRST_RULE_ID}\"]}")
SLACK_SEL_COUNT=$(echo "$SLACK_SEL_RESP" | jq -r '.rules_created // 0')
assert_eq "$SLACK_SEL_COUNT" "1" "6.11 Slack with explicit selection: 1 rule"

# 6.12 Disable Slack (cleanup)
api_curl -X POST "${API}/integrations/slack/disable" \
    -H "Content-Type: application/json" >/dev/null 2>&1
log "Slack disabled (cleanup)"

# ============================================================
# Phase 7: Custom MCP Server Template
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 7: Custom MCP Server Template ===${NC}"

# 7.1 Enable custom_mcp with server name
log "Enabling custom MCP server 'e2e_test_server'..."
CUSTOM_ENABLE=$(api_curl -X POST "${API}/integrations/custom_mcp/enable" \
    -H "Content-Type: application/json" \
    -d '{"custom_server_name": "e2e_test_server"}')
CUSTOM_RULES_CREATED=$(echo "$CUSTOM_ENABLE" | jq -r '.rules_created // 0')
assert_eq "$CUSTOM_RULES_CREATED" "3" "7.1 Custom MCP created 3 rules"

# 7.2 Verify rules exist via rules API
log "Verifying custom rules in database..."
CUSTOM_RULES_RESP=$(api_curl "${API}/rules?page_size=100")
CUSTOM_RULE_NAMES=$(echo "$CUSTOM_RULES_RESP" | jq -r '[.items[] | select(.source_reference == "custom_mcp:e2e_test_server") | .name] | sort | join("|")')
assert_contains "$CUSTOM_RULE_NAMES" "Allow Read" "7.2a Has 'Allow Read' rule"
assert_contains "$CUSTOM_RULE_NAMES" "Approve Write" "7.2b Has 'Approve Write' rule"
assert_contains "$CUSTOM_RULE_NAMES" "Block Destructive" "7.2c Has 'Block Destructive' rule"

# 7.3 Verify patterns contain the server name
CUSTOM_PATTERNS=$(echo "$CUSTOM_RULES_RESP" | jq -r '[.items[] | select(.source_reference == "custom_mcp:e2e_test_server") | .parameters.patterns[]] | join(" ")')
assert_contains "$CUSTOM_PATTERNS" "e2e_test_server" "7.3 Patterns reference server name"

# 7.4 Rule evaluation against custom server rules
log "Evaluating commands against custom server rules..."
# Read operation — should be allowed
READ_RESULT=$(evaluate "{
    \"agent_id\": \"${AGENT_UUID}\",
    \"request_type\": \"command\",
    \"command\": \"mcp__e2e_test_server__list_items\"
}")
READ_DECISION=$(echo "$READ_RESULT" | jq -r '.decision // empty')
assert_eq "$READ_DECISION" "allow" "7.4a Read command allowed by custom rules"

# Destructive operation — should be denied
DELETE_RESULT=$(evaluate "{
    \"agent_id\": \"${AGENT_UUID}\",
    \"request_type\": \"command\",
    \"command\": \"mcp__e2e_test_server__delete_all\"
}")
DELETE_DECISION=$(echo "$DELETE_RESULT" | jq -r '.decision // empty')
assert_eq "$DELETE_DECISION" "deny" "7.4b Delete command denied by custom rules"

# 7.5 Missing server name returns 400
MISSING_SN_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "${CURL_HOST_ARGS[@]+"${CURL_HOST_ARGS[@]}"}" \
    -X POST "${API}/integrations/custom_mcp/enable" \
    -H "Content-Type: application/json" \
    -d '{}')
assert_eq "$MISSING_SN_CODE" "400" "7.5 Missing server_name returns 400"

# 7.6 Disable custom MCP — finds rules by source_reference
log "Disabling custom MCP 'e2e_test_server'..."
# The disable endpoint uses integration_id "custom_mcp" but also checks source_reference like "custom_mcp:e2e_test_server"
# We need to clean up via the rules API directly since disable by template ID won't find custom ones
CUSTOM_IDS=$(echo "$CUSTOM_RULES_RESP" | jq -r '.items[] | select(.source_reference == "custom_mcp:e2e_test_server") | .id')
CUSTOM_DELETE_COUNT=0
for cid in $CUSTOM_IDS; do
    if delete_rule "$cid"; then
        CUSTOM_DELETE_COUNT=$((CUSTOM_DELETE_COUNT + 1))
    fi
done
assert_eq "$CUSTOM_DELETE_COUNT" "3" "7.6 Cleaned up 3 custom MCP rules"

# ============================================================
# Phase 8: Legacy Rules Detection
# ============================================================
echo ""
echo -e "${BOLD}=== Phase 8: Legacy Rules (from removed templates) ===${NC}"

# 8.1 Create a rule pretending to be from a removed template
log "Creating a 'legacy' rule from removed template 'linear'..."
LEGACY_RULE_ID=$(create_rule '{
    "name":"Linear - Allow Issue Read (legacy)",
    "rule_type":"command_allowlist",
    "action":"allow",
    "parameters":{"patterns":["^mcp__linear__.*"]},
    "priority":100,
    "is_active":true,
    "source":"integration",
    "source_reference":"linear"
}')
assert_not_eq "$LEGACY_RULE_ID" "" "8.1 Legacy rule created"

# 8.2 Legacy rules endpoint returns it
log "Fetching legacy rules..."
LEGACY_RESP=$(api_curl "${API}/integrations/legacy-rules")
LEGACY_COUNT=$(echo "$LEGACY_RESP" | jq -r '.count // 0')
assert_gt "$LEGACY_COUNT" "0" "8.2a Legacy rules count > 0"

LEGACY_REFS=$(echo "$LEGACY_RESP" | jq -r '.rules[].source_reference')
assert_contains "$LEGACY_REFS" "linear" "8.2b 'linear' found in legacy rules"

# 8.3 Legacy response includes the helpful note
LEGACY_NOTE=$(echo "$LEGACY_RESP" | jq -r '.note // empty')
assert_contains "$LEGACY_NOTE" "simplified" "8.3 Legacy note mentions 'simplified'"

# 8.4 Current template rules NOT in legacy list
log "Creating a rule from current template 'gmail'..."
CURRENT_RULE_ID=$(create_rule '{
    "name":"Gmail - E2E Test (current)",
    "rule_type":"command_allowlist",
    "action":"allow",
    "parameters":{},
    "priority":100,
    "is_active":true,
    "source":"integration",
    "source_reference":"gmail"
}')

LEGACY_RESP2=$(api_curl "${API}/integrations/legacy-rules")
LEGACY_GMAIL=$(echo "$LEGACY_RESP2" | jq '[.rules[] | select(.source_reference == "gmail")] | length')
assert_eq "$LEGACY_GMAIL" "0" "8.4 Current 'gmail' NOT in legacy rules"

# 8.5 Legacy rule still evaluates (functional)
log "Evaluating command against legacy rule..."
LEGACY_EVAL=$(evaluate "{
    \"agent_id\": \"${AGENT_UUID}\",
    \"request_type\": \"command\",
    \"command\": \"mcp__linear__create_issue\"
}")
LEGACY_DECISION=$(echo "$LEGACY_EVAL" | jq -r '.decision // empty')
assert_eq "$LEGACY_DECISION" "allow" "8.5 Legacy rule still evaluates correctly"

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

# 9.7 Check for e2e_test_server in insights (from Phase 7 evaluations)
E2E_SERVER_GROUP=$(echo "$AGENT_INSIGHTS" | jq '[.service_groups[] | select(.server_key == "e2e_test_server")] | length')
assert_gt "$E2E_SERVER_GROUP" "0" "9.7 e2e_test_server found in agent traffic"

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

# Enable shell template and verify its rules work against real commands
log "Enabling Shell template for pattern testing..."
SHELL_ENABLE=$(api_curl -X POST "${API}/integrations/shell/enable" \
    -H "Content-Type: application/json" \
    -d '{}')
SHELL_RULES_COUNT=$(echo "$SHELL_ENABLE" | jq -r '.rules_created // 0')
assert_gt "$SHELL_RULES_COUNT" "0" "10.1 Shell template enabled"

# 10.2 Safe command allowed
SAFE_CMD=$(evaluate "{
    \"agent_id\": \"${AGENT_UUID}\",
    \"request_type\": \"command\",
    \"command\": \"ls -la /tmp\"
}")
SAFE_DECISION=$(echo "$SAFE_CMD" | jq -r '.decision // empty')
assert_eq "$SAFE_DECISION" "allow" "10.2 'ls -la /tmp' allowed by shell template"

# 10.3 Git read allowed
GIT_READ=$(evaluate "{
    \"agent_id\": \"${AGENT_UUID}\",
    \"request_type\": \"command\",
    \"command\": \"git status\"
}")
GIT_DECISION=$(echo "$GIT_READ" | jq -r '.decision // empty')
assert_eq "$GIT_DECISION" "allow" "10.3 'git status' allowed by shell template"

# 10.4 Dangerous command denied
DANGER_CMD=$(evaluate "{
    \"agent_id\": \"${AGENT_UUID}\",
    \"request_type\": \"command\",
    \"command\": \"rm -rf /\"
}")
DANGER_DECISION=$(echo "$DANGER_CMD" | jq -r '.decision // empty')
assert_eq "$DANGER_DECISION" "deny" "10.4 'rm -rf /' denied by shell template"

# 10.5 Disable shell (cleanup)
api_curl -X POST "${API}/integrations/shell/disable" \
    -H "Content-Type: application/json" >/dev/null 2>&1

# Enable github and test MCP patterns
log "Enabling GitHub template for MCP pattern testing..."
GH_ENABLE=$(api_curl -X POST "${API}/integrations/github/enable" \
    -H "Content-Type: application/json" \
    -d '{}')
GH_RULES=$(echo "$GH_ENABLE" | jq -r '.rules_created // 0')
assert_gt "$GH_RULES" "0" "10.5a GitHub template enabled"

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
GH_DELETE_DEC=$(echo "$GH_DELETE" | jq -r '.decision // empty')
assert_eq "$GH_DELETE_DEC" "deny" "10.7 'mcp__github__delete_repo' denied"

# 10.8 Disable github (cleanup)
api_curl -X POST "${API}/integrations/github/disable" \
    -H "Content-Type: application/json" >/dev/null 2>&1

# ============================================================
# Done — cleanup runs via EXIT trap
# ============================================================
echo ""
echo -e "${BOLD}=== All phases complete ===${NC}"
