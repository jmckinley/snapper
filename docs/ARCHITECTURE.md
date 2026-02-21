# Snapper Architecture: Inbound & Outbound Agent Traffic Flow

This document explains how Snapper works as an Agent Application Firewall (AAF) — intercepting, evaluating, and controlling traffic between AI agents and the outside world.

---

## Overview

Snapper operates in two primary flows:

1. **Inbound**: Agent wants to execute an action → Snapper intercepts and evaluates
2. **Outbound**: Snapper responds with allow/deny/require_approval → resolves encrypted data if approved

```
┌─────────────┐                              ┌─────────────┐
│  AI Agent    │ ──── tool call / command ──→ │   Snapper   │
│  (OpenClaw)  │                              │   Firewall  │
│              │ ←── allow + resolved data ── │             │
└─────────────┘                              └─────────────┘
```

---

## Inbound Flow: Agent Request → Evaluation

### 1. Request Entry Points

Snapper receives agent requests through three pathways:

#### A. OpenClaw Plugin Hook (Client-Side Interception)

**File**: `plugins/snapper-guard/index.ts`

The `snapper-guard` plugin registers a `before_tool_call` hook in OpenClaw. Before the agent executes a tool (browser, exec, bash, write), the plugin:

1. Scans `tool_input` for vault tokens (`{{SNAPPER_VAULT:...}}`) or `vault:Label` references
2. Sends `POST /api/v1/rules/evaluate` to Snapper
3. Based on the decision:
   - **allow** → lets the tool call proceed (with resolved tokens if available)
   - **deny** → blocks the tool call with a reason
   - **require_approval** → polls for human decision, then proceeds or blocks

**Fail-open**: If Snapper is unreachable, the plugin allows the call (fail-open for UX).

#### B. Shell Hook Wrappers (CLI Interception)

**Files**: `scripts/openclaw-hooks/bash-wrapper.sh`, `scripts/openclaw-hooks/snapper-check.sh`

Wraps the real bash binary to intercept shell commands:

```bash
# Agent tries: bash -c "curl https://example.com/api"
# Wrapper intercepts, calls Snapper evaluate, blocks if denied
RESP=$(curl -sf -X POST "${SNAPPER_URL}/api/v1/rules/evaluate" \
  -H "X-API-Key: $SNAPPER_API_KEY" \
  -d '{"agent_id":"openclaw-main","request_type":"command","command":"curl https://example.com/api"}')
```

Uses `$SNAPPER_URL` and `$SNAPPER_API_KEY` environment variables (never hardcoded).

#### C. REST API (Direct Evaluation)

**File**: `app/routers/rules.py` → `POST /api/v1/rules/evaluate`

Any system can call the evaluate endpoint directly with an API key (`snp_*` prefix) or agent external ID. Accepts command, file_access, network, tool, and skill request types.

#### D. Browser Extension (Web-Based AI Chat Interception)

**File**: `extension/background.js`

Chrome/Firefox extension (Manifest V3) that intercepts tool calls in web-based AI chats:

- **Content scripts** for 5 platforms: ChatGPT, Claude.ai, Gemini, Copilot, Grok
- **PII scanner** (`content/pii-scanner.js`) scans textarea content for 20+ patterns before submission
- **Decision caching** — ALLOW decisions cached for 5 minutes (per tool_name + params)
- **Fail mode** — configurable: `closed` (deny on Snapper unreachable) or `open`
- **Enterprise deployment** — settings lockable via Chrome managed storage policy

---

### 2. Evaluation Pipeline

**Entry**: `app/routers/rules.py::evaluate_request()` (~550 lines)

```
Request arrives
    │
    ├─ 1. Authenticate (API key or agent_id lookup)
    ├─ 2. Check agent status (suspended/quarantined → DENY)
    ├─ 3. Check one-time approvals (Redis short-circuit → ALLOW)
    ├─ 4. Build EvaluationContext
    ├─ 5. Call rule_engine.evaluate()
    ├─ 6. Check threat score override
    ├─ 7. Audit log + policy violation recording
    ├─ 8. If REQUIRE_APPROVAL → create approval request
    ├─ 9. Dispatch notifications (Telegram/Slack/webhook)
    └─ 10. Return response
```

### 3. Rule Engine

**File**: `app/services/rule_engine.py::RuleEngine.evaluate()`

#### Rule Loading (Cached)
- **Redis cache** with 10-second TTL — rule IDs stored per agent (`rules:{agent_id}`)
- Cache miss → loads global + agent-specific rules from PostgreSQL
- Filters: `is_active=True`, `is_deleted=False`
- Org-scoped: only rules from agent's organization or system-wide (`org_id=NULL`)
- Sorted by priority (descending)
- **Immediate invalidation** on rule create/update/delete — no stale rules
- Global rule changes (`agent_id=NULL`) flush all cached rule sets via SCAN+DELETE

#### Evaluation Loop

Rules are evaluated in priority order. The logic follows these semantics:

```
For each rule (highest priority first):
  if rule matches:
    DENY      → IMMEDIATE RETURN (short-circuit, nothing overrides)
    REQUIRE_APPROVAL → set pending (can be overridden by higher-priority ALLOW)
    ALLOW     → mark allowed, continue evaluating
```

**Key principle**: DENY always wins. Higher-priority ALLOW can override lower-priority REQUIRE_APPROVAL.

#### 15 Rule Type Evaluators

| Rule Type | What It Does |
|-----------|-------------|
| COMMAND_ALLOWLIST | Regex whitelist on command text |
| COMMAND_DENYLIST | Regex blacklist on command text |
| TIME_RESTRICTION | Hour/day-of-week restrictions |
| RATE_LIMIT | Token bucket with adaptive trust multiplier |
| SKILL_DENYLIST | Block specific ClawHub skills by name/pattern/publisher |
| CREDENTIAL_PROTECTION | Block access to .env, .pem, .key files |
| NETWORK_EGRESS | Host/port whitelisting for outbound connections |
| ORIGIN_VALIDATION | WebSocket origin header validation (CVE-2026-25253) |
| HUMAN_IN_LOOP | Require approval for matching patterns/categories |
| LOCALHOST_RESTRICTION | IP address checks |
| FILE_ACCESS | Path allowlist/denylist for file operations |
| VERSION_ENFORCEMENT | Agent version requirement checks |
| SANDBOX_REQUIRED | Execution environment checks |
| PII_GATE | PII detection + vault token scanning (see below) |

#### PII Gate (Critical for Outbound Flow)

The PII gate evaluator scans `tool_input` and `command` text for:

1. **Vault tokens**: `{{SNAPPER_VAULT:abc123...}}` — extracted, enriched with label/category
2. **Raw PII patterns**: Credit cards, emails, phones, SSN, API keys — detected via compiled regex
3. **Vault label references**: `vault:My-Visa` — mapped to vault tokens via DB lookup
4. **Placeholder matching**: Detected raw values matched against vault placeholder values

Three modes:
- **Auto**: ALLOW + return resolved tokens inline (no human needed)
- **Protected**: REQUIRE_APPROVAL (human must approve before tokens resolve)
- **Strict**: DENY if raw PII found outside the vault

#### Default Deny & Learning Mode

```
if explicit ALLOW matched → ALLOW
elif LEARNING_MODE=true   → ALLOW (logged as "would_have_blocked")
elif DENY_BY_DEFAULT      → DENY
else                      → ALLOW
```

#### Threat Score Override (Post-Evaluation)

After the rule engine returns, the evaluate endpoint checks the agent's current threat score from Redis:

```
threat:score:{agent_id} → float (0-100)

if score >= 80 → override to DENY
if score >= 60 → override to REQUIRE_APPROVAL
```

---

### 4. Threat Detection (Background)

**File**: `app/services/threat_detector.py`

After evaluation, threat signals are extracted in <2ms (hot path, compiled regex):

- 13 signal types: FILE_READ, NETWORK_SEND, CREDENTIAL_ACCESS, PII_OUTBOUND, ENCODING_DETECTED, VAULT_TOKEN_PROBE, PRIVILEGE_ESCALATION, etc.
- Published to Redis Streams: `threat:signals:{agent_id}`

**Background Worker** (`app/tasks/threat_analysis.py`):
- Celery worker consumes signals every 2 seconds
- Updates per-agent behavioral baseline (7-day rolling window)
- Evaluates against 7 kill chain patterns (data exfil, cred theft, PII harvest, etc.)
- Computes composite score → stores in `threat:score:{agent_id}` (300s TTL)

---

## Outbound Flow: Decision → Resolution → Response

### 1. Immediate Decisions (ALLOW / DENY)

For ALLOW or DENY, the response is returned immediately:

```json
{
  "decision": "allow",
  "reason": "Matched rule: Safe Commands",
  "matched_rule_id": "uuid",
  "resolved_data": {}
}
```

For ALLOW with **auto-mode PII gate**, `resolved_data` contains decrypted vault values:

```json
{
  "decision": "allow",
  "resolved_data": {
    "{{SNAPPER_VAULT:abc123def456...}}": {
      "value": "4111111111111234",
      "category": "credit_card",
      "label": "My Visa",
      "masked_value": "****-****-****-1234"
    }
  }
}
```

### 2. Approval Workflow (REQUIRE_APPROVAL)

When a decision is REQUIRE_APPROVAL:

#### Step 1: Create Approval Request

```
POST /api/v1/rules/evaluate → returns:
{
  "decision": "require_approval",
  "approval_request_id": "uuid",
  "reason": "Requires human approval: PII Gate"
}
```

Stored in Redis with 5-minute TTL:
```
approval:{uuid} → {
  id, agent_id, agent_name, request_type, command,
  tool_name, tool_input, rule_id, rule_name,
  status: "pending", vault_tokens, pii_context,
  owner_chat_id, expires_at
}
```

#### Step 2: Human Notification

Alert routing based on `owner_chat_id`:
- Numeric ID → **Telegram DM** with Approve/Deny inline buttons
- `U` prefix (e.g., `U0ACYA78DSR`) → **Slack DM** with action buttons
- Org webhooks → HTTP POST to configured URL

```
┌──────────┐  Approve/Deny  ┌──────────┐
│ Telegram │ ←──── or ────→ │  Slack   │
│   Bot    │    buttons      │   Bot    │
└────┬─────┘                 └────┬─────┘
     │                            │
     └────────────┬───────────────┘
                  │
                  ▼
     approval:{id}.status = "approved" | "denied"
```

#### Step 3: Agent Polls for Decision

The agent (via plugin or hook) polls `GET /api/v1/approvals/{id}/status`:

```json
// Pending:
{ "status": "pending", "wait_seconds": 5 }

// Approved:
{ "status": "approved", "resolved_data": { ... } }

// Denied:
{ "status": "denied", "reason": "Denied by telegram:john" }
```

#### Step 4: Vault Token Resolution (on Approval)

**File**: `app/services/pii_vault.py::resolve_tokens()`

When approved, each vault token goes through:

1. **Lookup**: Find entry by token in PostgreSQL
2. **Ownership check**: `entry.owner_chat_id == requester_chat_id`
3. **Expiration check**: Token not expired
4. **Max uses check**: `use_count < max_uses`
5. **Domain whitelist**: Destination URL domain in `allowed_domains`
6. **Brute-force check**: Not locked out (5 failures → 15min lockout)
7. **Decrypt**: AES-256-GCM decryption using key derived from SECRET_KEY via HKDF
8. **Update usage**: Increment `use_count`, record `last_used_at`

#### Step 5: Token Replacement in Plugin

**File**: `plugins/snapper-guard/index.ts::replaceTokensInParams()`

```typescript
// Before: { "card": "{{SNAPPER_VAULT:abc123...}}" }
// After:  { "card": "4111111111111234" }
for (const [token, data] of Object.entries(resolved)) {
  result = result.split(token).join(data.value);
}
```

The tool call then executes with the real (decrypted) values. The plaintext never touches disk or logs.

### 3. One-Time Approvals

Telegram "Allow Once" button stores a temporary key:
```
once_allow:{agent_id}:{sha256(command)[:16]} → "1" (short TTL)
```

On next evaluation, the rule engine checks this **first** (before loading rules) and short-circuits to ALLOW.

"Allow Always" creates a permanent allowlist rule in the database.

---

## End-to-End Data Flow

```
Agent tries: browser.fill_form({ card: "vault:My-Visa" })
    │
    ▼
Plugin intercepts (before_tool_call)
    │
    ├─ Detects "vault:My-Visa" reference
    │
    ▼
POST /api/v1/rules/evaluate
    │
    ├─ Auth: API key → agent lookup
    ├─ Rule engine: PII_GATE matches
    │   ├─ Finds "vault:My-Visa" → maps to token {{SNAPPER_VAULT:abc123...}}
    │   └─ Mode: protected → REQUIRE_APPROVAL
    │
    ├─ Threat check: score=12 (low) → no override
    ├─ Creates approval request in Redis
    ├─ Sends Telegram notification with [Approve] [Deny] buttons
    │
    └─ Returns: { decision: "require_approval", approval_request_id: "uuid" }
    │
    ▼
Plugin polls GET /approvals/{uuid}/status every 5s
    │
    ▼
Human clicks [Approve] on Telegram
    │
    ├─ approval:{uuid}.status = "approved"
    │
    ▼
Next poll returns: { status: "approved", resolved_data: {
    "{{SNAPPER_VAULT:abc123...}}": { value: "4111111111111234", ... }
}}
    │
    ▼
Plugin replaces token in params:
    { card: "4111111111111234" }
    │
    ▼
Tool call executes with real credit card number
(plaintext never stored in logs, memory, or disk)
```

---

## Security Architecture

### Multi-Layer Defense

| Layer | Component | Purpose |
|-------|-----------|---------|
| 1 | Rule Engine | Policy enforcement (15 rule types) |
| 2 | Threat Detection | Behavioral anomaly + kill chain detection |
| 3 | PII Vault | AES-256-GCM encrypted sensitive data |
| 4 | Approval Workflow | Human-in-the-loop for sensitive operations |
| 5 | Adaptive Trust | Per-agent trust scoring affects rate limits |
| 6 | Audit Trail | Full logging of all decisions and actions |

### Organization Isolation

- Rules scoped by `organization_id` — no cross-org leakage
- Agents belong to organizations — evaluation only loads matching rules
- Vault entries keyed by `owner_chat_id` — ownership enforced at resolution
- Audit logs org-scoped — users only see their org's activity

### Performance

| Component | Latency | Notes |
|-----------|---------|-------|
| Threat signal extraction | <2ms | Compiled regex, no I/O |
| Rule evaluation | 5-50ms | Depends on rule count |
| Rule cache hit | <1ms | Redis GET + ID-based DB lookup |
| PII batch lookup | 1-5ms | 3 IN queries (tokens, placeholders, labels) |
| Total evaluate endpoint | 50-200ms | Including DB + Redis |
| Token resolution | 10-50ms | Per-token decrypt |
| Approval polling | 0-300s | Human decision time |

---

## Key Files

| File | Purpose |
|------|---------|
| `app/routers/rules.py` | Rule CRUD + `/evaluate` endpoint |
| `app/services/rule_engine.py` | Core evaluation logic, 15 evaluators |
| `app/routers/approvals.py` | Approval workflow API |
| `app/services/pii_vault.py` | AES-256-GCM encryption + token resolution |
| `app/services/threat_detector.py` | Signal extraction (13 types, <2ms) |
| `app/services/behavioral_baseline.py` | Per-agent behavioral profiles |
| `app/services/kill_chain_detector.py` | Multi-step attack pattern detection |
| `app/tasks/threat_analysis.py` | Background Celery worker for scoring |
| `app/routers/telegram.py` | Telegram bot approval workflow |
| `app/routers/slack.py` | Slack bot approval workflow |
| `plugins/snapper-guard/index.ts` | OpenClaw plugin (tool interception) |
| `scripts/openclaw-hooks/` | Shell hook scripts |
| `extension/background.js` | Browser extension service worker |
| `extension/content/*.js` | Content scripts for 5 AI chat platforms |
