# Security Guide

Snapper is an **Agent Application Firewall (AAF)** — it inspects and enforces security policy on traffic in both directions between AI agents and the outside world. This document covers every security mechanism: how data is encrypted, how requests are validated, how PII is detected and protected, and how the system fails safe.

## Table of Contents

- [Design Principles](#design-principles)
- [Inbound Protection](#inbound-protection)
- [Outbound Protection](#outbound-protection)
- [PII Vault Encryption](#pii-vault-encryption)
- [PII Detection & Data Loss Prevention](#pii-detection--data-loss-prevention)
- [Approval Workflow](#approval-workflow)
- [Rule Engine (Fail-Safe)](#rule-engine-fail-safe)
- [API Authentication](#api-authentication)
- [Rate Limiting & Brute Force Protection](#rate-limiting--brute-force-protection)
- [Request Security (Middleware)](#request-security-middleware)
- [Network & Infrastructure](#network--infrastructure)
- [Audit Trail](#audit-trail)
- [Trust Scoring](#trust-scoring)
- [Configuration Hardening](#configuration-hardening)
- [Architecture Assumptions](#architecture-assumptions)

---

## Design Principles

1. **Deny by default** — If no rule explicitly allows an action, it is denied.
2. **Fail closed** — Errors during rule evaluation result in deny, not allow.
3. **Defense in depth** — Multiple independent layers (middleware, rule engine, PII gate, rate limiting) each enforce security independently.
4. **Least privilege** — Agents start untrusted and must earn elevated access.
5. **Immutable audit** — All security-relevant events are logged to the database with server-generated timestamps.
6. **Secrets never at rest in plaintext** — PII is Fernet-encrypted, API keys are hashed for comparison, resolved data has a 30-second TTL and is deleted after one retrieval.

---

## Inbound Protection

Inbound protection prevents external threats from reaching or compromising the agent.

### Origin Validation (CVE-2026-25253)

Unauthorized WebSocket and HTTP origins are blocked at the middleware layer before reaching any application logic. The `Origin` header is validated against the `ALLOWED_ORIGINS` allowlist on every request. This prevents cross-origin WebSocket hijacking attacks where a malicious website sends commands to a locally-running agent.

- **Enforcement:** Middleware (all requests) + `ORIGIN_VALIDATION` rule type
- **Default:** Enabled (`VALIDATE_WEBSOCKET_ORIGIN=true`)
- **Response:** 403 Forbidden with audit log entry

### Host Header Validation

The `Host` header is validated against the `ALLOWED_HOSTS` allowlist to prevent host header injection attacks that can bypass authentication or redirect requests to attacker-controlled servers.

- **Enforcement:** Middleware (all requests)
- **Response:** 403 Forbidden

### Version Enforcement

Agents must report their version when connecting. Snapper checks against minimum version requirements and a blocked versions list to prevent agents with known vulnerabilities from operating.

- **Rule type:** `VERSION_ENFORCEMENT`
- **Mechanism:** Compares reported `agent_version` against per-type minimum versions using Python's `packaging.version` library
- **Conservative default:** Unknown versions are denied unless `allow_unknown_version=true`
- **Use case:** Block agents affected by CVE-2026-25157 (command injection in OpenClaw < 2026.1.29)

### Sandbox Enforcement

Agents must run in an approved execution environment. Bare metal and unknown environments are denied by default.

- **Rule type:** `SANDBOX_REQUIRED`
- **Allowed environments:** `container`, `vm`, `sandbox`
- **Denied environments:** `bare_metal`, `unknown`
- **Use case:** Ensure agents can't directly access host filesystems or network interfaces

### Malicious Skill Blocking

When an agent requests to install or use a skill, Snapper checks it against multiple layers of threat intelligence:

1. **Exact match** against 44+ known malicious skill IDs
2. **Regex patterns** (11 patterns) catching typosquats and naming conventions
3. **Publisher blocking** — all skills from known bad publishers (e.g., `hightower6eu` with 314+ malicious skills)
4. **Database lookup** — automatically blocks skills flagged in the `MaliciousSkill` threat intelligence table

- **Rule type:** `SKILL_DENYLIST`
- **Campaign coverage:** ClawHavoc (341+ skills), typosquats, auto-updaters, crypto drainers
- **Action:** DENY or REQUIRE_APPROVAL

### Localhost Restriction

Restricts which network locations can send requests to Snapper, ensuring only local agents can connect.

- **Enforcement:** Middleware + `LOCALHOST_RESTRICTION` rule type
- **Allowed IPs:** `127.0.0.1`, `::1`, `localhost` (configurable)
- **Use case:** Prevent remote attackers from sending evaluate requests to a locally-running Snapper instance

### API Key Authentication

Each agent receives a unique API key (`snp_xxx`) on registration. When `REQUIRE_API_KEY=true`, requests without a valid key are denied before rule evaluation begins.

- **Key format:** `snp_{base64url(32 bytes)}` — 47 characters
- **Tracking:** `api_key_last_used` timestamp updated on each successful authentication
- **Enforcement:** Controlled by `REQUIRE_API_KEY` setting

### Rate Limiting & Brute Force

Sliding window rate limiting on all endpoints prevents abuse. Adaptive trust scoring optionally throttles misbehaving agents down to 50% of their base rate (only rate-limit breaches penalize trust — normal denials like denylist blocks do not). Trust enforcement is off by default (info-only) and can be enabled per-agent. The vault has dedicated brute force protection (5 failed lookups = 15-minute lockout).

See [Rate Limiting & Brute Force Protection](#rate-limiting--brute-force-protection) for full details.

---

## Outbound Protection

Outbound protection controls what agents can do — blocking dangerous commands, preventing data exfiltration, and requiring human approval for sensitive actions.

### Command Control

Command allowlists and denylists use regex patterns to control which shell commands agents can execute. Deny rules short-circuit evaluation — a single deny match blocks the action regardless of allow rules.

Blocked patterns include remote code execution (pipe to shell, base64 bypass, command substitution), reverse shells (netcat, bash TCP, Python/Perl/Ruby/PHP), destructive operations (rm -rf, dd, mkfs, fork bombs), and persistence/escalation (crontab injection, bashrc modification, SUID/SGID).

### PII Detection & Data Loss Prevention

Every tool call is scanned for 30+ PII patterns covering government IDs, financial data, contact info, addresses, API keys, and secrets across US/UK/Canada/Australia formats. Raw PII from any source — files, APIs, web scrapes — is intercepted before the agent can exfiltrate or misuse it.

See [PII Detection & Data Loss Prevention](#pii-detection--data-loss-prevention) for full details.

### Credential Protection

File access rules block agents from reading sensitive files by default: `.env`, `.pem`, `.key`, `.p12`, `.ssh/*`, `.aws/credentials`, `credentials.json`, `secrets.yaml`, and more.

### Network Egress Control

Outbound network access is controlled by host/port allowlists and denylists. Known exfiltration domains (pastebin, transfer.sh, file.io) and backdoor ports (4444, 5555, 6666-6697) are blocked. IP whitelisting allows users to approve specific destinations after review.

### Human-in-the-Loop Approval

Sensitive operations can require human approval via Telegram before proceeding. The approval workflow has a 5-minute timeout, one-time retrieval of resolved data, and a complete audit trail.

See [Approval Workflow](#approval-workflow) for full details.

---

## PII Vault Encryption

The vault stores sensitive data (credit cards, addresses, SSNs, API keys) so agents never handle raw values directly.

### Encryption Algorithm

| Property | Value |
|----------|-------|
| **Cipher** | Fernet (AES-128-CBC + HMAC-SHA256) |
| **Key derivation** | HKDF-SHA256 |
| **Key input** | `SECRET_KEY` environment variable (minimum 32 characters) |
| **HKDF salt** | `snapper-pii-vault-v1` (constant) |
| **HKDF info** | `pii-vault-encryption-key` (constant) |
| **Derived key size** | 32 bytes (base64url-encoded for Fernet) |

### How It Works

1. User stores PII via Telegram (`/vault add`) or the REST API
2. Snapper encrypts the value with Fernet and stores the ciphertext in PostgreSQL
3. A vault token is generated: `{{SNAPPER_VAULT:<32-hex>}}` (128 bits of entropy from `os.urandom`)
4. The user gives the token to their agent instead of the raw value
5. When the agent uses the token in a tool call, Snapper's PII gate intercepts it
6. After approval (or automatically in auto mode), the token is resolved to the real value and passed to the tool
7. The decrypted value is stored in Redis with a **30-second TTL** and deleted after the first retrieval

### Token Format

```
{{SNAPPER_VAULT:a7f3b2c1d4e5f6a7b8c9d0e1f2a3b4c5}}
                └─────── 32 hex chars (128-bit) ──────┘
```

Legacy 8-character tokens (`{{SNAPPER_VAULT:a7f3b2c1}}`) are backward-compatible.

### Masked Values

Vault entries are never returned in plaintext via the API. All responses use masked values:

| Category | Mask Example |
|----------|-------------|
| Credit card | `****-****-****-4242` |
| Email | `j***@example.com` |
| Phone | `***-***-7890` |
| SSN | `***-**-6789` |
| Name | `J*** S***` |
| Passport | `*****1234` |
| Bank account | `****5678` |
| Address | `123 **** **** ****` |

### Multi-Tenancy & Ownership

- Every vault entry is keyed to an `owner_chat_id` (Telegram user ID)
- All operations (list, delete, resolve, update domains) enforce ownership
- Unauthorized access attempts are logged at WARNING severity
- Token resolution on approval verifies the approver owns the tokens

### Domain Whitelisting

Each vault entry can have an optional `allowed_domains` list. Tokens only resolve when the agent is submitting to a whitelisted domain:

```
/vault domains {{SNAPPER_VAULT:abc123}} add *.expedia.com *.booking.com
```

The PII gate extracts the destination from `tool_input.url`, `page_url`, or `navigate_url` and matches against the whitelist using glob patterns.

### Usage Limits & Expiration

- `max_uses` — Optional cap on how many times a token can be resolved
- `expires_at` — Optional expiration datetime after which the token is unusable
- Both enforced at resolution time; expired/exhausted tokens return errors

### What Happens If SECRET_KEY Changes

Fernet encryption keys are derived from `SECRET_KEY` via HKDF. If you change `SECRET_KEY`, all existing vault entries become **permanently unrecoverable**. Back up your `SECRET_KEY`.

---

## PII Detection & Data Loss Prevention

Beyond the vault, Snapper scans every tool call for raw PII — even if the agent obtained it from a file, API response, web scrape, or any other source.

### How It Works

1. The agent makes a tool call (run command, fill form, write file, etc.)
2. The hook sends the tool name and input to Snapper's `/api/v1/rules/evaluate` endpoint
3. The PII gate rule serializes `tool_input` and `command` to text
4. The text is scanned against 30+ regex patterns
5. If PII is detected:
   - **Protected mode** (default): The action is blocked and a Telegram approval is sent with masked values
   - **Auto mode**: Vault tokens auto-resolve, but raw PII is still blocked
   - **`require_vault_for_approval: true`**: Raw PII is denied outright — the user must store it in the vault first

### Detected PII Categories

| Category | Patterns | Regions |
|----------|----------|---------|
| **Government IDs** | SSN, National Insurance, Social Insurance, Tax File Number, NHS, Medicare, Passport, Driver's License | US, UK, Canada, Australia |
| **Financial** | Credit/debit cards (Visa, MC, Amex, Discover), IBAN, bank routing numbers | International |
| **Contact Info** | Email addresses, phone numbers | US, Canada, UK, Australia |
| **Addresses** | Street addresses, ZIP codes, postcodes, postal codes | US, UK, Canada, Australia |
| **Dates** | MM/DD/YYYY, DD/MM/YYYY, YYYY-MM-DD (potential DOBs) | International |
| **Network** | IPv4 addresses | — |
| **API Keys & Secrets** | OpenAI, Anthropic, AWS (access key + secret), GitHub, Google, Stripe, Slack, Twilio, SendGrid, Bearer tokens, generic secrets | — |
| **Names** | Full names with titles (Mr., Dr., Prof., etc.) | English |

### What Gets Scanned

The PII gate scans two fields from every evaluation request:

- **`command`** — The shell command the agent wants to run
- **`tool_input`** — The full JSON payload for the tool call (form fields, file contents, API parameters, etc.)

Both are serialized to text and scanned with all configured patterns.

### Domain Exemptions

You can exempt trusted domains from PII scanning. If the tool call targets an exempt domain, the PII gate is skipped entirely:

```json
{
  "rule_type": "pii_gate",
  "parameters": {
    "exempt_domains": ["*.yourcompany.com", "internal.example.org"]
  }
}
```

### Monetary Amount Extraction

When PII is detected, Snapper also extracts monetary amounts from the tool input (`$1,234.56`, `EUR 99.99`, etc.) and includes them in the Telegram approval alert — so you can see what the agent is trying to spend.

### Configurable Categories

The PII gate's `pii_categories` parameter controls which patterns are active. The default set covers the highest-signal, lowest-false-positive patterns:

```
credit_card, email, phone_us_ca, street_address, name_with_title,
api_key_openai, api_key_anthropic, api_key_aws, api_key_github,
api_key_google, api_key_stripe, api_key_slack, generic_secret
```

You can expand to the full set (government IDs, dates, postcodes, etc.) or narrow it down in the rule parameters.

---

## Approval Workflow

When a rule triggers `require_approval`, Snapper creates a time-limited approval request.

### Flow

1. Agent tool call → evaluate → rule returns `require_approval`
2. Snapper creates an approval request in Redis (not the database) with a UUID
3. The hook receives `approval_request_id` and starts polling `/api/v1/approvals/{id}/status`
4. A Telegram notification is sent with action details and [Approve] / [Deny] buttons
5. The user taps a button within the timeout window
6. If approved and vault tokens are present, tokens are resolved and `resolved_data` is returned
7. The hook receives the decision and either proceeds or blocks

### Security Properties

| Property | Value |
|----------|-------|
| **Storage** | Redis only (ephemeral, no database persistence) |
| **TTL** | 365 seconds (300s timeout + 60s buffer) |
| **Default timeout** | 300 seconds (5 minutes) |
| **Resolved data TTL** | 30 seconds |
| **Resolved data retrieval** | One-time only (deleted after first poll) |
| **Idempotent decisions** | Can't re-decide an already-decided approval |
| **Ownership enforcement** | Vault token resolution verifies the approver owns the tokens |

### One-Time Approvals

The "Allow Once" Telegram button creates a temporary Redis key:

```
once_allow:{agent_id}:{command_hash}
TTL: 300 seconds
```

The command hash is the first 16 characters of the SHA-256 hex digest. The key is deleted after the first match.

---

## Rule Engine (Fail-Safe)

### Evaluation Order

1. Load all rules for the agent (global + agent-specific)
2. Sort by priority (highest first)
3. Evaluate each active rule:
   - **DENY match → immediate return** (short-circuit, no further evaluation)
   - **REQUIRE_APPROVAL match → return pending** (unless a higher-priority rule already allowed — see below)
   - **ALLOW match → mark found, continue** (later DENY rules can still override)
   - **LOG_ONLY match → continue**
4. If an ALLOW was found → return allow
5. Otherwise → **return deny** (fail closed)

### Priority Precedence

Higher-priority rules take precedence over lower-priority rules of the same permissiveness:

- **DENY always wins** — A deny rule at any priority overrides all allow rules (short-circuits immediately)
- **ALLOW overrides lower-priority REQUIRE_APPROVAL** — If a higher-priority rule explicitly allows an action, lower-priority rules cannot escalate it to require approval. This enables patterns like a high-priority PII gate in auto-mode (ALLOW with resolved tokens) coexisting with a lower-priority PII gate in protected mode (REQUIRE_APPROVAL) — the auto-mode rule's explicit allow takes precedence.
- **REQUIRE_APPROVAL does NOT override a prior ALLOW** — Once a higher-priority rule has allowed the action, subsequent require_approval matches are skipped.

This ensures that rule priority is meaningful: an administrator can create a high-priority allow rule that definitively permits an action, without it being overridden by a lower-priority approval requirement.

### Key Properties

- **No rules = deny** — An agent with no rules cannot do anything
- **DENY always wins** — A deny rule at any priority overrides all allow rules
- **ALLOW blocks lower-priority REQUIRE_APPROVAL** — Explicit allows from higher-priority rules are respected
- **Errors = deny** — Exceptions during evaluation result in deny
- **No caching** — Rules are always loaded fresh from the database to ensure changes take effect immediately
- **Learning mode** — When `LEARNING_MODE=true`, denials are logged but not enforced (the action proceeds)

### Rule Types (15)

| Type | What It Does |
|------|-------------|
| `command_allowlist` | Regex match against allowed command patterns |
| `command_denylist` | Regex match against denied patterns |
| `time_restriction` | Hour/day-of-week enforcement (supports wrap-around) |
| `rate_limit` | Sliding window rate limiting per agent/IP/combined |
| `skill_allowlist` | Only allow listed skills |
| `skill_denylist` | Block listed skills, patterns, publishers |
| `credential_protection` | Block access to .env, .pem, .key, credentials.json |
| `network_egress` | Control outbound hosts, ports, with IP whitelist |
| `origin_validation` | WebSocket origin checking (CVE-2026-25253) |
| `human_in_loop` | Require approval for matching patterns |
| `localhost_restriction` | Only allow localhost clients |
| `file_access` | Path allowlist/denylist with read-only support |
| `version_enforcement` | Block vulnerable agent versions |
| `sandbox_required` | Require containerized execution |
| `pii_gate` | Vault token + raw PII detection |

---

## API Authentication

### Agent API Keys

- **Format:** `snp_{base64url(32 bytes)}` — 47 characters total
- **Generation:** `secrets.token_urlsafe(32)` with `snp_` prefix
- **Storage:** PostgreSQL, unique-indexed, 64-char column
- **Validation:** Prefix check (`snp_`) + database lookup
- **Usage tracking:** `api_key_last_used` timestamp updated on each evaluation
- **Enforcement:** Controlled by `REQUIRE_API_KEY` setting (default: off, recommended on for production)

### Authentication Flow

1. Hook sends `X-API-Key: snp_xxx` header with evaluation request
2. Snapper validates format (must start with `snp_`)
3. Looks up agent by API key in database
4. If `REQUIRE_API_KEY=true` and no valid key → deny the request
5. If key is valid → update `api_key_last_used`, proceed with evaluation

### Vault API Authentication

Vault write operations support an additional authentication layer:

- **`REQUIRE_VAULT_AUTH=true`** — Requires `X-API-Key` header for all vault writes
- **Internal bypass** — Requests with `X-Internal-Source: telegram` (from the Telegram bot) skip API key validation

---

## Rate Limiting & Brute Force Protection

### Rate Limiting

| Endpoint Category | Limit | Window |
|-------------------|-------|--------|
| Default (most endpoints) | 300 requests | 60 seconds |
| Strict (sensitive operations) | 30 requests | 60 seconds |
| API (high-throughput) | 3,000 requests | 60 seconds |
| Vault writes | 30 requests | 60 seconds |
| Approval status polling | 360 requests | 60 seconds |
| Approval decisions | 30 requests | 60 seconds |
| Telegram webhooks | 300 requests | 60 seconds |

**Algorithm:** Sliding window using Redis sorted sets (ZSET) with a Lua script for atomic check-and-increment. This avoids the boundary problems of fixed windows.

**Scope options:** Per agent ID, per IP address, or combined (default).

**Adaptive adjustment:** Agents with high trust scores get up to 2x their base rate limit. Agents with violations get as low as 10% of their base limit.

**Response:** HTTP 429 with `Retry-After` and `X-RateLimit-Remaining` headers.

### Brute Force Protection (Vault)

Failed vault token lookups trigger a lockout mechanism:

| Property | Value |
|----------|-------|
| **Threshold** | 5 failed lookups |
| **Lockout duration** | 15 minutes |
| **Tracking** | Redis keys per identifier |
| **Counter TTL** | 15 minutes (resets on expiry) |
| **Reset** | Counter clears on successful lookup |

### Circuit Breaker (Redis)

If Redis becomes unavailable, a circuit breaker prevents cascading failures:

| State | Behavior |
|-------|----------|
| **Closed** (normal) | All operations proceed |
| **Open** (after 5 failures) | All operations fail fast for 30 seconds |
| **Half-open** (testing) | Up to 3 test calls; success → closed, failure → open |

---

## Request Security (Middleware)

Every HTTP request passes through security middleware that enforces:

### Security Headers

All responses include:

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `X-Frame-Options` | `DENY` | Block clickjacking |
| `X-XSS-Protection` | `1; mode=block` | Legacy XSS protection |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Control referrer leakage |
| `Cache-Control` | `no-store, no-cache, must-revalidate` | Prevent sensitive data caching |
| `Content-Security-Policy` | Restrictive policy (see below) | Prevent XSS and injection |

### Content Security Policy

```
default-src 'self';
script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com;
style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com;
img-src 'self' data:;
font-src 'self';
connect-src 'self';
frame-ancestors 'none';
base-uri 'self';
form-action 'self';
```

### Host Header Validation

- Extracts hostname from the `Host` header (strips port)
- Validates against `ALLOWED_HOSTS` configuration
- Returns 403 for unrecognized hosts
- Prevents host header injection and routing attacks

### Origin Validation

- Validates `Origin` header against `ALLOWED_ORIGINS` for WebSocket and CORS requests
- Mitigates CVE-2026-25253 (WebSocket RCE via malicious origins)
- Controlled by `VALIDATE_WEBSOCKET_ORIGIN` (default: true)

### Request Tracing

- Every request gets a UUID4 `X-Request-ID` (generated if not provided)
- Propagated through all audit logs, error responses, and downstream calls
- Enables end-to-end tracing of security events

### Exempt Paths

Health checks and API documentation bypass security middleware:

```
/health, /health/ready, /api/docs, /api/redoc, /api/openapi.json, /static/*
```

---

## Network & Infrastructure

### Recommended Production Architecture

```
Internet
    │
    ▼
┌──────────┐
│   UFW    │  Firewall: only 22 (SSH) + HTTPS port open
│ Firewall │  (+ port 80 for Let's Encrypt ACME if using --domain)
└────┬─────┘
     │
     ▼
┌──────────┐
│  Caddy   │  --domain: Let's Encrypt on :443 (automatic cert)
│          │  IP-only:  Self-signed cert on :8443
└────┬─────┘
     │ http://127.0.0.1:8000
     ▼
┌──────────────────────────────────────────────┐
│  Docker Network (restart: unless-stopped)     │
│  ┌─────┐  ┌────────┐  ┌───────┐  ┌────────┐ │
│  │ App │  │Postgres│  │ Redis │  │ Celery │ │
│  │:8000│  │ :5432  │  │ :6379 │  │        │ │
│  └─────┘  └────────┘  └───────┘  └────────┘ │
└──────────────────────────────────────────────┘
```

### Key Properties

- **App binds to 127.0.0.1:8000** — Not accessible from the internet directly
- **Caddy handles TLS** — Automatic Let's Encrypt with `--domain`, or self-signed certificates for IP-only deployments
- **UFW firewall** — Only necessary ports open (22 + HTTPS port; 80/443 for ACME)
- **Docker network isolation** — PostgreSQL and Redis are only accessible from within the Docker network; no ports exposed to the host
- **Restart policy** — All containers use `restart: unless-stopped` to survive VPS reboots
- **No secrets in Docker images** — All secrets via `.env` file and environment variables

### Database Security

- PostgreSQL only accessible within Docker network (no host port binding)
- Connection pooling: pool_size=10, max_overflow=20
- Query timeout: 30 seconds
- Soft deletes preserve audit trails (records are never physically deleted)

### Redis Security

- Redis only accessible within Docker network
- Max connections: 50
- PII resolved data encrypted at rest in Redis with 30-second TTL
- Circuit breaker prevents cascading failures on Redis outage

---

## Audit Trail

Every security-relevant event is recorded in an immutable audit log.

### Logged Events

| Category | Events |
|----------|--------|
| **Rule evaluation** | Request allowed, denied, pending approval |
| **Rule management** | Created, updated, deleted, activated, deactivated |
| **Agent management** | Registered, updated, deleted, suspended, quarantined |
| **Security events** | Rate limit exceeded, origin violation, host violation, credential access blocked, malicious skill blocked |
| **PII operations** | Vault entry created, accessed, deleted; PII gate triggered; submission approved/denied |
| **User actions** | Login, logout, approval granted/denied |

### Severity Levels

`DEBUG` → `INFO` → `WARNING` → `ERROR` → `CRITICAL`

### Audit Log Fields

Each log entry includes:
- UUID primary key and request correlation ID
- Action type and severity level
- Associated agent, rule, and user IDs
- Client IP address, origin, user agent
- Human-readable message
- JSONB `details`, `old_value`, `new_value` for change tracking
- Server-generated immutable timestamp

### Database Indexes

- `(agent_id, action)` — Fast agent-specific queries
- `(severity, created_at)` — Alert filtering
- `created_at` — BRIN index for efficient time-range scans on large tables

### Traffic Monitoring & Coverage Analysis

Snapper passively discovers MCP servers and tools from live agent traffic. The Integrations page shows which commands have matching rules and which are uncovered — helping identify gaps in your rule set. This is observational only (no enforcement changes) and uses the same audit log data that powers the Audit dashboard.

Coverage analysis checks every discovered command against active rule patterns, so you can see at a glance whether a new MCP server your agent started using has any security rules in place.

### Policy Violations & Alerts

Serious events generate `PolicyViolation` and `Alert` records with resolution tracking:
- Violations can be resolved with notes
- Alerts can be acknowledged
- Both support severity-based filtering and pagination

---

## Trust Scoring

Each agent has an adaptive trust score that can optionally affect its effective rate limits.

| Property | Details |
|----------|---------|
| **Range** | 0.5 to 2.0 (default: 1.0) |
| **Violation penalty** | -10% per rate-limit breach |
| **Good behavior bonus** | +1% per successful request |
| **Trust decay** | -0.1% over time |
| **Rate limit effect** | Score of 0.5 = 50% of base rate limit (only when enforced) |
| **Minimum multiplier** | 0.5 (50% of base limit) |
| **Maximum multiplier** | 2.0 (200% of base limit) |
| **Default enforcement** | Off (info-only) — score is tracked but does not affect limits |

**Important:** Only rate-limit breaches reduce trust. Normal rule denials (denylist blocks, credential protection, etc.) do not penalize the score — those are the system working correctly.

Trust enforcement is per-agent:
- **Off (default):** Score is tracked for display in the dashboard and Telegram but does not affect rate limits
- **On:** Score actively scales the agent's configured rate limit

Management commands:
- **API:** `POST /agents/{id}/reset-trust` (reset to 1.0), `POST /agents/{id}/toggle-trust` (enable/disable enforcement)
- **Telegram:** `/trust` (view all your agents), `/trust reset [name]`, `/trust enable [name]`, `/trust disable [name]` — operates on all agents owned by your chat ID, or target one by name
- **Dashboard:** "Reset Trust" button and "Trust: On/Off" toggle on each agent card

Trust levels: `untrusted` → `limited` → `standard` → `elevated`

New agents start at `untrusted` trust level. Agents that consistently follow rules can be promoted.

---

## Configuration Hardening

### Recommended Production Settings

```bash
# Strong secret key (never change after vault entries exist)
SECRET_KEY=$(openssl rand -hex 32)

# Enforcement mode (disable learning mode)
LEARNING_MODE=false
DENY_BY_DEFAULT=true

# Require API keys for all agent requests
REQUIRE_API_KEY=true

# Require auth for vault writes
REQUIRE_VAULT_AUTH=true

# Lock down origins and hosts
ALLOWED_HOSTS=localhost,127.0.0.1,your-server-ip
ALLOWED_ORIGINS=https://your-server-ip:8443

# Origin validation (CVE-2026-25253)
VALIDATE_WEBSOCKET_ORIGIN=true
```

### Security Checklist

Run `python3 scripts/snapper-cli.py security-check` to audit automatically, or `security-check --fix` to auto-remediate .env settings.

- [ ] `SECRET_KEY` is at least 32 characters and backed up securely
- [ ] `LEARNING_MODE=false` and `DENY_BY_DEFAULT=true` for enforcement
- [ ] `REQUIRE_API_KEY=true` so agents must authenticate
- [ ] `REQUIRE_VAULT_AUTH=true` so vault writes require API key
- [ ] `ALLOWED_HOSTS` and `ALLOWED_ORIGINS` are set to your actual server/domain
- [ ] Telegram bot token and chat ID are configured for approval alerts
- [ ] UFW firewall is enabled with only necessary ports open
- [ ] Caddy is configured with TLS (Let's Encrypt via `--domain`, or self-signed)
- [ ] PostgreSQL and Redis are not exposed outside the Docker network
- [ ] All containers have `restart: unless-stopped` (set automatically by compose)
- [ ] OpenClaw integration configured (if OpenClaw is on the same server — `deploy.sh` handles this automatically)
- [ ] PII gate rule is active with appropriate categories
- [ ] Audit logs are being generated (check `/audit` dashboard)
- [ ] Hook scripts use `https://` URLs (not `http://`)
- [ ] App is bound to `127.0.0.1:8000` in production (not `0.0.0.0`)
- [ ] Docker is the deployment method (no bare-metal installs)
- [ ] Caddy (or equivalent reverse proxy) is the only external entry point

---

## Architecture Assumptions

Snapper's security model depends on several architectural assumptions. If any of these are violated, security guarantees are weakened or broken entirely.

### Docker Is Mandatory

Snapper must run in Docker containers. The security model assumes:

- **PostgreSQL and Redis are only accessible within the Docker network.** Neither service has authentication enabled by default. If their ports are exposed to the host or network (`ports: "5432:5432"`), anyone can connect with the default credentials (`snapper:snapper`) and read/modify the database, steal vault entries, or poison rate-limiting state.
- **The app container runs as a non-root user** (`snapper`) in production. The Dockerfile creates a dedicated user and drops privileges. Running on bare metal as root removes this isolation.
- **Container networking provides the security boundary** between services. Without Docker, you'd need to manually configure firewall rules, service authentication, and process isolation for every component.

**What breaks:** Bare-metal deployment exposes PostgreSQL and Redis to the network without authentication. Database takeover is trivial.

### App Must Bind to Localhost in Production

In production, the app must bind to `127.0.0.1:8000`, not `0.0.0.0:8000`. The `docker-compose.prod.yml` enforces this with an `!override` directive.

If the app binds to all interfaces (`0.0.0.0`), attackers can bypass the reverse proxy and connect directly to port 8000 — circumventing TLS, origin validation, and any rate limiting or IP restrictions configured in Caddy.

**What breaks:** Direct network access to the app, bypassing TLS and proxy-layer security.

### Reverse Proxy (Caddy) Required for Production

Snapper must sit behind a TLS-terminating reverse proxy in production. `deploy.sh` configures Caddy automatically:

- **With `--domain`:** Caddy obtains a free Let's Encrypt certificate automatically (recommended for production)
- **Without `--domain`:** Caddy uses a self-signed certificate on port 8443 (suitable for internal/testing)

Without a reverse proxy:
- All traffic between agents and Snapper is unencrypted — tool commands, file paths, API keys, and approval decisions are visible to network observers
- Hook scripts transmit evaluation requests (including `tool_input` with potential PII) over plaintext HTTP
- The `ALLOWED_ORIGINS` setting has no effect if there's no TLS layer enforcing the origin

**What breaks:** Plaintext transmission of all agent activity, evaluation requests, and approval decisions. Man-in-the-middle can return `"decision": "allow"` for any blocked command.

### Hook Scripts Must Use HTTPS

All hook scripts (`claude-code-hook.sh`, `cursor-hook.sh`, `windsurf-hook.sh`, `cline-hook.sh`) must communicate with Snapper over HTTPS. The `SNAPPER_URL` environment variable in the hook's env file controls this.

If set to `http://` instead of `https://`:
- Every tool call the agent makes is sent to Snapper in plaintext, including commands, file paths, and tool input
- An attacker can intercept and modify the response, allowing any blocked action
- API keys (`X-API-Key` header) are transmitted in cleartext

Note: Hook scripts use `curl -k` (insecure mode) to accept self-signed certificates. This is acceptable for localhost/internal deployments but does not verify the server's identity. For production deployments exposed to untrusted networks, use valid TLS certificates.

**What breaks:** Full plaintext exposure of all agent activity and credentials.

### SECRET_KEY Is Immutable After Vault Use

The `SECRET_KEY` environment variable is the root of all cryptographic operations. The PII vault derives its Fernet encryption key from `SECRET_KEY` via HKDF-SHA256 with a fixed salt (`snapper-pii-vault-v1`).

If `SECRET_KEY` changes after vault entries have been created:
- **All existing vault entries become permanently unrecoverable.** There is no re-encryption mechanism.
- Vault tokens will fail to resolve, and the encrypted data cannot be decrypted.
- Session tokens are also invalidated (requiring re-authentication).

Key management requirements:
- Generate with `openssl rand -hex 32` (64 hex characters = 256 bits of entropy)
- Back up securely (password manager, secrets vault, or encrypted backup)
- Never commit to version control
- Never share between separate deployments
- The HKDF salt (`snapper-pii-vault-v1`) is hardcoded and must never be modified in the source code

**What breaks:** Permanent, irrecoverable loss of all encrypted PII vault entries.

### Database Connections Are Local

The default `DATABASE_URL` connects to PostgreSQL over the Docker network without SSL:

```
postgresql+asyncpg://snapper:snapper@postgres:5432/snapper
```

This is secure because PostgreSQL is only accessible within the Docker network. However, if you configure a remote PostgreSQL instance (e.g., AWS RDS, managed database), you **must** add `?sslmode=require` to the connection URL:

```
postgresql+asyncpg://user:pass@remote-host:5432/snapper?sslmode=require
```

Without SSL, database credentials and all query data (including PII vault operations) are transmitted in plaintext.

**What breaks:** Plaintext database credentials and query data on the network.

### Redis Has No Authentication

Redis runs without authentication by default. This is safe within the Docker network but would be a critical vulnerability if Redis were exposed to the host or network.

Redis stores:
- Rate limiting counters and windows
- Approval requests and decisions (including PII context)
- Brute force lockout state
- One-time approval keys
- Temporarily resolved PII data (30-second TTL)

If an attacker gains Redis access, they can clear rate limits, approve pending requests, bypass brute force protection, or read cached PII data.

**What breaks:** Rate limiting, brute force protection, approval workflow integrity, and potential PII exposure.

### Summary

| Assumption | If Violated | Severity |
|-----------|------------|----------|
| Docker deployment | DB/Redis exposed without auth | **Critical** |
| App bound to 127.0.0.1 | Bypass TLS and proxy security | **High** |
| Reverse proxy with TLS | Plaintext agent traffic | **High** |
| HTTPS in hook scripts | Plaintext commands and API keys | **High** |
| SECRET_KEY immutable | All vault entries lost forever | **High** |
| Database connections local | Plaintext credentials on network | **Medium** |
| Redis unauthenticated internal | Rate limit/approval bypass | **Medium** |

---

## SIEM Integration

Snapper publishes security events in CEF (Common Event Format) for SIEM consumption.

### CEF Format

Events follow the CEF standard: `CEF:0|Snapper|AAF|version|event_id|name|severity|extensions`

### Syslog Configuration

```env
SIEM_ENABLED=true
SYSLOG_HOST=siem.corp.example.com
SYSLOG_PORT=514
SYSLOG_PROTOCOL=udp
```

### Webhook HMAC Verification

Webhook payloads include `X-Snapper-Signature` header with `sha256=<hex-digest>`. Verify using:

```python
import hmac, hashlib
expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
assert hmac.compare_digest(expected, signature)
```

See [Enterprise Guide](ENTERPRISE.md#siem-integration) for Splunk, QRadar, and Sentinel setup.

## SSO Security

### JIT Provisioning

- Users are auto-created on first SSO login with `member` role
- Email is the unique identifier (normalized to lowercase)
- Deactivated users are re-activated on next SSO login

### Session Lifetime

- Access tokens: 30 minutes (configurable via `ACCESS_TOKEN_EXPIRE_MINUTES`)
- Refresh tokens: 7 days
- SSO sessions follow the IdP session lifetime

### Attribute Mapping

| SAML Attribute | OIDC Claim | Snapper Field |
|---------------|------------|--------------|
| `email` | `email` | `user.email` |
| `firstName` | `given_name` | `user.full_name` (first part) |
| `lastName` | `family_name` | `user.full_name` (last part) |

## SCIM Provisioning

### Bearer Token Security

- SCIM endpoints require `Authorization: Bearer <token>` header
- Token is configured per-organization in settings (`scim_bearer_token`)
- Token should be rotated regularly (recommend 90 days)

### User Lifecycle

| SCIM Operation | Snapper Action |
|---------------|---------------|
| Create User | Create user + add to org |
| Update User | Update email/name |
| Deactivate | Soft-delete user |
| Delete | Hard-delete user |

## Multi-Tenant Security

### Organization Isolation

- All database queries include `organization_id` filter
- Agents, rules, audit logs, and vault entries are org-scoped
- Cross-org data access is impossible through the API
- System-wide rules are read-only for non-admin users

### Data Scoping

| Resource | Scoped By | Enforcement |
|----------|-----------|------------|
| Agents | `organization_id` | Database query filter |
| Rules | `organization_id` | Database query filter |
| Audit Logs | `organization_id` | Database query filter |
| PII Vault | `organization_id` + `owner_chat_id` | Database + ownership check |
| Users | `OrganizationMembership` | Join table |

## Browser Extension Security

### Extension Permissions Model

The browser extension requests minimal permissions:
- `activeTab` — Access only the current tab (not all tabs)
- `storage` — Store configuration locally
- Host permissions limited to AI chat sites only

### No Raw PII in Extension Context

- PII scanning happens client-side (patterns only, no data sent)
- Extension sends tool call metadata to Snapper, not user content
- Vault tokens are resolved server-side, never in the browser

### Managed Storage

Enterprise admins can lock extension settings via Chrome policy:
- Users cannot change Snapper URL or API key
- Fail mode enforced to `closed`
- PII scanning always enabled
