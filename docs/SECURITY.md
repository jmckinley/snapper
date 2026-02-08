# Security Guide

This document covers every security mechanism in Snapper — how data is encrypted, how requests are validated, how PII is detected and protected, and how the system fails safe.

## Table of Contents

- [Design Principles](#design-principles)
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

---

## Design Principles

1. **Deny by default** — If no rule explicitly allows an action, it is denied.
2. **Fail closed** — Errors during rule evaluation result in deny, not allow.
3. **Defense in depth** — Multiple independent layers (middleware, rule engine, PII gate, rate limiting) each enforce security independently.
4. **Least privilege** — Agents start untrusted and must earn elevated access.
5. **Immutable audit** — All security-relevant events are logged to the database with server-generated timestamps.
6. **Secrets never at rest in plaintext** — PII is Fernet-encrypted, API keys are hashed for comparison, resolved data has a 30-second TTL and is deleted after one retrieval.

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
   - **REQUIRE_APPROVAL match → return pending**
   - **ALLOW match → mark found, continue** (later DENY rules can still override)
   - **LOG_ONLY match → continue**
4. If an ALLOW was found → return allow
5. Otherwise → **return deny** (fail closed)

### Key Properties

- **No rules = deny** — An agent with no rules cannot do anything
- **DENY always wins** — A deny rule at any priority overrides all allow rules
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
| Default (most endpoints) | 100 requests | 60 seconds |
| Strict (sensitive operations) | 10 requests | 60 seconds |
| API (high-throughput) | 1,000 requests | 60 seconds |
| Vault writes | 10 requests | 60 seconds |
| Approval status polling | 30 requests | 60 seconds |
| Approval decisions | 10 requests | 60 seconds |
| Telegram webhooks | 60 requests | 60 seconds |

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
│   UFW    │  Firewall: only 22 (SSH), 443, 8443 open
│ Firewall │
└────┬─────┘
     │
     ▼
┌──────────┐
│  Caddy   │  Reverse proxy: TLS termination, rate limiting
│  :8443   │
└────┬─────┘
     │ http://127.0.0.1:8000
     ▼
┌──────────────────────────────────────────────┐
│              Docker Network                   │
│  ┌─────┐  ┌────────┐  ┌───────┐  ┌────────┐ │
│  │ App │  │Postgres│  │ Redis │  │ Celery │ │
│  │:8000│  │ :5432  │  │ :6379 │  │        │ │
│  └─────┘  └────────┘  └───────┘  └────────┘ │
└──────────────────────────────────────────────┘
```

### Key Properties

- **App binds to 127.0.0.1:8000** — Not accessible from the internet directly
- **Caddy handles TLS** — Self-signed certificates or Let's Encrypt
- **UFW firewall** — Only necessary ports open (22, 443, 8443)
- **Docker network isolation** — PostgreSQL and Redis are only accessible from within the Docker network; no ports exposed to the host
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

### Policy Violations & Alerts

Serious events generate `PolicyViolation` and `Alert` records with resolution tracking:
- Violations can be resolved with notes
- Alerts can be acknowledged
- Both support severity-based filtering and pagination

---

## Trust Scoring

Each agent has an adaptive trust score that affects its effective rate limits.

| Property | Details |
|----------|---------|
| **Range** | 0.0 to 1.0 (default: 1.0) |
| **Violation penalty** | -10% per violation |
| **Good behavior bonus** | +1% per successful request |
| **Trust decay** | -0.1% over time |
| **Rate limit effect** | Score of 0.5 = 50% of base rate limit |
| **Minimum multiplier** | 0.1 (10% of base limit) |
| **Maximum multiplier** | 2.0 (200% of base limit) |

Trust levels: `untrusted` → `limited` → `standard` → `elevated`

New agents start at `untrusted` trust level. Agents that consistently follow rules can be promoted. Agents that violate rules have their trust score automatically reduced if `auto_adjust_trust` is enabled.

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

- [ ] `SECRET_KEY` is at least 32 characters and backed up securely
- [ ] `LEARNING_MODE=false` and `DENY_BY_DEFAULT=true` for enforcement
- [ ] `REQUIRE_API_KEY=true` so agents must authenticate
- [ ] `ALLOWED_HOSTS` and `ALLOWED_ORIGINS` are set to your actual server
- [ ] Telegram bot token and chat ID are configured for approval alerts
- [ ] UFW firewall is enabled with only necessary ports open
- [ ] Caddy is configured with TLS for HTTPS access
- [ ] PostgreSQL and Redis are not exposed outside the Docker network
- [ ] PII gate rule is active with appropriate categories
- [ ] Audit logs are being generated (check `/audit` dashboard)
