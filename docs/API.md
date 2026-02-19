# API Documentation

> **Looking for the stable public API reference?** See [PUBLIC-API.md](PUBLIC-API.md) for the v1.0 public API surface (~35 endpoints) with versioning, rate limit headers, and SDK examples.

Snapper provides a RESTful API for managing agents, rules, and evaluating requests.

**Base URL:** `http://localhost:8000/api/v1`

**OpenAPI Docs:** `http://localhost:8000/api/docs`

## Authentication

### API Key Authentication

Each agent receives a unique API key on creation (`snp_xxx`). Include it in requests:

```bash
curl -X POST /api/v1/rules/evaluate \
  -H "X-API-Key: snp_your_key_here" \
  -H "Content-Type: application/json" \
  -d '{"request_type": "command", "command": "ls -la"}'
```

API keys are optional by default. Enable enforcement with:
```bash
REQUIRE_API_KEY=true
```

## Endpoints

### Health

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Basic health check |
| GET | `/health/ready` | Readiness check (DB + Redis) |

```bash
curl http://localhost:8000/health
# {"status": "healthy", "version": "1.0.0"}

curl http://localhost:8000/health/ready
# {"status": "ready", "database": "connected", "redis": "connected"}
```

### Agents

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/agents` | List agents (paginated) |
| POST | `/api/v1/agents` | Create agent |
| GET | `/api/v1/agents/{id}` | Get agent by ID |
| PUT | `/api/v1/agents/{id}` | Update agent |
| DELETE | `/api/v1/agents/{id}` | Delete agent (soft) |
| POST | `/api/v1/agents/{id}/activate` | Activate agent |
| POST | `/api/v1/agents/{id}/suspend` | Suspend agent |
| POST | `/api/v1/agents/{id}/quarantine` | Quarantine agent |
| POST | `/api/v1/agents/{id}/regenerate-key` | Generate new API key |
| POST | `/api/v1/agents/{id}/reset-trust` | Reset trust score to 1.0 |
| POST | `/api/v1/agents/{id}/toggle-trust` | Toggle trust enforcement on/off |
| POST | `/api/v1/agents/{id}/purge-pii` | Remove PII data |
| POST | `/api/v1/agents/{id}/whitelist-ip` | Add IP to whitelist |
| GET | `/api/v1/agents/{id}/whitelist-ip` | List whitelisted IPs |
| DELETE | `/api/v1/agents/{id}/whitelist-ip` | Remove from whitelist |

#### Create Agent

```bash
curl -X POST http://localhost:8000/api/v1/agents \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My AI Assistant",
    "external_id": "my-agent-001",
    "trust_level": "standard",
    "allowed_origins": ["http://localhost:8000"]
  }'
```

Response:
```json
{
  "id": "uuid",
  "name": "My AI Assistant",
  "external_id": "my-agent-001",
  "api_key": "snp_abc123...",
  "status": "pending",
  "trust_level": "standard",
  "created_at": "2026-02-06T12:00:00Z"
}
```

### Rules

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/rules` | List rules (paginated, filterable) |
| POST | `/api/v1/rules` | Create rule |
| GET | `/api/v1/rules/{id}` | Get rule by ID |
| PUT | `/api/v1/rules/{id}` | Update rule |
| DELETE | `/api/v1/rules/{id}` | Delete rule |
| POST | `/api/v1/rules/evaluate` | Evaluate a request |
| POST | `/api/v1/rules/validate` | Validate rule without saving |
| GET | `/api/v1/rules/templates` | List rule templates |
| POST | `/api/v1/rules/templates/{id}/apply` | Apply template |
| POST | `/api/v1/rules/export` | Export rules |
| POST | `/api/v1/rules/import` | Import rules |

#### Create Rule

```bash
curl -X POST http://localhost:8000/api/v1/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Block rm -rf",
    "rule_type": "command_denylist",
    "action": "deny",
    "priority": 100,
    "parameters": {
      "patterns": ["^rm\\s+-rf"]
    },
    "is_active": true
  }'
```

#### Evaluate Request

This is the main endpoint called by agent hooks:

```bash
curl -X POST http://localhost:8000/api/v1/rules/evaluate \
  -H "Content-Type: application/json" \
  -H "X-API-Key: snp_your_key" \
  -d '{
    "agent_id": "my-agent-001",
    "request_type": "command",
    "command": "rm -rf /tmp/test",
    "origin": "http://localhost:8000"
  }'
```

Response:
```json
{
  "decision": "deny",
  "reason": "Command blocked by rule: Block rm -rf",
  "matched_rule_id": "uuid",
  "matched_rule_name": "Block rm -rf"
}
```

Possible decisions:
- `allow` - Request is permitted
- `deny` - Request is blocked
- `require_approval` - Request needs human approval

#### Allow Once Bypass

When a user taps "Allow Once" in Telegram, a one-time approval key is stored in Redis. The next matching request will be allowed and the key consumed:

```json
{
  "decision": "allow",
  "reason": "One-time approval granted via Telegram"
}
```

The key format is `once_allow:{agent_id}:{command_hash}` with a 5-minute TTL.

#### Learning Mode Response

When `LEARNING_MODE=true`, denied requests show what would happen:
```json
{
  "decision": "allow",
  "reason": "[LEARNING MODE] Would be denied by: Block Dangerous Commands",
  "matched_rule_id": "uuid",
  "matched_rule_name": "Block Dangerous Commands"
}
```

#### Request Types

| Type | Description | Fields |
|------|-------------|--------|
| `command` | Shell command execution | `command` |
| `file_access` | File read/write | `file_path`, `file_operation` |
| `network` | Network egress | `url`, `host`, `port` |
| `tool` | Generic tool call | `tool_name`, `tool_input` |
| `browser_action` | Browser tool call (fill, type, navigate) | `tool_name`, `tool_input` |
| `skill_install` | Skill installation | `skill_name`, `publisher` |

#### PII Detection in Evaluate Response

When the PII gate rule matches, the evaluate response includes additional fields:

```json
{
  "decision": "require_approval",
  "reason": "Requires approval: PII Gate Protection",
  "matched_rule_id": "uuid",
  "matched_rule_name": "PII Gate Protection",
  "approval_request_id": "uuid",
  "approval_timeout_seconds": 300,
  "resolved_data": null
}
```

In **auto mode**, vault tokens are resolved inline:

```json
{
  "decision": "allow",
  "reason": "Allowed by matching rules",
  "resolved_data": {
    "{{SNAPPER_VAULT:a1b2c3d4}}": {
      "value": "4111111111111234",
      "category": "credit_card",
      "label": "My Visa",
      "masked_value": "****-****-****-1234"
    }
  }
}
```

The `resolved_data` field maps vault tokens to their decrypted values. The snapper-guard plugin uses this to replace tokens in tool params before execution.

### Vault (PII Storage)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/vault/entries` | Create encrypted vault entry |
| GET | `/api/v1/vault/entries` | List entries (masked values only) |
| DELETE | `/api/v1/vault/entries/{id}` | Soft-delete entry (ownership check) |
| PUT | `/api/v1/vault/entries/{id}/domains` | Update allowed domains |

#### Create Vault Entry

```bash
curl -X POST http://localhost:8000/api/v1/vault/entries \
  -H "Content-Type: application/json" \
  -d '{
    "owner_chat_id": "12345",
    "owner_name": "John",
    "label": "My Visa",
    "category": "credit_card",
    "raw_value": "4111111111111234",
    "allowed_domains": ["*.expedia.com", "*.delta.com"]
  }'
```

Response:
```json
{
  "id": "uuid",
  "token": "{{SNAPPER_VAULT:a7f3b2c1}}",
  "label": "My Visa",
  "category": "credit_card",
  "masked_value": "****-****-****-1234",
  "allowed_domains": ["*.expedia.com", "*.delta.com"],
  "created_at": "2026-02-07T12:00:00Z"
}
```

The `token` is what agents use in place of raw PII. The raw value is encrypted at rest with AES-256-GCM and never returned via API.

#### Supported PII Categories

`credit_card`, `email`, `phone`, `name`, `address`, `ssn`, `passport`, `bank_account`, `custom`

### Audit

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/audit/stats` | Aggregated stats + hourly breakdown |
| GET | `/api/v1/audit/logs` | List audit logs (paginated) |
| GET | `/api/v1/audit/logs/stream` | Stream logs via SSE |
| GET | `/api/v1/audit/violations` | List policy violations |
| POST | `/api/v1/audit/violations/{id}/resolve` | Resolve violation |
| GET | `/api/v1/audit/alerts` | List alerts |
| POST | `/api/v1/audit/alerts/{id}/acknowledge` | Acknowledge alert |
| GET | `/api/v1/audit/reports/compliance` | Generate compliance report |

#### Audit Stats

Get aggregated stats for the dashboard — total evaluations, allowed/denied/pending counts, and an hourly breakdown for chart rendering.

```bash
curl "http://localhost:8000/api/v1/audit/stats?hours=24"
```

Response:
```json
{
  "total_evaluations": 142,
  "allowed_count": 118,
  "denied_count": 19,
  "pending_count": 5,
  "hourly_breakdown": [
    {"hour": "2026-02-07T10:00", "allowed": 12, "denied": 3},
    {"hour": "2026-02-07T11:00", "allowed": 8, "denied": 1}
  ]
}
```

Query params: `hours` (1-168, default 24)

#### Query Audit Logs

```bash
# All logs
curl http://localhost:8000/api/v1/audit/logs

# Filter by agent
curl "http://localhost:8000/api/v1/audit/logs?agent_id=uuid"

# Filter by action
curl "http://localhost:8000/api/v1/audit/logs?action=request_denied"

# Filter by severity
curl "http://localhost:8000/api/v1/audit/logs?severity=warning"

# Pagination
curl "http://localhost:8000/api/v1/audit/logs?page=1&page_size=50"
```

### Security

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/security/vulnerabilities` | List known vulnerabilities |
| GET | `/api/v1/security/vulnerabilities/{cve}` | Get vulnerability by CVE |
| GET | `/api/v1/security/skills/flagged` | List flagged skills |
| GET | `/api/v1/security/score/{agent_id}` | Get agent security score |
| GET | `/api/v1/security/recommendations` | Get security recommendations |
| POST | `/api/v1/security/recommendations/{id}/apply` | Apply recommendation |
| GET | `/api/v1/security/threat-feed` | Get threat feed updates |

### Threat Detection

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/threats` | List threat events (paginated, filterable) |
| GET | `/api/v1/threats/summary` | Dashboard widget statistics |
| GET | `/api/v1/threats/{threat_id}` | Get single threat event |
| POST | `/api/v1/threats/{threat_id}/resolve` | Resolve or mark as false positive |
| GET | `/api/v1/threats/scores/live` | Live threat scores from Redis |

#### List Threat Events

```bash
curl "http://localhost:8000/api/v1/threats?severity=high&status=active&page=1&page_size=20"
```

Query parameters:

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `agent_id` | UUID | -- | Filter by agent |
| `severity` | string | -- | Filter: `critical`, `high`, `medium`, `low` |
| `threat_type` | string | -- | Filter by type (e.g., `data_exfiltration`, `credential_theft`) |
| `status` | string | -- | Filter: `active`, `investigating`, `resolved`, `false_positive` |
| `page` | int | 1 | Page number |
| `page_size` | int | 20 | Items per page (max 100) |

Response: `{ items: ThreatEvent[], total, page, page_size, pages }`

#### Get Threat Summary

Returns dashboard widget statistics: active threat counts by severity, resolved in last 24h, agents affected, top threat types.

```bash
curl http://localhost:8000/api/v1/threats/summary
```

Response:
```json
{
  "active_count": 5,
  "critical_count": 1,
  "high_count": 2,
  "medium_count": 1,
  "low_count": 1,
  "resolved_24h": 3,
  "agents_affected": 2,
  "top_threat_types": [
    {"threat_type": "data_exfiltration", "count": 2}
  ]
}
```

#### Get Single Threat Event

```bash
curl http://localhost:8000/api/v1/threats/{threat_id}
```

Returns a single threat event with agent name enrichment.

#### Resolve Threat Event

Mark a threat as resolved or false positive.

```bash
curl -X POST http://localhost:8000/api/v1/threats/{threat_id}/resolve \
  -H "Content-Type: application/json" \
  -d '{
    "status": "resolved",
    "resolution_notes": "Investigated - legitimate batch processing"
  }'
```

`status` must be `resolved` or `false_positive`.

#### Live Threat Scores

Returns current threat scores for all agents from Redis (only agents with non-zero scores). Scores have a 300-second TTL.

```bash
curl http://localhost:8000/api/v1/threats/scores/live
```

Response:
```json
[
  {
    "agent_id": "uuid",
    "agent_name": "my-agent",
    "threat_score": 42.5,
    "threat_level": "medium"
  }
]
```

Threat levels: `none` (0), `low` (<40), `medium` (<60), `high` (<80), `critical` (>=80).

### Approvals

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/approvals/pending` | List pending approvals |
| GET | `/api/v1/approvals/{id}/status` | Check approval status (polled by hooks/plugin) |
| POST | `/api/v1/approvals/{id}/decide` | Approve or deny |

#### Check Approval Status

Polled by hooks and the snapper-guard plugin while waiting for human decision:

```bash
curl http://localhost:8000/api/v1/approvals/{id}/status
```

Response (pending):
```json
{
  "id": "uuid",
  "status": "pending",
  "wait_seconds": 5
}
```

Response (approved with PII):
```json
{
  "id": "uuid",
  "status": "approved",
  "reason": "Approved by john",
  "resolved_data": {
    "{{SNAPPER_VAULT:a7f3b2c1}}": {
      "value": "4111111111111234",
      "category": "credit_card",
      "label": "My Visa",
      "masked_value": "****-****-****-1234"
    }
  }
}
```

Note: `resolved_data` is a one-time retrieval — it's deleted from Redis after the first read.

#### Decide on Approval

```bash
curl -X POST http://localhost:8000/api/v1/approvals/{id}/decide \
  -H "Content-Type: application/json" \
  -d '{
    "decision": "approve",
    "decided_by": "admin"
  }'
```

### Integrations

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/integrations` | List integration templates by category |
| GET | `/api/v1/integrations/{id}` | Get integration template details |
| POST | `/api/v1/integrations/{id}/enable` | Enable integration (creates rules) |
| POST | `/api/v1/integrations/{id}/disable` | Disable integration (soft-deletes rules) |
| GET | `/api/v1/integrations/categories/summary` | Category summaries with counts |
| GET | `/api/v1/integrations/legacy-rules` | Rules from removed templates |

### Traffic Discovery

Passively discovers MCP servers and tools from live agent traffic, checks rule coverage, and creates rules from discovered commands.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/integrations/traffic/insights` | Discovered services with coverage analysis |
| GET | `/api/v1/integrations/traffic/coverage` | Check if a command is covered by rules |
| POST | `/api/v1/integrations/traffic/create-rule` | Create rule from a discovered command |
| POST | `/api/v1/integrations/traffic/create-server-rules` | Generate 3 smart default rules for a server |
| GET | `/api/v1/integrations/traffic/known-servers` | List 40+ recognized MCP servers |

#### Traffic Insights

Returns discovered services grouped by MCP server, CLI tool, or builtin — with command counts, coverage status, and template links.

```bash
curl "http://localhost:8000/api/v1/integrations/traffic/insights?hours=168"
```

Query params: `agent_id` (optional UUID), `hours` (1-720, default 168)

Response:
```json
{
  "period_hours": 168,
  "total_evaluations": 633,
  "total_unique_commands": 59,
  "total_uncovered": 12,
  "service_groups": [
    {
      "server_key": "mcp__github",
      "display_name": "GitHub (MCP)",
      "source_type": "mcp",
      "total_count": 142,
      "uncovered_count": 3,
      "has_template": true,
      "template_id": "github",
      "commands": [
        {
          "command": "mcp__github__create_issue",
          "count": 47,
          "last_seen": "2026-02-13T10:30:00Z",
          "decisions": {"allow": 42, "deny": 3, "require_approval": 2},
          "has_matching_rule": true
        }
      ]
    }
  ]
}
```

#### Coverage Check

Check whether a specific command is covered by any active rule, with parsed tool info and template linking.

```bash
curl "http://localhost:8000/api/v1/integrations/traffic/coverage?command=mcp__github__create_issue"
```

Query params: `command` (required), `agent_id` (optional UUID)

Response:
```json
{
  "command": "mcp__github__create_issue",
  "covered": true,
  "matching_rules": [{"id": "uuid", "name": "GitHub - Allow Read", "rule_type": "command_allowlist"}],
  "parsed": {
    "source_type": "mcp",
    "server_key": "github",
    "display_name": "GitHub",
    "tool_name": "create_issue",
    "template_id": "github"
  }
}
```

#### Create Rule from Traffic

Create a rule from a discovered command using prefix or exact pattern mode.

```bash
curl -X POST http://localhost:8000/api/v1/integrations/traffic/create-rule \
  -H "Content-Type: application/json" \
  -d '{
    "command": "mcp__github__create_issue",
    "action": "allow",
    "pattern_mode": "prefix",
    "agent_id": null,
    "name": null
  }'
```

- `pattern_mode: "prefix"` → generates `^mcp__github__create.*` (broader match)
- `pattern_mode: "exact"` → generates `^mcp__github__create_issue$` (single command)
- `action`: `"allow"`, `"deny"`, or `"require_approval"`
- `name`: optional custom name (auto-generated if omitted)

#### Create Server Rules (Smart Defaults)

Generate 3 rules for any MCP server: allow reads, require approval for writes, deny destructive operations.

```bash
curl -X POST http://localhost:8000/api/v1/integrations/traffic/create-server-rules \
  -H "Content-Type: application/json" \
  -d '{"server_name": "google_calendar", "agent_id": null}'
```

Response:
```json
{
  "server_name": "google_calendar",
  "rules_created": 3,
  "rules": [
    {"name": "Google Calendar MCP - Allow Read Operations", "rule_type": "command_allowlist", "action": "allow"},
    {"name": "Google Calendar MCP - Approve Write Operations", "rule_type": "command_allowlist", "action": "require_approval"},
    {"name": "Google Calendar MCP - Block Destructive Operations", "rule_type": "command_denylist", "action": "deny"}
  ]
}
```

#### Custom MCP Template

Enable the `custom_mcp` template with a server name to auto-generate 3 rules:

```bash
curl -X POST http://localhost:8000/api/v1/integrations/custom_mcp/enable \
  -H "Content-Type: application/json" \
  -d '{"custom_server_name": "my_tool"}'
```

#### Known Servers

List all recognized MCP servers (40+) with display names, prefixes, and template links.

```bash
curl http://localhost:8000/api/v1/integrations/traffic/known-servers
```

### Telegram Webhook

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/telegram/webhook` | Telegram bot webhook |

#### Callback Data Formats

The Telegram bot uses inline buttons with specific callback data formats:

| Action | Data Format | Description |
|--------|-------------|-------------|
| `once:{context}` | Allow this command once (5 min) | Creates temporary Redis key |
| `always:{context}` | Create permanent allow rule | Creates COMMAND_ALLOWLIST or SKILL_ALLOWLIST rule |
| `rule:{id}` | View rule details | Shows rule info in chat |
| `confirm_block:{chat_id}` | Confirm emergency block | Creates priority 10000 deny-all rule |
| `cancel_block:{chat_id}` | Cancel emergency block | Clears pending block |
| `approve:{request_id}` | Approve pending request | Allows blocked action |
| `deny:{request_id}` | Deny pending request | Rejects blocked action |

### Setup

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/setup/status` | Check setup status |
| GET | `/api/v1/setup/discover` | Auto-discover running agents |
| POST | `/api/v1/setup/quick-register` | Quick-register an agent |
| POST | `/api/v1/setup/install-config` | Auto-install hook configuration |
| GET | `/api/v1/setup/profiles` | List security profiles |
| GET | `/api/v1/setup/config/{agent_id}` | Get agent config snippet |
| POST | `/api/v1/setup/complete` | Mark setup as complete |

#### Quick Register

Register an agent in one call. Supported `agent_type` values: `openclaw`, `claude-code`, `cursor`, `windsurf`, `cline`, `custom`.

```bash
curl -X POST http://localhost:8000/api/v1/setup/quick-register \
  -H "Content-Type: application/json" \
  -d '{"agent_type": "cursor", "name": "My Cursor"}'
```

Response includes `agent_id` and `api_key` (starts with `snp_`).

#### Install Config

After registering, auto-install hook configuration into the agent's config directory:

```bash
curl -X POST http://localhost:8000/api/v1/setup/install-config \
  -H "Content-Type: application/json" \
  -d '{
    "agent_type": "cursor",
    "agent_id": "cursor-myhostname",
    "api_key": "snp_abc123..."
  }'
```

This writes the env file, copies the hook script, and merges hook configuration. Returns the install result or a fallback config snippet if auto-install isn't possible.

## Rule Types

| Type | Description | Parameters |
|------|-------------|------------|
| `command_allowlist` | Allow matching commands | `patterns: string[]` |
| `command_denylist` | Deny matching commands | `patterns: string[]` |
| `credential_protection` | Block sensitive files | `protected_patterns: string[]` |
| `skill_allowlist` | Allow specific skills | `skills: string[]` |
| `skill_denylist` | Block specific skills | `skills: string[], patterns: string[]` |
| `network_egress` | Control network access | `blocked_hosts: string[], blocked_ports: int[]` |
| `rate_limit` | Rate limiting | `max_requests: int, window_seconds: int` |
| `time_restriction` | Time-based access | `allowed_hours: {start, end}, allowed_days: string[]` |
| `origin_validation` | Validate request origin | `allowed_origins: string[]` |
| `version_enforcement` | Require minimum version | `min_version: string` |
| `sandbox_required` | Require containerized execution | `allowed_environments: string[]` |
| `pii_gate` | Detect PII in tool/browser actions | `scan_tool_input: bool, detect_vault_tokens: bool, pii_categories: string[], pii_mode: "protected"\|"auto"` |
| `human_in_loop` | Require approval for matching requests | `patterns: string[]` |

## Error Responses

All errors follow this format:

```json
{
  "detail": "Error message",
  "type": "ErrorType"
}
```

| Status | Description |
|--------|-------------|
| 400 | Bad Request - Invalid parameters |
| 401 | Unauthorized - Invalid/missing API key |
| 403 | Forbidden - Access denied |
| 404 | Not Found - Resource doesn't exist |
| 409 | Conflict - Duplicate resource |
| 422 | Validation Error - Schema violation |
| 429 | Too Many Requests - Rate limited |
| 500 | Internal Server Error |

## Rate Limiting

API endpoints are rate limited. Headers indicate current status:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1707220800
```

Default limits:
- Evaluate endpoint: 300 requests/minute per agent
- Telegram webhook: 300 requests/minute
- Approval status polling: 360 requests/minute
- Other endpoints: 300 requests/minute per IP

## Webhooks

Configure webhooks to receive notifications:

```bash
curl -X POST http://localhost:8000/api/v1/settings/webhooks \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://your-server.com/webhook",
    "events": ["request_denied", "approval_needed"],
    "secret": "your-webhook-secret"
  }'
```

Webhook payload:
```json
{
  "event": "request_denied",
  "timestamp": "2026-02-06T12:00:00Z",
  "data": {
    "agent_id": "uuid",
    "rule_id": "uuid",
    "request": {...},
    "decision": "deny",
    "reason": "..."
  }
}
```

---

## Authentication (SSO)

### SAML 2.0

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/auth/saml/metadata/{org_slug}` | SP metadata XML |
| `GET` | `/auth/saml/login/{org_slug}` | Initiate SAML login |
| `POST` | `/auth/saml/acs/{org_slug}` | Assertion Consumer Service (callback) |

### OIDC

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/auth/oidc/login/{org_slug}` | Redirect to IdP |
| `GET` | `/auth/oidc/callback/{org_slug}` | Handle IdP callback |

---

## SCIM 2.0

Base path: `/scim/v2`

Authentication: `Authorization: Bearer <scim_token>`

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/Users` | List users (supports `filter`, `startIndex`, `count`) |
| `GET` | `/Users/{id}` | Get user |
| `POST` | `/Users` | Create user |
| `PUT` | `/Users/{id}` | Replace user |
| `PATCH` | `/Users/{id}` | Update user |
| `DELETE` | `/Users/{id}` | Deactivate user |

Filter examples:
- `?filter=userName eq "user@example.com"`
- `?startIndex=1&count=10`

---

## Policy Export/Import

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/rules/export` | Export rules (JSON or YAML) |
| `POST` | `/api/v1/rules/import` | Import rules |
| `POST` | `/api/v1/rules/sync` | Sync from YAML (GitOps) |

Export request:
```json
{
  "format": "yaml",
  "agent_id": "uuid (optional)",
  "include_global": true
}
```

Import request:
```json
{
  "rules": [...],
  "overwrite_existing": false,
  "dry_run": true
}
```

---

## Metrics

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/metrics` | Prometheus-format metrics |

Returns text/plain with counters, histograms, and gauges for HTTP requests, rule evaluations, PII operations, and active agents.

---

## Organizations

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/orgs` | List user's organizations |
| `POST` | `/api/v1/orgs` | Create organization |
| `GET` | `/api/v1/orgs/{id}` | Get organization details |
| `PUT` | `/api/v1/orgs/{id}` | Update organization |
| `GET` | `/api/v1/orgs/{id}/members` | List members |
| `POST` | `/api/v1/orgs/{id}/invite` | Invite member by email |
| `PUT` | `/api/v1/orgs/{id}/members/{user_id}` | Update member role |
| `DELETE` | `/api/v1/orgs/{id}/members/{user_id}` | Remove member |
