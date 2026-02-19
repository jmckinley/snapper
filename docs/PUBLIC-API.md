# Snapper Public API v1.0

> Authoritative reference for the stable, public API surface. For internal/dashboard endpoints, see [API.md](API.md).

---

## Authentication

API key via `X-API-Key` header. Keys use the `snp_` prefix and are generated when registering an agent.

```bash
curl -H "X-API-Key: snp_your_key" https://your-snapper/api/v1/agents
```

All write operations on the vault require a valid API key when `REQUIRE_VAULT_AUTH` is enabled (the default for production). Read-only audit and rule listing endpoints accept the key but may not require it depending on deployment configuration.

---

## Base URL & Versioning

- Base path: `/api/v1/`
- Every API response includes the `X-API-Version: 1.0.0` header
- Semantic versioning -- breaking changes only in major bumps

---

## Rate Limits

Default limits per IP per minute. Headers included on every response:

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Max requests per window |
| `X-RateLimit-Remaining` | Remaining in current window |
| `X-RateLimit-Reset` | Seconds until window resets |
| `Retry-After` | Seconds to wait (only on 429) |

Defaults: **300/min** general, **30/min** vault writes, **360/min** approval polling.

---

## Error Format

All errors return a JSON body:

```json
{"detail": "Error message"}
```

Standard HTTP status codes: `400` Bad Request, `401` Unauthorized, `403` Forbidden, `404` Not Found, `409` Conflict, `422` Validation Error, `429` Too Many Requests, `500` Internal Server Error.

---

## Endpoints

### Core (Hook Integration)

#### 1. POST /api/v1/rules/evaluate

Evaluate a request against active security policy. This is the primary endpoint called by agent hooks (PreToolUse, shell hooks, snapper-guard plugin).

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agent_id` | string | yes | Agent external ID |
| `request_type` | string | yes | `command`, `tool`, `file_access`, `network`, `skill_install`, `browser_action` |
| `command` | string | no | Shell command to evaluate |
| `tool_name` | string | no | MCP tool name (e.g., `mcp__github__create_issue`) |
| `tool_input` | object | no | Tool call parameters (scanned for PII) |
| `url` | string | no | Target URL for network requests |
| `file_path` | string | no | File path for file access requests |
| `file_operation` | string | no | `read` or `write` |
| `origin` | string | no | WebSocket/HTTP origin header |
| `skill_id` | string | no | ClawHub skill identifier |

```bash
curl -X POST https://your-snapper/api/v1/rules/evaluate \
  -H "X-API-Key: snp_your_key" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "openclaw-prod",
    "request_type": "command",
    "command": "rm -rf /tmp/build"
  }'
```

**Response (200):**

```json
{
  "decision": "deny",
  "reason": "Command matches denylist pattern: rm -rf",
  "matched_rule_id": "a1b2c3d4-...",
  "matched_rule_name": "Block destructive commands",
  "approval_request_id": null,
  "approval_timeout_seconds": null,
  "resolved_data": null
}
```

When the decision is `require_approval`, the response includes `approval_request_id` and `approval_timeout_seconds`. Poll the approval status endpoint to wait for the human decision. When PII gate mode is `auto`, `resolved_data` contains the decrypted vault values inline.

---

#### 2. GET /api/v1/approvals/{id}/status

Poll approval status. Used by hooks waiting for a human decision via Telegram or Slack.

```bash
curl https://your-snapper/api/v1/approvals/abc123-def456/status
```

**Response (200):**

```json
{
  "id": "abc123-def456",
  "status": "approved",
  "reason": "Approved by @john via Telegram",
  "wait_seconds": null,
  "resolved_data": {
    "{{SNAPPER_VAULT:a1b2c3d4...}}": "actual-secret-value"
  }
}
```

| Status | Meaning |
|--------|---------|
| `pending` | Awaiting human decision |
| `approved` | Approved -- proceed with action |
| `denied` | Denied by reviewer |
| `expired` | Timed out (default 5 minutes) |

`resolved_data` is populated once on approval for PII gate requests and cleared after first retrieval.

---

#### 3. POST /api/v1/approvals/{id}/decide

Approve or deny a pending approval request. Supports human decisions (via dashboard/Telegram/Slack) and automated bot decisions (via API key).

**Auth:** API key (`snp_` prefix) or user session. When using an API key, the calling agent must belong to the same organization as the approval request.

```bash
curl -X POST https://your-snapper/api/v1/approvals/abc123-def456/decide \
  -H "X-API-Key: snp_bot_key" \
  -H "Content-Type: application/json" \
  -d '{
    "decision": "approve",
    "decided_by": "bot:my-approval-bot",
    "reason": "Command matches safe read pattern"
  }'
```

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `decision` | string | yes | `approve` or `deny` |
| `decided_by` | string | no | Human-readable name of the decider. Defaults to `bot:<agent-name>` for API key callers |
| `reason` | string | no | Why the decision was made. Stored in audit trail |

**Response (200):**

```json
{
  "id": "abc123-def456",
  "status": "approved",
  "reason": "Approved by bot:my-approval-bot"
}
```

| Status Code | Meaning |
|-------------|---------|
| `200` | Decision applied |
| `400` | Invalid decision value |
| `401` | Missing or invalid API key |
| `403` | Agent not in same organization |
| `409` | Approval already decided |
| `410` | Approval expired or not found |
| `429` | Automated approval rate cap exceeded (see `Retry-After` header) |

**Safety mechanisms for automated bots:**
- Per-org hourly rate cap (default 200/hour, configurable per org)
- Anomaly detection: alert fired if a single agent auto-approves > 50 requests in 10 minutes
- Audit trail tags automated decisions with `decision_source: "automation"` and the calling agent's ID

---

#### 4. GET /api/v1/approvals/pending

List pending (undecided) approval requests. When called with an API key, results are filtered to the calling agent's organization.

```bash
curl https://your-snapper/api/v1/approvals/pending \
  -H "X-API-Key: snp_bot_key"
```

**Response (200):**

```json
{
  "pending": [
    {
      "id": "abc123-def456",
      "agent_id": "f47ac10b-...",
      "agent_name": "openclaw-prod",
      "request_type": "command",
      "command": "rm -rf /tmp/build",
      "tool_name": null,
      "tool_input": null,
      "rule_name": "Approve destructive commands",
      "status": "pending",
      "created_at": "2026-02-18T10:00:00",
      "expires_at": "2026-02-18T10:05:00",
      "organization_id": "org-uuid-..."
    }
  ],
  "count": 1
}
```

---

#### 5. POST /api/v1/approvals/test

Simulate the full approval webhook flow without creating a real approval. Creates a temporary test approval in Redis (60s TTL), delivers a realistic `request_pending_approval` webhook to org webhooks, and returns the test approval ID.

Bot developers can use the returned ID to call `/decide` and verify their full round-trip.

```bash
curl -X POST https://your-snapper/api/v1/approvals/test \
  -H "X-API-Key: snp_your_key" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "f47ac10b-...",
    "request_type": "command",
    "command": "echo test"
  }'
```

**Response (200):**

```json
{
  "approval_request_id": "test_abc123-...",
  "payload": {
    "event": "request_pending_approval",
    "test": true,
    "details": { "..." }
  },
  "webhooks_delivered": 1
}
```

Test approvals are sandboxed: decisions on test IDs are logged with `"test": true` in the audit trail and do not affect real workflows. Rate caps are not applied to test decisions.

---

### Approval Policies (Server-Side Auto-Rules)

Policies auto-approve or auto-deny requests without human intervention. Stored in organization settings. Policies never auto-approve when PII vault tokens are present.

#### 6. GET /api/v1/approval-policies

List all approval policies for the organization.

#### 7. POST /api/v1/approval-policies

Create an approval policy. Requires org membership.

```bash
curl -X POST https://your-snapper/api/v1/approval-policies \
  -H "X-API-Key: snp_your_key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Auto-approve reads for trusted agents",
    "conditions": {
      "request_types": ["command"],
      "command_patterns": ["^(ls|cat|head|git log)"],
      "min_trust_score": 0.8
    },
    "decision": "approve",
    "priority": 10,
    "max_auto_per_hour": 100
  }'
```

**Policy conditions (all are AND-ed):**

| Condition | Type | Description |
|-----------|------|-------------|
| `request_types` | list[str] | Filter by request type |
| `command_patterns` | list[str] | Regex patterns for command matching |
| `tool_names` | list[str] | Exact tool name matches |
| `min_trust_score` | float | Minimum agent trust score (0.5-2.0) |
| `agent_names` | list[str] | Specific agent names |

**Safety:**
- Per-policy hourly cap (`max_auto_per_hour`, default 100)
- Org kill switch: `Organization.settings["approval_policies_enabled"]` (default true)
- PII vault tokens always require explicit decision (policies cannot auto-approve PII)

#### 8. PUT /api/v1/approval-policies/{id}

Update a policy (name, conditions, decision, priority, active status).

#### 9. DELETE /api/v1/approval-policies/{id}

Delete a policy. Returns `204 No Content`.

#### 10. POST /api/v1/approval-policies/test

Dry-run a request against policies without executing anything.

```bash
curl -X POST https://your-snapper/api/v1/approval-policies/test \
  -H "X-API-Key: snp_your_key" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_name": "production-agent",
    "request_type": "command",
    "command": "ls -la",
    "trust_score": 0.9,
    "has_pii": false
  }'
```

**Response (200):**

```json
{
  "matched": true,
  "policy_id": "abc123-...",
  "policy_name": "Auto-approve reads for trusted agents",
  "decision": "approve",
  "reason": "Policy 'Auto-approve reads for trusted agents' would approve this request"
}
```

---

### Webhook Payload: request_pending_approval

When an approval is created, Snapper delivers an enriched webhook payload to all configured org webhooks:

```json
{
  "event": "request_pending_approval",
  "severity": "warning",
  "message": "Agent 'openclaw-prod' requires approval: rm -rf /tmp/build",
  "timestamp": "2026-02-18T10:00:00",
  "source": "snapper",
  "organization_id": "org-uuid-...",
  "details": {
    "approval_request_id": "abc123-def456",
    "approval_expires_at": "2026-02-18T10:05:00",
    "agent_id": "f47ac10b-...",
    "agent_name": "openclaw-prod",
    "rule_name": "Approve destructive commands",
    "rule_id": "rule-uuid-...",
    "request_type": "command",
    "command": "rm -rf /tmp/build",
    "tool_name": null,
    "tool_input": null,
    "trust_score": 1.0,
    "pii_detected": false
  }
}
```

Use `details.approval_request_id` to call `/decide`. Check `details.approval_expires_at` for your deadline.

---

### Agents

#### 3. GET /api/v1/agents

List agents with pagination and filtering.

| Query Param | Type | Default | Description |
|-------------|------|---------|-------------|
| `page` | int | 1 | Page number |
| `page_size` | int | 20 | Items per page (max 100) |
| `status` | string | -- | Filter: `active`, `suspended`, `quarantined` |
| `trust_level` | string | -- | Filter: `untrusted`, `basic`, `verified`, `admin` |
| `search` | string | -- | Search name or external_id |
| `include_deleted` | bool | false | Include soft-deleted agents |

```bash
curl -H "X-API-Key: snp_your_key" \
  "https://your-snapper/api/v1/agents?page=1&page_size=10&status=active"
```

**Response (200):**

```json
{
  "items": [
    {
      "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
      "name": "openclaw-prod",
      "external_id": "openclaw-prod",
      "status": "active",
      "trust_level": "basic",
      "trust_score": 1.0,
      "auto_adjust_trust": false,
      "api_key": "snp_abc123...",
      "owner_chat_id": "123456789",
      "created_at": "2026-02-01T12:00:00",
      "updated_at": "2026-02-15T08:30:00"
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 10,
  "pages": 1
}
```

#### 4. POST /api/v1/agents

Register a new agent. Returns the generated `api_key`.

```bash
curl -X POST https://your-snapper/api/v1/agents \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-agent",
    "external_id": "my-agent-001",
    "trust_level": "basic",
    "owner_chat_id": "123456789"
  }'
```

**Response (201):**

```json
{
  "id": "f47ac10b-...",
  "name": "my-agent",
  "external_id": "my-agent-001",
  "status": "active",
  "trust_level": "basic",
  "api_key": "snp_7f3a9b2e...",
  "trust_score": 1.0,
  "auto_adjust_trust": false,
  "owner_chat_id": "123456789",
  "created_at": "2026-02-16T10:00:00",
  "updated_at": "2026-02-16T10:00:00"
}
```

Save the `api_key` -- it is the only time it is returned in full.

#### 5. GET /api/v1/agents/{id}

Get a single agent by UUID.

#### 6. PUT /api/v1/agents/{id}

Update agent fields. Accepts partial updates (any subset of: `name`, `description`, `status`, `trust_level`, `owner_chat_id`, `allowed_origins`, `rate_limit_max_requests`, `rate_limit_window_seconds`, `tags`, `metadata`).

#### 7. DELETE /api/v1/agents/{id}

Soft-delete an agent. Sets `is_deleted = true`; the agent is excluded from queries by default.

#### 8. POST /api/v1/agents/{id}/activate

Re-activate a suspended agent. Returns the updated agent.

#### 9. POST /api/v1/agents/{id}/suspend

Suspend an agent. All evaluate calls for this agent will return `deny` while suspended.

#### 10. POST /api/v1/agents/{id}/regenerate-key

Generate a new API key, invalidating the old one. Returns `{"api_key": "snp_new_key..."}`.

#### 11. POST /api/v1/agents/{id}/reset-trust

Reset the adaptive trust score back to `1.0`.

```bash
curl -X POST https://your-snapper/api/v1/agents/{id}/reset-trust \
  -H "X-API-Key: snp_your_key"
```

#### 12. POST /api/v1/agents/{id}/toggle-trust

Toggle adaptive trust enforcement on or off for this agent. When off, the trust score is still tracked but does not affect rate limits.

---

### Rules

#### 13. GET /api/v1/rules

List rules with pagination and filtering.

| Query Param | Type | Default | Description |
|-------------|------|---------|-------------|
| `page` | int | 1 | Page number |
| `page_size` | int | 20 | Items per page (max 100) |
| `agent_id` | UUID | -- | Filter by agent |
| `rule_type` | string | -- | Filter by type (see Rule Types) |
| `is_active` | bool | -- | Filter active/inactive |

#### 14. POST /api/v1/rules

Create a new rule.

```bash
curl -X POST https://your-snapper/api/v1/rules \
  -H "X-API-Key: snp_your_key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Block rm -rf",
    "rule_type": "command_denylist",
    "action": "deny",
    "priority": 100,
    "parameters": {
      "commands": ["rm -rf", "mkfs", "dd if="]
    },
    "agent_id": "f47ac10b-...",
    "is_active": true,
    "tags": ["safety", "destructive"]
  }'
```

**Response (201):**

```json
{
  "id": "b2c3d4e5-...",
  "name": "Block rm -rf",
  "rule_type": "command_denylist",
  "action": "deny",
  "priority": 100,
  "parameters": {"commands": ["rm -rf", "mkfs", "dd if="]},
  "agent_id": "f47ac10b-...",
  "is_active": true,
  "tags": ["safety", "destructive"],
  "match_count": 0,
  "last_matched_at": null,
  "created_at": "2026-02-16T10:05:00",
  "updated_at": "2026-02-16T10:05:00"
}
```

#### 15. GET /api/v1/rules/{id}

Get a single rule by UUID.

#### 16. PUT /api/v1/rules/{id}

Update rule fields. Accepts partial updates.

#### 17. DELETE /api/v1/rules/{id}

Delete a rule (returns `204 No Content`).

#### 18. POST /api/v1/rules/validate

Validate a rule definition without persisting it. Useful for dry-run testing.

```bash
curl -X POST https://your-snapper/api/v1/rules/validate \
  -H "Content-Type: application/json" \
  -d '{
    "rule": {
      "name": "Test rule",
      "rule_type": "command_denylist",
      "action": "deny",
      "parameters": {"commands": ["rm -rf"]}
    },
    "test_context": {
      "command": "rm -rf /tmp"
    }
  }'
```

#### 19. GET /api/v1/rules/templates

List available rule templates (CVE mitigations, skill blockers, credential protection, etc.).

#### 20. POST /api/v1/rules/templates/{id}/apply

Apply a template to create a rule. Accepts `agent_id` and optional parameter overrides.

#### 21. POST /api/v1/rules/export

Export rules as JSON or YAML.

```bash
curl -X POST https://your-snapper/api/v1/rules/export \
  -H "Content-Type: application/json" \
  -d '{"format": "yaml", "agent_id": "f47ac10b-..."}'
```

#### 22. POST /api/v1/rules/import

Import rules from a JSON or YAML payload. Returns counts of created, updated, and errored rules.

#### 23. POST /api/v1/rules/sync

Sync rules from a YAML definition (GitOps workflow). Compares the provided YAML against existing rules and applies a diff -- creating, updating, or deactivating as needed.

---

### Vault (Encrypted PII Storage)

#### 24. POST /api/v1/vault/entries

Create a new encrypted PII vault entry. The raw value is encrypted with AES-256-GCM (HKDF-derived key) and never stored in plaintext.

```bash
curl -X POST https://your-snapper/api/v1/vault/entries \
  -H "X-API-Key: snp_your_key" \
  -H "Content-Type: application/json" \
  -d '{
    "owner_chat_id": "123456789",
    "label": "Stripe API key",
    "category": "api_key",
    "raw_value": "sk_live_abc123...",
    "allowed_domains": ["api.stripe.com"]
  }'
```

**Response (201):**

```json
{
  "id": "e5f6a7b8-...",
  "owner_chat_id": "123456789",
  "label": "Stripe API key",
  "category": "api_key",
  "token": "{{SNAPPER_VAULT:a1b2c3d4e5f6a7b8...}}",
  "masked_value": "sk_l****123...",
  "placeholder_value": null,
  "allowed_domains": ["api.stripe.com"],
  "max_uses": null,
  "use_count": 0,
  "created_at": "2026-02-16T10:10:00",
  "expires_at": null
}
```

Use the returned `token` value in agent tool inputs. The PII gate rule will detect the token and either require approval or auto-resolve it depending on configuration.

**Categories:** `email`, `phone`, `ssn`, `credit_card`, `api_key`, `password`, `address`, `name`, `other`.

#### 25. GET /api/v1/vault/entries

List vault entries for a specific owner. Values are always masked.

| Query Param | Type | Required | Description |
|-------------|------|----------|-------------|
| `owner_chat_id` | string | yes | Telegram/Slack user ID of the owner |

```bash
curl "https://your-snapper/api/v1/vault/entries?owner_chat_id=123456789" \
  -H "X-API-Key: snp_your_key"
```

#### 26. DELETE /api/v1/vault/entries/{id}

Permanently delete a vault entry and its encrypted data. Returns `204 No Content`.

#### 27. PUT /api/v1/vault/entries/{id}/domains

Update the allowed domain list for a vault entry.

```bash
curl -X PUT https://your-snapper/api/v1/vault/entries/{id}/domains \
  -H "X-API-Key: snp_your_key" \
  -H "Content-Type: application/json" \
  -d '{"allowed_domains": ["api.stripe.com", "dashboard.stripe.com"]}'
```

---

### Audit

#### 28. GET /api/v1/audit/stats

Aggregated audit statistics with hourly breakdown. Used for dashboard charts.

| Query Param | Type | Default | Description |
|-------------|------|---------|-------------|
| `hours` | int | 24 | Lookback window (1-168) |

```bash
curl "https://your-snapper/api/v1/audit/stats?hours=24" \
  -H "X-API-Key: snp_your_key"
```

**Response (200):**

```json
{
  "total_evaluations": 1542,
  "allowed": 1389,
  "denied": 127,
  "pending_approval": 26,
  "hourly": [
    {"hour": "2026-02-16T09:00:00", "allowed": 58, "denied": 5},
    {"hour": "2026-02-16T10:00:00", "allowed": 63, "denied": 8}
  ]
}
```

#### 29. GET /api/v1/audit/logs

Query audit logs with pagination and filtering.

| Query Param | Type | Default | Description |
|-------------|------|---------|-------------|
| `page` | int | 1 | Page number |
| `page_size` | int | 50 | Items per page (max 200) |
| `agent_id` | UUID | -- | Filter by agent |
| `action` | string | -- | Filter by action type |
| `severity` | string | -- | Filter: `info`, `warning`, `critical` |
| `since` | datetime | -- | Start time (ISO 8601) |
| `until` | datetime | -- | End time (ISO 8601) |

#### 30. GET /api/v1/audit/violations

List policy violations with pagination. Violations are generated when rules deny a request.

#### 31. GET /api/v1/audit/alerts

List alerts with pagination. Alerts are generated for critical security events such as rate-limit breaches, emergency blocks, and origin violations.

---

### Webhooks

Webhook endpoints allow you to receive real-time notifications for security events. Payloads are signed with HMAC-SHA256 (see Webhook Signatures below).

#### 32. GET /api/v1/webhooks

List all webhook endpoints for the organization.

#### 33. POST /api/v1/webhooks

Create a webhook endpoint.

```bash
curl -X POST https://your-snapper/api/v1/webhooks \
  -H "X-API-Key: snp_your_key" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://your-app.com/snapper-events",
    "event_filters": ["request_denied", "rate_limit_exceeded"],
    "description": "Security alerts to PagerDuty"
  }'
```

**Response (201):**

```json
{
  "id": "wh_abc123",
  "url": "https://your-app.com/snapper-events",
  "description": "Security alerts to PagerDuty",
  "event_filters": ["request_denied", "rate_limit_exceeded"],
  "active": true,
  "created_at": "2026-02-16T10:15:00",
  "has_secret": true
}
```

If `secret` is not provided, one is auto-generated. The secret is only returned at creation time.

**Available event types:** `request_allowed`, `request_denied`, `request_pending_approval`, `rate_limit_exceeded`, `origin_violation`, `rule_created`, `rule_updated`, `rule_deleted`, `agent_registered`, `agent_suspended`, `agent_quarantined`, `pii_vault_created`, `pii_vault_accessed`, `emergency_block`.

#### 34. PUT /api/v1/webhooks/{id}

Update a webhook endpoint (URL, event filters, active status, description).

#### 35. DELETE /api/v1/webhooks/{id}

Delete a webhook endpoint. Returns `204 No Content`.

---

### Integrations (Traffic Discovery)

Discovery-first approach: Snapper analyzes audit log traffic to detect MCP servers and tools your agents use, then helps you create targeted rules.

#### 36. GET /api/v1/integrations/traffic/insights

Discovered MCP servers and tools from audit trail traffic.

| Query Param | Type | Description |
|-------------|------|-------------|
| `agent_id` | UUID | Scope to a specific agent |

```bash
curl "https://your-snapper/api/v1/integrations/traffic/insights" \
  -H "X-API-Key: snp_your_key"
```

#### 37. POST /api/v1/integrations/traffic/create-rule

Create a single rule from a discovered command or tool.

```bash
curl -X POST https://your-snapper/api/v1/integrations/traffic/create-rule \
  -H "X-API-Key: snp_your_key" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "mcp__github__create_issue",
    "action": "allow",
    "pattern_mode": "prefix",
    "agent_id": "f47ac10b-..."
  }'
```

#### 38. POST /api/v1/integrations/traffic/create-server-rules

Generate smart default rules for a recognized MCP server. Known servers (github, slack, filesystem, etc.) get curated rule sets. Unknown servers get three generic rules: allow reads, require approval for writes, deny destructive operations.

```bash
curl -X POST https://your-snapper/api/v1/integrations/traffic/create-server-rules \
  -H "X-API-Key: snp_your_key" \
  -H "Content-Type: application/json" \
  -d '{"server_name": "github", "agent_id": "f47ac10b-..."}'
```

**Response (200):**

```json
{
  "server_name": "github",
  "rules_created": 5,
  "rules": [
    {
      "name": "GitHub - Allow read operations",
      "rule_type": "command_allowlist",
      "action": "allow",
      "parameters": {"commands": ["mcp__github__get_.*", "mcp__github__list_.*"]}
    },
    {
      "name": "GitHub - Approve write operations",
      "rule_type": "command_allowlist",
      "action": "require_approval",
      "parameters": {"commands": ["mcp__github__create_.*", "mcp__github__update_.*"]}
    }
  ]
}
```

#### 39. GET /api/v1/integrations/traffic/known-servers

List all recognized MCP servers in the registry (40+). Returns server names, descriptions, and associated tool patterns.

---

## Rule Types

| Type | Description | Key Parameters |
|------|-------------|----------------|
| `command_allowlist` | Allow commands matching patterns | `commands` (list of regex patterns) |
| `command_denylist` | Deny commands matching patterns | `commands` (list of regex patterns) |
| `credential_protection` | Block access to sensitive credential files | `protected_paths` (list of file globs) |
| `skill_allowlist` | Allow specific ClawHub skills | `skills` (list of skill IDs) |
| `skill_denylist` | Block specific ClawHub skills | `skills` (list of skill IDs), `auto_block_flagged` |
| `network_egress` | Control outbound network access | `allowed_hosts`, `blocked_hosts`, `allowed_ports` |
| `rate_limit` | Limit request frequency per agent | `max_requests`, `window_seconds` |
| `time_restriction` | Allow/deny during time windows | `allowed_days`, `allowed_hours_start`, `allowed_hours_end`, `timezone` |
| `origin_validation` | Validate request origin headers | `allowed_origins`, `strict_mode` |
| `version_enforcement` | Require minimum agent version | `min_version`, `version_header` |
| `sandbox_required` | Require sandboxed execution | `require_sandbox`, `allowed_modes` |
| `pii_gate` | Detect and protect PII in tool inputs | `mode` (`protected` or `auto`), `categories` |
| `human_in_loop` | Require human approval for matching actions | `commands`, `tools`, `timeout_seconds` |

Rule evaluation order: rules are sorted by priority (highest first). `DENY` always short-circuits. A higher-priority `ALLOW` prevents a lower-priority `REQUIRE_APPROVAL` from overriding it. Default behavior is deny (fail-safe).

---

## Webhook Signatures

Every webhook delivery includes an `X-Snapper-Signature` header containing the hex-encoded HMAC-SHA256 digest of the request body, computed using the webhook secret.

### Verification (Python)

```python
import hashlib
import hmac

def verify_signature(payload_body: bytes, secret: str, signature: str) -> bool:
    """Verify the X-Snapper-Signature header."""
    expected = hmac.new(
        secret.encode("utf-8"),
        payload_body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)
```

### Verification (Node.js)

```javascript
const crypto = require("crypto");

function verifySignature(body, secret, signature) {
  const expected = crypto
    .createHmac("sha256", secret)
    .update(body)
    .digest("hex");
  return crypto.timingSafeEqual(
    Buffer.from(expected),
    Buffer.from(signature)
  );
}
```

Always use constant-time comparison to prevent timing attacks.

---

## SDK

The Snapper Python SDK provides typed clients for all public API endpoints, plus drop-in wrappers for popular LLM providers.

### Installation

```bash
pip install snapper-sdk
```

### Usage

```python
from snapper_sdk import SnapperClient

client = SnapperClient(
    base_url="https://your-snapper",
    api_key="snp_your_key",
)

# Evaluate a command
result = client.evaluate(
    agent_id="my-agent",
    request_type="command",
    command="git push origin main",
)
print(result.decision)  # "allow"
```

### Async Client

```python
from snapper_sdk import AsyncSnapperClient

async def main():
    client = AsyncSnapperClient(
        base_url="https://your-snapper",
        api_key="snp_your_key",
    )
    result = await client.evaluate(
        agent_id="my-agent",
        request_type="command",
        command="git push origin main",
    )
```

### LLM Provider Wrappers

Drop-in wrappers that automatically intercept tool calls and run them through Snapper policy before execution:

```python
from snapper_sdk.providers import SnapperOpenAI, SnapperAnthropic, SnapperGemini

# OpenAI
client = SnapperOpenAI(
    snapper_url="https://your-snapper",
    snapper_api_key="snp_your_key",
    openai_api_key="sk-...",
)

# Anthropic
client = SnapperAnthropic(
    snapper_url="https://your-snapper",
    snapper_api_key="snp_your_key",
    anthropic_api_key="sk-ant-...",
)

# Google Gemini
client = SnapperGemini(
    snapper_url="https://your-snapper",
    snapper_api_key="snp_your_key",
    google_api_key="AIza...",
)
```

See the [SDK README](../sdk/README.md) for full documentation, configuration options, and advanced usage.
