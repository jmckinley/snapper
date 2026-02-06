# API Documentation

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
| `skill_install` | Skill installation | `skill_name`, `publisher` |

### Audit

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/audit/logs` | List audit logs (paginated) |
| GET | `/api/v1/audit/violations` | List policy violations |
| POST | `/api/v1/audit/violations/{id}/resolve` | Resolve violation |
| GET | `/api/v1/audit/alerts` | List alerts |
| POST | `/api/v1/audit/alerts/{id}/acknowledge` | Acknowledge alert |

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

### Approvals

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/approvals` | List pending approvals |
| GET | `/api/v1/approvals/{id}` | Get approval details |
| POST | `/api/v1/approvals/{id}/decide` | Approve or deny |

#### Decide on Approval

```bash
curl -X POST http://localhost:8000/api/v1/approvals/{id}/decide \
  -H "Content-Type: application/json" \
  -d '{
    "decision": "approve",
    "reason": "Approved by admin"
  }'
```

### Integrations

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/integrations` | List available integrations |
| GET | `/api/v1/integrations/{id}` | Get integration details |
| POST | `/api/v1/integrations/{id}/enable` | Enable integration |
| POST | `/api/v1/integrations/{id}/disable` | Disable integration |

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
- Evaluate endpoint: 100 requests/minute per agent
- Other endpoints: 60 requests/minute per IP

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
