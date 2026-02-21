# Enterprise Deployment Guide

This guide covers Snapper's enterprise features for organizations deploying at scale.

## Table of Contents

- [Kubernetes Deployment](#kubernetes-deployment)
- [SSO Configuration](#sso-configuration)
- [SCIM User Provisioning](#scim-user-provisioning)
- [SIEM Integration](#siem-integration)
- [Observability](#observability)
- [Policy-as-Code](#policy-as-code)
- [Webhook Events](#webhook-events)
- [Multi-Tenant Architecture](#multi-tenant-architecture)

---

## Kubernetes Deployment

Snapper ships a Helm chart in `charts/snapper/` with four deployment profiles.

### Installation

```bash
# Add Snapper Helm repo (or use local chart)
helm install snapper ./charts/snapper \
  --namespace snapper \
  --create-namespace \
  -f values-production.yaml
```

### Helm Values Reference

| Key | Default | Description |
|-----|---------|-------------|
| `replicaCount` | `2` | Number of app replicas |
| `image.repository` | `ghcr.io/jmckinley/snapper` | Container image |
| `image.tag` | `latest` | Image tag |
| `postgresql.enabled` | `true` | Deploy PostgreSQL subchart |
| `redis.enabled` | `true` | Deploy Redis subchart |
| `ingress.enabled` | `false` | Enable Kubernetes Ingress |
| `ingress.tls` | `[]` | TLS configuration |
| `resources.requests.memory` | `256Mi` | Memory request |
| `resources.limits.memory` | `512Mi` | Memory limit |
| `env.SECRET_KEY` | Required | Encryption key for PII vault |
| `env.DATABASE_URL` | Auto | PostgreSQL connection string |
| `env.REDIS_URL` | Auto | Redis connection string |

### Deployment Profiles

**Minimal** — Single replica, embedded PostgreSQL and Redis:
```yaml
replicaCount: 1
postgresql:
  enabled: true
  persistence:
    size: 5Gi
redis:
  enabled: true
```

**Standard** — HA with 2 replicas, external databases:
```yaml
replicaCount: 2
postgresql:
  enabled: false
env:
  DATABASE_URL: postgresql+asyncpg://user:pass@rds-instance:5432/snapper
  REDIS_URL: redis://elasticache-instance:6379/0
```

**Enterprise** — Full HA, SSO, SIEM, metrics:
```yaml
replicaCount: 3
env:
  SAML_ENABLED: "true"
  SIEM_ENABLED: "true"
  SYSLOG_HOST: siem.corp.example.com
  SYSLOG_PORT: "514"
metrics:
  enabled: true
  serviceMonitor: true
```

**Air-Gapped** — No external network access:
```yaml
image:
  pullPolicy: Never  # Pre-loaded image
env:
  SELF_HOSTED: "true"
  REGISTRATION_ENABLED: "false"
```

### Secrets Management

```bash
kubectl create secret generic snapper-secrets \
  --namespace snapper \
  --from-literal=SECRET_KEY=$(openssl rand -hex 32) \
  --from-literal=DATABASE_URL=postgresql+asyncpg://... \
  --from-literal=TELEGRAM_BOT_TOKEN=... \
  --from-literal=SLACK_BOT_TOKEN=...
```

---

## SSO Configuration

Snapper supports SAML 2.0 and OIDC for enterprise single sign-on.

### SAML 2.0

Configure in your organization settings (`/org/settings` or via API):

| Setting | Description |
|---------|-------------|
| `saml_idp_entity_id` | IdP Entity ID (e.g., `https://login.okta.com/...`) |
| `saml_idp_sso_url` | IdP SSO URL |
| `saml_idp_x509_cert` | IdP X.509 certificate (PEM format) |

**Endpoints:**
- SP Metadata: `GET /auth/saml/metadata/{org_slug}`
- Login: `GET /auth/saml/login/{org_slug}`
- ACS (callback): `POST /auth/saml/acs/{org_slug}`

#### Okta Setup

1. Create a SAML 2.0 application in Okta
2. Set Single Sign-On URL to `https://snapper.example.com/auth/saml/acs/your-org`
3. Set Audience URI to `https://snapper.example.com/auth/saml/metadata/your-org`
4. Map attributes: `email` (required), `firstName`, `lastName`
5. Copy IdP Entity ID, SSO URL, and X.509 cert to Snapper org settings

#### Entra ID (Azure AD) Setup

1. Register enterprise application > SAML SSO
2. Set Reply URL to `https://snapper.example.com/auth/saml/acs/your-org`
3. Set Identifier to `https://snapper.example.com/auth/saml/metadata/your-org`
4. Download Federation Metadata XML, extract IdP values

### OIDC (OpenID Connect)

| Setting | Description |
|---------|-------------|
| `oidc_issuer` | Issuer URL (e.g., `https://accounts.google.com`) |
| `oidc_client_id` | OAuth Client ID |
| `oidc_client_secret` | OAuth Client Secret |
| `oidc_scopes` | Scopes (default: `openid email profile`) |
| `oidc_provider` | Provider hint (`okta`, `google`, `entra`) |

**Endpoints:**
- Login: `GET /auth/oidc/login/{org_slug}`
- Callback: `GET /auth/oidc/callback/{org_slug}`

#### Google Workspace

1. Create OAuth 2.0 client in Google Cloud Console
2. Add authorized redirect URI: `https://snapper.example.com/auth/oidc/callback/your-org`
3. Set issuer to `https://accounts.google.com`

### JIT Provisioning

Both SAML and OIDC support Just-In-Time user provisioning:
- New users are auto-created on first SSO login
- Users are added to the organization with `member` role
- Email is used as the unique identifier

---

## SCIM User Provisioning

SCIM 2.0 endpoints enable automatic user lifecycle management.

**Base URL:** `https://snapper.example.com/scim/v2`

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/Users` | List users (with pagination + filtering) |
| `GET` | `/Users/{id}` | Get single user |
| `POST` | `/Users` | Create user |
| `PUT` | `/Users/{id}` | Update user |
| `PATCH` | `/Users/{id}` | Partial update |
| `DELETE` | `/Users/{id}` | Deactivate user |

### Authentication

SCIM endpoints require a Bearer token:
```
Authorization: Bearer <scim-token>
```

Configure the SCIM token in org settings (`scim_bearer_token`).

### User Schema

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "user@example.com",
  "name": {
    "givenName": "Jane",
    "familyName": "Doe"
  },
  "emails": [
    { "value": "user@example.com", "primary": true }
  ],
  "active": true
}
```

### Okta SCIM Setup

1. In Okta app > Provisioning > Configure API Integration
2. Base URL: `https://snapper.example.com/scim/v2`
3. API Token: your SCIM bearer token
4. Enable: Create Users, Update User Attributes, Deactivate Users

---

## SIEM Integration

Snapper publishes security events in CEF (Common Event Format) via syslog and webhooks.

### CEF Format

```
CEF:0|Snapper|AAF|1.0|103|Request Denied|5|dvchost=agent-1 msg=Blocked by denylist src=192.168.1.1 cs1=rule-uuid cs1Label=RuleID
```

**Event IDs:**

| ID | Name | CEF Severity |
|----|------|-------------|
| 100 | request_allowed | 1 (Low) |
| 103 | request_denied | 5 (Medium) |
| 104 | approval_required | 3 (Low) |
| 200 | rule_created | 3 (Low) |
| 201 | rule_updated | 3 (Low) |
| 202 | rule_deleted | 5 (Medium) |
| 300 | agent_registered | 3 (Low) |
| 400 | security_alert | 10 (Critical) |
| 401 | pii_detected | 7 (High) |

### Syslog Configuration

```env
SIEM_ENABLED=true
SYSLOG_HOST=siem.corp.example.com
SYSLOG_PORT=514
SYSLOG_PROTOCOL=udp  # or tcp
SYSLOG_FACILITY=local0
```

### Splunk Integration

1. Configure a UDP/TCP input on port 514
2. Set sourcetype to `cef`
3. Point `SYSLOG_HOST` to your Splunk forwarder

### QRadar Integration

1. Add log source: type = Universal CEF
2. Protocol = Syslog
3. Log Source Identifier = Snapper

### Microsoft Sentinel

1. Deploy CEF connector via Azure Monitor Agent
2. Point syslog to the connector VM
3. CEF events appear in `CommonSecurityLog` table

---

## Observability

### Prometheus Metrics

Snapper exposes metrics at `GET /metrics` in Prometheus text format.

**Available Metrics:**

| Metric | Type | Description |
|--------|------|-------------|
| `snapper_http_requests_total` | Counter | HTTP requests by method, path, status |
| `snapper_http_request_duration_seconds` | Histogram | Request latency |
| `snapper_rule_evaluations_total` | Counter | Rule evaluations by type and decision |
| `snapper_rule_evaluation_duration_seconds` | Histogram | Evaluation latency |
| `snapper_active_agents` | Gauge | Number of active agents |
| `snapper_pii_operations_total` | Counter | PII vault operations |
| `snapper_approval_decisions_total` | Counter | Approval decisions |
| `snapper_approval_latency_seconds` | Histogram | Time to approval decision |

### Grafana Dashboard

Import the included dashboard from `charts/snapper/grafana-dashboard.json`:

1. Grafana > Dashboards > Import
2. Upload JSON file or paste contents
3. Select Prometheus data source

### Alerting Rules

Example Prometheus alerting rules:

```yaml
groups:
  - name: snapper
    rules:
      - alert: HighDenialRate
        expr: rate(snapper_rule_evaluations_total{decision="deny"}[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High denial rate detected"

      - alert: SnapperDown
        expr: up{job="snapper"} == 0
        for: 1m
        labels:
          severity: critical
```

---

## Policy-as-Code

Export and import security rules as YAML for GitOps workflows.

### Export Rules

```bash
curl -X POST https://snapper.example.com/api/v1/rules/export \
  -H "Content-Type: application/json" \
  -d '{"format": "yaml", "include_global": true}'
```

### YAML Schema

```yaml
version: "1"
rules:
  - name: Block credential access
    type: command_denylist
    action: deny
    priority: 100
    active: true
    parameters:
      patterns:
        - "**/.env"
        - "**/credentials*"
    agent: "*"
    tags:
      - security
      - credentials
```

### Import Rules

```bash
curl -X POST https://snapper.example.com/api/v1/rules/import \
  -H "Content-Type: application/json" \
  -d '{
    "rules": [...],
    "overwrite_existing": false,
    "dry_run": true
  }'
```

### GitOps CI/CD Workflow

```yaml
# .github/workflows/snapper-policy.yml
name: Sync Snapper Policy
on:
  push:
    paths:
      - 'security/snapper-rules.yaml'
    branches: [main]

jobs:
  sync:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Dry run
        run: |
          curl -X POST $SNAPPER_URL/api/v1/rules/sync \
            -H "Authorization: Bearer $SNAPPER_API_KEY" \
            -H "Content-Type: application/json" \
            -d "{\"yaml\": $(cat security/snapper-rules.yaml | jq -Rs .), \"dry_run\": true}"
      - name: Apply
        run: |
          curl -X POST $SNAPPER_URL/api/v1/rules/sync \
            -H "Authorization: Bearer $SNAPPER_API_KEY" \
            -H "Content-Type: application/json" \
            -d "{\"yaml\": $(cat security/snapper-rules.yaml | jq -Rs .), \"dry_run\": false}"
```

---

## Webhook Events

Subscribe to Snapper events via webhooks with HMAC signature verification.

### Create Webhook

```bash
curl -X POST https://snapper.example.com/api/v1/webhooks \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://hooks.example.com/snapper",
    "secret": "your-webhook-secret",
    "events": ["request_denied", "security_alert", "pii_detected"],
    "active": true
  }'
```

### Event Types

| Event | Trigger |
|-------|---------|
| `request_allowed` | Tool call allowed |
| `request_denied` | Tool call denied |
| `approval_required` | Approval request created |
| `approval_decided` | Approval granted or denied |
| `rule_created` | New rule created |
| `rule_updated` | Rule modified |
| `rule_deleted` | Rule deleted |
| `agent_registered` | New agent registered |
| `security_alert` | Security issue detected |
| `pii_detected` | PII found in tool call |

### Payload Format

```json
{
  "event": "request_denied",
  "timestamp": "2026-02-16T12:00:00Z",
  "severity": "warning",
  "agent_id": "agent-uuid",
  "organization_id": "org-uuid",
  "data": {
    "tool_name": "bash",
    "command": "cat /etc/passwd",
    "rule_name": "block-credential-access",
    "reason": "Credential file access blocked"
  }
}
```

### HMAC Verification

```python
import hashlib
import hmac

def verify_webhook(payload_body: bytes, signature: str, secret: str) -> bool:
    expected = "sha256=" + hmac.new(
        secret.encode(),
        payload_body,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)

# In your webhook handler:
sig = request.headers.get("X-Snapper-Signature")
if not verify_webhook(request.body, sig, WEBHOOK_SECRET):
    return 401
```

### Retry Behavior

- Failed deliveries are retried up to 3 times
- Retry intervals: 10s, 60s, 300s
- Webhooks are deactivated after 10 consecutive failures

---

## MCP Server Catalog & Auto-Classification

Snapper maintains a catalog of 27,000+ MCP servers synced daily from public registries (Glama, Smithery, PulseMCP, mcp.run, and the official MCP servers list). Each server is automatically classified into one of **13 security categories** using a 3-tier classification engine:

1. **Tier 1 — Name pattern matching:** Compiled regex against server names (<1ms)
2. **Tier 2 — Description keyword scoring:** High-confidence keywords score 3 points, medium 1 point, threshold of 3
3. **Tier 3 — BGE embedding similarity:** BAAI/bge-small-en-v1.5 model (~5ms/server, runs as a Celery background task)

### Security Categories

| Category | Policy |
|----------|--------|
| `data_store` | Deny bulk export, deny drop/truncate, approve writes |
| `code_repository` | Allow reads, approve commits/merges, deny force-push/delete-branch |
| `filesystem` | Allow reads, approve writes, deny deletion, block sensitive paths |
| `shell_exec` | Allowlist safe reads, deny rm/sudo/pipes |
| `browser_automation` | Allow navigate/screenshot, approve form fills, PII gate |
| `network_http` | Allow GET/search, approve POST, deny internal IPs |
| `communication` | Allow reads, approve sends, deny admin/delete |
| `cloud_infra` | Allow describe/list, approve create, deny terminate/delete |
| `identity_auth` | Deny most, approve reads only |
| `payment_finance` | Require approval for ALL, deny refunds/reversals |
| `ai_model` | Allow queries, approve training, deny model deletion |
| `monitoring` | Allow reads, approve config changes, deny data deletion |
| `general` | Allow reads, approve writes, deny destructive (fallback) |

When an agent first calls a tool from an unrecognized MCP server, Snapper auto-applies the category-based rule template (3-5 rules per category), deduplicates via Redis, and enforces a per-org cap of 200 auto-created rules.

---

## Bot Commands (Telegram & Slack)

Snapper provides full bot integration for both Telegram and Slack, with feature parity between the two.

### Slack Commands

All Slack commands use the `/snapper-` prefix to avoid conflicts with other apps:

| Command | Description |
|---------|-------------|
| `/snapper-status` | Check Snapper connection status |
| `/snapper-rules` | View active security rules |
| `/snapper-test run <cmd>` | Test if a command would be allowed |
| `/snapper-pending` | List pending approval requests |
| `/snapper-vault list\|add\|delete\|domains` | Manage encrypted PII vault entries |
| `/snapper-trust` | View/reset/enable/disable agent trust scores |
| `/snapper-block` | Emergency block ALL agent actions |
| `/snapper-unblock` | Resume normal operation |
| `/snapper-pii` | View/set PII gate mode (protected/auto) |
| `/snapper-purge` | Clean up bot messages in channel |
| `/snapper-help` | Show all available commands |
| `/snapper-dashboard` | Open the Snapper web dashboard |

### Telegram Commands

Telegram bot uses the same command set without the `snapper-` prefix: `/rules`, `/test`, `/vault`, `/trust`, `/block`, `/unblock`, `/pii`, `/purge`, `/help`, `/start`.

### Alert Routing

Approval notifications are routed based on the agent's `owner_chat_id`:
- Numeric ID (e.g., `123456`) -> Telegram DM with inline Approve/Deny buttons
- `U` prefix (e.g., `U0ACYA78DSR`) -> Slack DM with action buttons
- Org webhooks -> HTTP POST to configured URL

---

## Multi-Tenant Architecture

### Organization Scoping

All data is scoped to organizations:

- **Rules** — Each org has its own rule set (plus system-wide rules)
- **Agents** — Agents belong to a single organization
- **Audit logs** — Filtered by organization
- **PII vault** — Entries scoped by org and owner
- **Users** — Members of one or more organizations

### Team Permissions

| Role | View | Create/Edit | Delete | Admin |
|------|------|-------------|--------|-------|
| Viewer | Yes | No | No | No |
| Member | Yes | Yes | No | No |
| Admin | Yes | Yes | Yes | Yes |
| Owner | Yes | Yes | Yes | Yes + billing |

### Data Isolation

- Database queries always include `organization_id` filter
- API responses only include data from the authenticated user's org
- Cross-org data access is not possible through the API
- System-wide rules (no `agent_id`) are read-only for non-admin users

---

## Platform Administration (Meta Admin)

For cloud deployments, Snapper includes a platform administration layer for the service operator.

### Meta Admin Dashboard

The meta admin dashboard (`/admin`) provides cross-org visibility:

- **Platform stats** — total organizations, agents, users, evaluations (24h), active threats
- **Organization listing** — paginated with member/agent/rule counts, plan, last activity
- **Org detail** — members, agents, rules, feature flags, quota overrides
- **Performance metrics** — p50/p95/p99 evaluation latency, throughput (requires Prometheus)
- **Hourly evaluation heatmap** — 24-bucket activity visualization
- **Agent funnel** — registered → active → evaluating conversion metrics

### Organization Provisioning

Meta admins can provision new organizations:

```
POST /api/v1/meta/provision
{
  "name": "Acme Corp",
  "plan": "pro",
  "admin_email": "admin@acme.com"
}
```

This creates the organization, default team, and sends an admin invitation — all in one call.

### Impersonation

For debugging customer issues, meta admins can impersonate an organization:

```
POST /api/v1/meta/impersonate
{ "organization_id": "uuid" }
```

Returns a scoped JWT with `imp` (impersonator user ID) and `org` (target org) claims. All actions during impersonation are audit-logged with `META_IMPERSONATION_START` and `META_IMPERSONATION_STOP` events.

### Feature Flags

Per-org feature toggles:

```
POST /api/v1/meta/orgs/{id}/features
{ "slack_enabled": true, "threat_detection_enabled": true }
```

### Quota Overrides

Override plan limits per organization:

| Override | Description |
|----------|-------------|
| `max_agents_override` | Override plan's agent limit |
| `max_rules_override` | Override plan's rule limit |
| `max_vault_entries_override` | Override plan's vault entry limit |
| `max_seats` | Override plan's team member limit |

Set to `-1` for unlimited. Overrides take precedence over plan defaults.

### Access Control

- Only users with `is_meta_admin=True` can access `/meta/*` endpoints
- JWT includes `meta: true` claim for meta admins
- All meta admin actions generate audit events (`META_*` action types)
- Non-meta-admin requests return 403 Forbidden
