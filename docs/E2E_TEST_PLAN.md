# End-to-End Test Plan: Snapper Agent Application Firewall

## Overview

This test plan validates Snapper's security enforcement across all subsystems: rule evaluation, multi-tenant organization isolation, threat detection, SIEM event publishing, Prometheus metrics, SSO/SCIM, approval workflows, PII vault, adaptive trust scoring, and the full agent integration pipeline.

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Telegram   │────▶│   OpenClaw   │────▶│   Snapper    │────▶│   Execute    │
│    User      │     │   AI Agent   │     │ Rule Engine  │     │   Action     │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                            │                    │
                            │              ┌─────┴──────┐
                            │              │ ALLOW /     │
                            │              │ DENY /      │     ┌──────────────┐
                            │              │ APPROVAL    │────▶│  SIEM / HEC  │
                            │              └─────┬──────┘     │  Prometheus  │
                            ◀────────────────────┘            │  Threat Det. │
                         (result sent back to user)           └──────────────┘
```

## Current State

| Component | Status | Endpoint |
|-----------|--------|----------|
| Snapper | Running | https://76.13.127.76:8443 |
| OpenClaw | Running | https://76.13.127.76:443 |
| Telegram Bot | Configured | @Snapper_approval_bot |
| Slack Bot | Configured | Socket Mode |
| Integration | Connected | Shell wrapper hooks |
| Auth Mode | Cloud | SELF_HOSTED=false, session/cookie auth |

---

## Test Inventory Summary

### Unit Tests (`tests/`)

62 test files covering all subsystems.

| Test File | Tests | Coverage |
|-----------|-------|----------|
| `test_enterprise.py` | 91 | CEF, webhook/syslog/Splunk, OIDC/SAML/SCIM, metrics, policy-as-code |
| `test_rule_engine.py` | ~50 | All rule evaluators, adaptive trust scoring (23 tests) |
| `test_threat_detector.py` | 48 | 13 signal types, kill chain detection, behavioral baselines |
| `test_ai_providers.py` | ~30 | OpenAI/Anthropic/Gemini SDK wrappers (requires `snapper` package) |
| `test_auth.py` | ~20 | Login, register, password reset, JWT tokens, session management |
| `test_org_scoping.py` | ~15 | Org-scoped agents, rules, vault, cross-org isolation |
| `test_multi_tenant_isolation.py` | ~15 | Cross-org boundary enforcement, resource isolation |
| `test_meta_admin.py` | ~15 | Meta admin auth, provision org, impersonation |
| `test_quotas.py` | ~10 | Plan limits, quota enforcement, 402 responses |
| `test_billing.py` | ~10 | Stripe integration, plan changes, usage |
| `test_rbac.py` | ~10 | Role-based access control, permissions |
| `test_pii_vault.py` | ~20 | AES-256-GCM encryption, token CRUD, domain locking |
| `test_pii_gate.py` | ~15 | PII scanning, approval flow, auto mode |
| `test_traffic_discovery.py` | ~20 | MCP server detection, coverage analysis, known servers |
| `test_slack_bot.py` | ~15 | Slash commands, approval routing, vault flow |
| `test_telegram_callbacks.py` | ~15 | Callback handlers, approval buttons |
| `test_security_research.py` | ~10 | CVE feed, auto-mitigation |
| Other test files | ~600+ | Rate limiter, suggestions, approvals, audit, API keys, etc. |

**Total: ~1,200+ unit tests**

Run: `docker compose exec app pytest tests/ -v`

### Playwright E2E Tests (`tests/e2e/`)

17 test files testing the full web UI with browser automation.

| Test File | Tests | Coverage |
|-----------|-------|----------|
| `test_dashboard.py` | 8 | Dashboard loading, stats tiles, navigation |
| `test_navigation.py` | 14 | Navbar, page titles, responsive, accessibility |
| `test_agents.py` | 15 | Agent registration, OpenClaw modal, platform cards |
| `test_agent_management.py` | 8 | API key, suspend/activate, form validation |
| `test_rules.py` | 7 | Rules page, templates, categories |
| `test_rules_crud.py` | 7 | Create, toggle, delete rules, apply template |
| `test_security.py` | 10 | Security, audit, settings, wizard, help, docs pages |
| `test_integrations.py` | 4 | Integrations page, MCP input, active packs |
| `test_auth_flow.py` | 11 | Login, register, logout, redirect |
| `test_billing_page.py` | 7 | Billing page, plans, usage bars |
| `test_org_management.py` | 9 | Org settings, members, invites |
| `test_wizard.py` | 12 | Setup wizard, agent selection, notifications |
| `test_wizard_new_agents.py` | 7 | Cursor, Windsurf, Cline, Claude Code flows |
| `test_audit.py` | 26 | Audit stats, charts, filters, tabs, pagination |
| `test_forgot_password.py` | 3 | Forgot/reset password pages |
| `test_approvals_page.py` | ~8 | Approvals page, pending/history |
| `test_suggestions.py` | ~5 | Suggestions page, rule suggestions |

**Total: ~168 Playwright tests**

Run: `E2E_BASE_URL=https://76.13.127.76:8443 pytest tests/e2e -v`

### Live E2E Scripts (`scripts/`)

| Script | Tests | Coverage |
|--------|-------|----------|
| `e2e_live_test.sh` | ~93 | All rule evaluators, approval workflow, PII vault, trust scoring, emergency block, audit trail, Slack integration, approval automation, deployment infra |
| `e2e_integrations_test.sh` | ~90 | Traffic discovery, known servers, coverage, rule creation, active packs, curated/generic server rules |
| `e2e_threat_test.sh` | 6 phases | Threat simulator (13 scenarios), backend state, kill chain pipeline, signal coverage, event resolution, config validation |
| `e2e_openclaw_test.sh` | 19 | Full-pipeline agent traffic (browser allow, rate limit, PII, approvals, metadata, emergency block, audit) |
| `e2e_multiuser_test.sh` | ~85 | Multi-tenant: org isolation, RBAC, quotas, invitation flow, team management, billing |

**Note:** All bash E2E scripts auto-authenticate in cloud mode (SELF_HOSTED=false) by registering a test user and using session cookies.

---

## Test Group A: Multi-Tenant Organization Isolation

### A.1 Unit Tests (`tests/test_multi_tenant_isolation.py`)

| # | Test | What It Validates |
|---|------|-------------------|
| A1.1 | Cross-org agent isolation | Org B cannot read/update/delete Org A's agents |
| A1.2 | Cross-org rule isolation | Org B cannot read/update/delete Org A's rules |
| A1.3 | Cross-org vault isolation | Org B cannot access Org A's PII vault entries |
| A1.4 | Cross-org threat isolation | Org B cannot see Org A's threat events |
| A1.5 | Cross-org security isolation | Security issues/recommendations scoped to org |
| A1.6 | Agent creation with org_id | New agents auto-assigned to creator's org |
| A1.7 | Rule creation with org_id | New rules auto-assigned to creator's org |
| A1.8 | Evaluate respects org scoping | Rule engine loads only the agent's org rules |

### A.2 Unit Tests (`tests/test_org_scoping.py`)

| # | Test | What It Validates |
|---|------|-------------------|
| A2.1 | Agents list filtered by org | `GET /agents` returns only current org's agents |
| A2.2 | Rules list filtered by org | `GET /rules` returns only current org's rules |
| A2.3 | Vault entries filtered by org | `GET /vault/entries` returns only current org's entries |
| A2.4 | System rules visible to all | Rules with `organization_id=NULL` visible to all orgs |
| A2.5 | `verify_resource_org` helper | Raises 404 for cross-org, passes for same-org |

### A.3 Per-Org Quota Overrides

| # | Test | What It Validates |
|---|------|-------------------|
| A3.1 | Free plan default limits | 25 agents, 250 rules, 50 vault entries, 5 members, 2 teams |
| A3.2 | Pro plan limits | 10 agents, 100 rules, 50 vault entries, 5 members, 3 teams |
| A3.3 | Enterprise unlimited | -1 for all limits (unlimited) |
| A3.4 | `max_agents_override` | Org-level override takes precedence over plan limit |
| A3.5 | `max_rules_override` | Org-level override takes precedence over plan limit |
| A3.6 | `max_vault_entries_override` | Org-level override takes precedence |
| A3.7 | `max_seats` | Org-level team member override takes precedence |
| A3.8 | 402 on quota exceeded | Returns `{"error": "quota_exceeded", "used": N, "limit": M}` |
| A3.9 | Self-hosted skips quotas | `SELF_HOSTED=true` → no quota enforcement |

---

## Test Group B: Threat Detection Engine

### B.1 Threat Simulator (`scripts/threat_simulator.py`)

13 attack scenarios run against a live Snapper instance:

| # | Scenario | Attack Pattern | Expected Score |
|---|----------|----------------|---------------|
| 1 | `data_exfil` | FILE_READ → NETWORK_SEND kill chain | >=5 |
| 2 | `credential_theft` | CREDENTIAL_ACCESS → NETWORK_SEND | >=5 |
| 3 | `pii_harvest` | 3x PII_OUTBOUND → NETWORK_SEND (needs PII_GATE) | >=5 |
| 4 | `encoded_exfil` | FILE_READ → ENCODING → NETWORK_SEND | >=5 |
| 5 | `privesc_chain` | PRIVESC → FILE_READ → NETWORK_SEND | >=5 |
| 6 | `vault_extraction` | VAULT_PROBE → PII_OUTBOUND (needs PII_GATE) | >=5 |
| 7 | `lotl_attack` | TOOL_ANOMALY → NETWORK_SEND | >=5 |
| 8 | `baseline_deviation` | 20 benign warmup → anomalous tools/destinations | >=1 |
| 9 | `slow_drip` | 20 small network sends with increasing payloads | >=5 |
| 10 | `encoding_stacking` | 5 requests with mixed base64+hex encoding | >=5 |
| 11 | `stego_exfil` | STEGANOGRAPHIC_CONTENT → NETWORK_SEND | >=1 |
| 12 | `signal_storm` | 12 rapid-fire mixed signals (all types) | >=10 |
| 13 | `benign_control` | 11 normal commands (negative test) | <10, 0 events |

### B.2 Threat E2E Wrapper (`scripts/e2e_threat_test.sh`)

6 phases validating the full threat detection pipeline:

| Phase | Tests | What It Validates |
|-------|-------|-------------------|
| 1 | Simulator (13) | All 13 attack scenarios via threat simulator |
| 2 | Backend State (3) | Threat events in DB, kill chain types, summary |
| 3 | Kill Chain Pipeline | Targeted agent → recon → exfil → chain detected |
| 4 | Signal Coverage | All 13 signal types extractable |
| 5 | Event Resolution | Resolve, false-positive, reopen workflow |
| 6 | Config Validation | `THREAT_DETECTION_ENABLED`, thresholds |

### B.3 Unit Tests (`tests/test_threat_detector.py`)

48 unit tests covering:
- 13 signal types (file read, credential access, network send, encoding, PII, privilege escalation, etc.)
- Kill chain detection (7 predefined chains)
- Behavioral baseline deviations
- Composite scoring algorithm
- Air-gapped configuration (AI review disabled by default)
- Celery task integration (9 tests, run in Docker only)

---

## Test Group C: Authentication & Authorization

### C.1 Auth Flow Tests (`tests/test_auth.py`)

| # | Test | What It Validates |
|---|------|-------------------|
| C1.1 | Register creates user + org | Email, password_confirm, auto-org, auto-team |
| C1.2 | Login sets cookies | `snapper_access_token` + `snapper_refresh_token` |
| C1.3 | JWT contains org claim | Token has `org`, `role`, `sub` claims |
| C1.4 | Token refresh works | New access token issued from refresh token |
| C1.5 | Logout clears cookies | Both tokens removed |
| C1.6 | Password reset flow | Request → email → reset with token |
| C1.7 | Email domain validation | Org with `allowed_email_domains` blocks wrong domains |
| C1.8 | Seat limit enforcement | Invitation blocked when `max_seats` exceeded |

### C.2 RBAC Tests (`tests/test_rbac.py`)

| # | Test | What It Validates |
|---|------|-------------------|
| C2.1 | Owner has full access | All endpoints accessible |
| C2.2 | Admin can manage | Agents, rules, vault — not org settings |
| C2.3 | Member read-only | Can view but not create/delete |
| C2.4 | Viewer minimal access | Dashboard and audit only |
| C2.5 | Role escalation blocked | Member cannot promote self to admin |

### C.3 Meta Admin Tests (`tests/test_meta_admin.py`)

| # | Test | What It Validates |
|---|------|-------------------|
| C3.1 | `is_meta_admin` defaults false | New users are not meta admins |
| C3.2 | `require_meta_admin` rejects non-meta | Returns 403 |
| C3.3 | JWT includes `meta` claim | When `is_meta_admin=True` |
| C3.4 | Provision org creates org+team+invite | Full provisioning flow |
| C3.5 | Impersonation issues scoped token | `imp` and `org` claims in JWT |
| C3.6 | Non-meta 403 on all `/meta/*` | All meta endpoints guarded |

### C.4 Playwright Auth Tests (`tests/e2e/test_auth_flow.py`)

11 tests: Login page, register form, logout redirect, session persistence, error messages.

---

## Test Group D: Rule Evaluation Engine

### D.1 Live API Tests (`scripts/e2e_live_test.sh`)

| Phase | Tests | What It Validates |
|-------|-------|-------------------|
| 0 | Environment (5) | Snapper health, Redis, learning mode, test agent, audit baseline |
| 0b | Deployment Infra (8) | GHCR images, Dockerfile targets, CI/CD workflows, setup/deploy scripts |
| 1 | Rule Evaluators (18) | All 18 rule types (command allow/deny, time, rate limit, skill, credential, network, origin, human_in_loop, localhost, file access, version, sandbox, PII gate) |
| 2 | OpenClaw Live (5) | Browser allow, time restriction, rate limit, PII detection, deny-by-default (optional, needs E2E_CHAT_ID) |
| 3 | Approval Workflow (4) | Create approval, poll status, approve, deny |
| 4 | PII Vault (8) | Create entry, detect token, approve+resolve, auto mode, delete, placeholder, label references |
| 4b | Vault Labels (4) | Label create, vault:Label syntax, auto mode resolution, cleanup |
| 4c | Trust Scoring (12) | Default trust 1.0, toggle ON/OFF, reset, rule denials don't reduce trust, rate breaches do |
| 5 | Emergency Block (3) | Block ALL via 4 deny-all rules, verify block, unblock and restore |
| 5b | Slack Bot (15) | Health, Redis prefixes, Slack-owned agent, approval/PII routing |
| 6 | Audit Trail (4) | Count increased, deny/allow entries, violations |
| 7 | Approval Automation (5) | HITL rule, require_approval, approve via API, suggestions, dismiss |

**Auth:** Auto-registers `e2e-live-test@snapper.test` with session cookies.

Run: `ssh root@76.13.127.76 "cd /opt/snapper && bash scripts/e2e_live_test.sh"`

### D.2 Integration & Traffic Discovery (`scripts/e2e_integrations_test.sh`)

| Phase | Tests | What It Validates |
|-------|-------|-------------------|
| 0 | Environment (3) | Snapper health, Redis, test agent creation |
| 1 | Active Packs (5) | Empty list, create server rules, pack structure, agent-scoped packs |
| 2 | Known Servers (4) | 10+ servers, structure, GitHub/Slack in list |
| 3 | Traffic Insights (2) | Structure with required fields, empty state |
| 4 | Traffic Coverage (7) | Uncovered/covered commands, parsed info, CLI/builtin/OpenClaw formats |
| 5 | Rule Creation (8) | Prefix/exact mode, custom name, validation, create-server-rules defaults |
| 6 | Disable Server Rules (7) | Create+disable, active packs verification, re-disable 404, name normalization |
| 7 | Unknown Server (5) | 3 generic defaults, correct actions, evaluation, active packs, disable |
| 8 | Curated Pack (5) | GitHub >3 rules, meaningful names, evaluate read/delete, disable |
| 9 | Traffic Insights Data (8) | Evaluations count, service_groups, command structure, agent-scoped |
| 10 | Pattern Verification (7) | CLI allow, safe command, git, dangerous deny, GitHub MCP read/delete |

**Auth:** Auto-registers `e2e-integ-test@snapper.test` with session cookies.

Run: `ssh root@76.13.127.76 "cd /opt/snapper && bash scripts/e2e_integrations_test.sh"`

### D.3 OpenClaw Full-Pipeline (`scripts/e2e_openclaw_test.sh`)

| Phase | Tests | What It Validates |
|-------|-------|-------------------|
| 0 | Environment (4) | Snapper health, OpenClaw reachable, test agent |
| 1 | Access control (3) | Browser allow, time restriction deny, deny-by-default |
| 2 | Rate limiting (2) | Rate limit exceeded + recovery after window |
| 3 | PII detection (3) | Browser vault token, browser raw PII, auto-mode resolution |
| 4 | Approval workflow (2) | Trigger + approve, trigger + deny |
| 5 | Agent metadata (2) | Version enforcement, origin validation |
| 6 | Emergency block (2) | Block ALL, unblock + verify |
| 7 | Audit trail (1) | Audit count increased |

Run: `E2E_CHAT_ID=<telegram_chat_id> bash scripts/e2e_openclaw_test.sh`

---

## Test Group E: Multi-User & Billing

### E.1 Multi-User E2E (`scripts/e2e_multiuser_test.sh`)

~85 tests covering:
- Organization CRUD (create, update, list, detail)
- Invitation flow (invite, accept, revoke)
- Team management (create, add members, remove)
- RBAC enforcement (owner/admin/member/viewer permissions)
- Org switching (switch-org endpoint, JWT re-issue)
- Billing page (plan display, usage bars)
- Quota enforcement (402 on exceeded limits)

### E.2 Billing & Quota Tests (`tests/test_billing.py`, `tests/test_quotas.py`)

| # | Test | What It Validates |
|---|------|-------------------|
| E2.1 | Plan limits enforced | Agent/rule/vault creation blocked at limit |
| E2.2 | Usage endpoint accurate | `/billing/usage` returns correct counts |
| E2.3 | Plan features gated | Slack integration only on paid plans |
| E2.4 | Org override takes precedence | `max_agents_override` overrides plan limit |
| E2.5 | -1 means unlimited | Enterprise plan has no caps |
| E2.6 | Self-hosted skips quotas | No enforcement in self-hosted mode |

### E.3 Plan Limits (Current)

| Plan | Agents | Rules | Vault | Members | Teams | Price |
|------|--------|-------|-------|---------|-------|-------|
| Free | 25 | 250 | 50 | 5 | 2 | $0/mo |
| Pro | 10 | 100 | 50 | 5 | 3 | $29/mo |
| Enterprise | Unlimited | Unlimited | Unlimited | Unlimited | Unlimited | $99/mo |

**Note:** Meta admin can override any limit per-org via `max_agents_override`, `max_rules_override`, `max_vault_entries_override`, `max_seats`.

---

## Test Group F: Enterprise & Provider Integration

### F.1 Enterprise SSO (Test Group H)

| # | Test | Expected Behavior |
|---|------|-------------------|
| H1 | `GET /auth/saml/metadata/{org}` | Valid SP metadata XML |
| H2 | `GET /auth/oidc/login/{org}` | Redirects to IdP with correct params |
| H3 | `POST /auth/oidc/callback` with valid code | Creates session, sets cookies |
| H4 | `POST /auth/saml/acs/{org}` with valid assertion | Processes SAML, creates session |
| H5 | SSO user auto-provisioned | JIT provisioning into org |
| H6-H10 | Config validation | Unconfigured → 400, setup endpoints, SCIM token |

### F.2 SIEM Integration (Test Group I)

| # | Test | Expected Behavior |
|---|------|-------------------|
| I1-I7 | CEF/Webhook/Syslog/Splunk | Format, signing, auth, delivery |
| I8-I10 | Routing modes | `splunk`, `all`, `none` |
| I11-I13 | `publish_from_audit_log` | Field extraction, org_id, error handling |
| I14 | SIEM wiring coverage | 38+ `publish_from_audit_log` calls across 7+ router files |

### F.3 Prometheus Metrics (Test Group J)

| # | Test | Expected Behavior |
|---|------|-------------------|
| J1-J10 | Metric counters | Rule evals, latency, active agents, PII ops, approvals |
| J11-J13 | Monitoring stack | Prometheus scraping, Grafana accessible, bound to localhost |

### F.4 SCIM 2.0 (Test Group L)

| # | Test | Expected Behavior |
|---|------|-------------------|
| L1-L5 | SCIM CRUD | Create user, list, filter, deactivate, auth |

### F.5 AI Provider SDK (Test Group M)

| # | Test | Expected Behavior |
|---|------|-------------------|
| M1-M3 | CLI agent registration | OpenAI, Anthropic, Gemini agent types |
| M4-M6 | SDK evaluate flow | Allow, deny (SnapperDenied), approval polling |

### F.6 Browser Extension (Test Group N)

| # | Test | Expected Behavior |
|---|------|-------------------|
| N1-N4 | Extension flow | Agent register, eval, PII scan, deny overlay |

---

## Test Group G: Resilience & Chaos

### G.1 Bypass Attempts

| # | Attack | Expected Outcome |
|---|--------|------------------|
| X1 | Base64 encoded command | DENY |
| X2 | Unicode obfuscation | DENY |
| X3 | Command substitution | DENY |
| X4 | Environment variable injection | DENY |
| X5 | Null byte injection | DENY |

### G.2 System Resilience

| # | Test | Expected Outcome |
|---|------|------------------|
| Y1 | Snapper down | Fail-safe: DENY by default |
| Y2 | Redis unavailable | Graceful degradation |
| Y3 | High concurrency (50 requests) | No race conditions |
| Y4 | Malformed request | 400 error, no crash |

---

## SIEM Event Wiring Coverage

All audit log creation sites call `publish_from_audit_log()`:

| File | Sites | Events |
|------|-------|--------|
| `app/routers/agents.py` | 11 | Agent CRUD, suspend, quarantine, key regen, PII purge, trust |
| `app/routers/telegram.py` | 11 | Vault, approval, emergency block, allow rule, PII mode |
| `app/routers/slack.py` | 8 | Vault, emergency block, PII mode, purge, approval |
| `app/routers/rules.py` | 4 | Rule create, template, update, delete |
| `app/routers/vault.py` | 2 | PII entry created, deleted |
| `app/routers/approvals.py` | 1 | Vault token resolution |
| `app/routers/integrations.py` | 1 | Rule from traffic template |

**Verification:** `grep -r 'asyncio.ensure_future(publish_from_audit_log' app/routers/ | wc -l` → 38+

---

## Metric Recording Wiring

| Function | Wired In | Trigger |
|----------|----------|---------|
| `record_pii_operation("create")` | `vault.py` | After PII entry creation |
| `record_pii_operation("delete")` | `vault.py` | After PII entry deletion |
| `record_approval_decision(decision)` | `approvals.py` | After approval grant/deny |
| `set_active_agents(count)` | `main.py`, `agents.py` | Startup + agent create/delete |
| `record_webhook_delivery(success)` | `webhook_delivery.py` | After delivery attempt |
| `record_siem_event(output, success)` | `event_publisher.py` | After syslog/webhook/Splunk |

---

## Execution Checklist

### Pre-requisites
- [ ] Docker containers running (app, postgres, redis, celery-worker, celery-beat, caddy)
- [ ] `jq` installed on test host
- [ ] Playwright + Chromium installed for browser E2E (`pip install playwright pytest-playwright && playwright install chromium`)
- [ ] `email-validator` installed for Playwright (`pip install email-validator`)

### Unit Tests
- [ ] Run `docker compose exec app pytest tests/ -v` — ~1,200+ tests
- [ ] Expected: ~1,200 pass, ~40 skip (Celery-dependent, SDK package)

### Playwright E2E Tests
- [ ] Run `E2E_BASE_URL=https://76.13.127.76:8443 pytest tests/e2e -v` — ~168 tests
- [ ] Expected: ~160+ pass, 2 skipped by design (integrations search/enable)

### Live API E2E Tests
- [ ] Run `bash scripts/e2e_live_test.sh` — ~93 tests across 8 phases
- [ ] Run `bash scripts/e2e_integrations_test.sh` — ~90 tests across 11 phases
- [ ] Run `bash scripts/e2e_threat_test.sh` — 6 phases (13 simulator scenarios)
- [ ] Verify all pass (Phase 2 skipped if no E2E_CHAT_ID, Phase 5b needs Slack)

### Multi-User E2E Tests
- [ ] Run `bash scripts/e2e_multiuser_test.sh` — ~85 tests
- [ ] Verify org isolation, RBAC, quotas

### OpenClaw Full-Pipeline Tests
- [ ] Run `E2E_CHAT_ID=<chat_id> bash scripts/e2e_openclaw_test.sh` — 19 tests
- [ ] Verify 19/19 pass

### Sign-off
- [ ] All automated tests pass (unit + Playwright + live E2E + integrations + threat + multiuser)
- [ ] SIEM wiring verified (38+ sites)
- [ ] Multi-tenant isolation verified (cross-org boundaries enforced)
- [ ] Threat detection operational (13/13 scenarios, kill chains detected)
- [ ] Per-org quota overrides working (meta admin can customize limits)
- [ ] No security bypasses found
- [ ] Performance targets met (< 50ms p95 rule evaluation)
- [ ] Documentation updated
