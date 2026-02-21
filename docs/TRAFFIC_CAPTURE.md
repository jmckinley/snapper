# How Snapper Captures Agent Traffic

## Overview

Snapper is an inline policy enforcement layer that sits between AI agents and the actions they take. Every tool call, shell command, file access, and network request passes through Snapper's evaluate endpoint before execution. This document explains the traffic capture architecture, integration methods, and how Snapper handles agents it has never seen before.

---

## The Evaluate Endpoint

All traffic flows through a single API endpoint:

```
POST /api/v1/rules/evaluate
```

Every agent integration — shell hooks, plugins, browser extensions, SDK wrappers — ultimately calls this endpoint with a request like:

```json
{
  "agent_id": "openclaw-main",
  "request_type": "command",
  "command": "rm -rf /tmp/build",
  "tool_name": "bash",
  "tool_input": {},
  "file_path": null,
  "url": null,
  "origin": null,
  "skill_id": null
}
```

Snapper returns a decision:

```json
{
  "decision": "deny",
  "reason": "Blocked by rule: Dangerous Commands Denylist",
  "matched_rule_id": "a1b2c3d4-...",
  "matched_rule_name": "Dangerous Commands Denylist"
}
```

Three possible decisions:
- **allow** — proceed with execution
- **deny** — block the action entirely
- **require_approval** — pause execution, notify a human (Telegram or Slack), wait for approve/deny

---

## Integration Methods

Snapper captures traffic through four integration points, each suited to different agent architectures:

### 1. Shell Wrapper Hook (CLI Agents)

For agents that execute shell commands (OpenClaw, Claude Code, Cursor, etc.), Snapper provides a shell wrapper (`scripts/openclaw-hooks/snapper-shell.sh`) that replaces the agent's shell:

```
Agent wants to run "git push origin main"
    │
    ▼
snapper-shell.sh intercepts the command
    │
    ▼
POST /api/v1/rules/evaluate
  { agent_id, request_type: "command", command: "git push origin main" }
    │
    ├── allow    → exec /bin/bash -c "git push origin main"
    ├── deny     → echo "BLOCKED by Snapper" >&2; exit 1
    └── approval → echo "Approval required — check Telegram" >&2; exit 1
```

The wrapper is a 32-line bash script. It extracts the command from `bash -c "$CMD"` invocations, calls the evaluate endpoint with the agent's API key (`X-API-Key` header), and either executes or blocks based on the response.

**Configuration:** Two environment variables:
- `SNAPPER_URL` — Snapper backend (default `http://127.0.0.1:8000`)
- `SNAPPER_API_KEY` — agent's API key (`snp_*` format)

### 2. Plugin Hook (OpenClaw)

The `snapper-guard` plugin (`plugins/snapper-guard/index.ts`) registers a `before_tool_call` hook with OpenClaw's plugin system. It intercepts tool calls at the framework level rather than the shell level:

```
OpenClaw decides to call browser.navigate("https://example.com")
    │
    ▼
snapper-guard before_tool_call hook fires
    │
    ▼
POST /api/v1/rules/evaluate
  { agent_id, request_type: "browser_action", tool_name: "browser", tool_input: {...} }
    │
    ├── allow    → tool call proceeds (with vault token resolution if needed)
    ├── deny     → return { block: true, blockReason: "..." }
    └── approval → poll /approvals/{id}/status every 5s until approved/denied/expired
```

**Watched tools:** `browser`, `exec`, `bash`, `write`

**PII vault integration:** When the tool input contains vault tokens (`{{SNAPPER_VAULT:abcdef1234...}}`), the plugin automatically replaces them with decrypted values from the evaluate response's `resolved_data` field. The agent never sees the real PII — it works with tokens, and Snapper resolves them at execution time.

### 3. Browser Extension (Web-Based AI Agents)

For AI agents accessed through web UIs (ChatGPT, Claude.ai, Gemini, Copilot, Grok), a Chrome extension intercepts tool calls via DOM observation and fetch monkey-patching:

```
User sends message to ChatGPT, which triggers Code Interpreter
    │
    ▼
Content script (content/chatgpt.js) detects tool call via DOM mutation
    │
    ▼
Sends message to background service worker (background.js)
    │
    ▼
POST /api/v1/rules/evaluate
  { agent_id: "browser-extension", tool_name: "code_interpreter", tool_input: {...} }
    │
    ├── allow    → cached for 5 minutes, tool proceeds
    ├── deny     → overlay injected into page: "Blocked by Snapper"
    └── approval → poll until resolved, show "Waiting for Approval" banner
```

**Content scripts** for each platform:
- `content/chatgpt.js` — ChatGPT Code Interpreter, web browsing, DALL-E, plugins
- `content/claude.js` — Claude.ai tool use
- `content/copilot.js` — Microsoft Copilot
- `content/gemini.js` — Google Gemini
- `content/grok.js` — xAI Grok

**PII scanning:** A shared `content/pii-scanner.js` scans textarea content before submission, detecting 20+ PII patterns (credit cards, SSNs, emails, phone numbers, API keys, private keys, etc.). Can warn or block depending on configuration.

**Enterprise deployment:** Configuration can be pushed via Chrome managed storage (enterprise admin policy), so IT can set `snapper_url` and `snapper_api_key` without user action.

**Fail mode:** Configurable — `closed` (deny on Snapper unreachable) or `open` (allow on Snapper unreachable).

### 4. Direct API Call (Any SDK)

Any agent framework can integrate by calling the evaluate endpoint directly over HTTP:

```python
import httpx

resp = httpx.post(
    "https://snapper.example.com/api/v1/rules/evaluate",
    headers={"X-API-Key": "snp_abc123..."},
    json={
        "agent_id": "my-agent",
        "request_type": "command",
        "command": "cat /etc/passwd",
    },
)
decision = resp.json()["decision"]  # "deny"
```

This is how SDK wrappers for OpenAI, Anthropic, and Gemini integrate — they wrap the SDK's tool execution with a Snapper evaluate call.

---

## What Gets Captured

Every evaluate request is logged as an audit event, creating a complete traffic record:

| Request Type | Fields Used | What It Captures |
|--------------|-------------|------------------|
| `command` | `command` | Shell commands (`ls`, `git push`, `rm -rf`) |
| `file_access` | `file_path`, `file_operation` | File reads and writes |
| `network` | `url` | Outbound HTTP/HTTPS requests |
| `tool` | `tool_name`, `tool_input` | MCP tool calls (`mcp__github__create_issue`) |
| `skill` | `skill_id` | Agent skill/plugin invocations |
| `browser_action` | `tool_name`, `tool_input` | Browser automation (navigate, click, type) |

**Inbound traffic** (commands, tool calls coming from the agent) and **outbound traffic** (network egress, file writes going to external systems) both flow through the same endpoint. The rule engine applies different rule types based on the request:

- **Inbound:** command allowlist/denylist, skill allowlist/denylist, human-in-loop, credential protection, PII gate
- **Outbound:** network egress rules, file access rules, origin validation

---

## How Rule Evaluation Works

When a request arrives, the rule engine:

1. **Loads rules** for the agent (cached in Redis with 10s TTL):
   - Global rules (`agent_id = NULL`) that apply to all agents
   - Agent-specific rules
   - Sorted by priority (highest first)

2. **Evaluates each rule** in priority order against 15 rule types:
   - Command allowlist/denylist (regex pattern matching)
   - Rate limiting (sliding window with adaptive trust)
   - Credential protection (blocks `.env`, `.pem`, `.key`, `.ssh/` access)
   - Network egress (allow/deny by host/domain)
   - Time restrictions (business hours only)
   - File access controls (path-based allow/deny)
   - PII gate (scans for vault tokens and raw PII)
   - Human-in-loop (pattern match → require approval)
   - Origin/version/sandbox enforcement
   - Skill allow/denylist

3. **Short-circuits on DENY** — the first matching DENY rule stops evaluation immediately. Higher-priority ALLOW rules prevent lower-priority REQUIRE_APPROVAL from triggering.

4. **Threat score override** — if the background threat detector has scored this agent >= 80, the decision is overridden to DENY regardless of rules. Score 60-79 triggers REQUIRE_APPROVAL.

5. **Learning mode fallback** — if no ALLOW rule matches and `LEARNING_MODE=true`, the request is allowed but logged with `would_have_blocked: true`.

---

## Handling Unknown Agents

Snapper does **not** auto-register unknown agents. When an evaluate request arrives with an unrecognized `agent_id` or `external_id`, Snapper returns:

```json
{
  "decision": "deny",
  "reason": "Unknown agent: mystery-agent-42"
}
```

This is a deliberate security design — deny-by-default for unregistered agents.

### Agent Registration

Agents must be explicitly registered before their traffic is evaluated:

```
POST /api/v1/agents
{
  "name": "My Claude Code Agent",
  "external_id": "claude-code-prod-1",
  "agent_type": "claude-code",
  "trust_level": "standard",
  "owner_chat_id": "123456789"
}
```

Registration returns an API key (`snp_*` format) that the agent uses for authentication.

**Registration channels:**
- **Dashboard UI** — register via web form with agent type selection (OpenClaw, Claude Code, Cursor, Windsurf, Cline, Custom)
- **Setup wizard** — guided first-run flow with config snippet generation
- **API** — direct `POST /api/v1/agents`
- **Telegram/Slack bot** — send commands to register agents

### Onboarding a New Agent: The Workflow

```
1. Register agent         → POST /api/v1/agents (get API key)
2. Configure hook         → Set SNAPPER_URL + SNAPPER_API_KEY in agent environment
3. Enable learning mode   → LEARNING_MODE=true (allow all, log everything)
4. Agent runs normally    → All traffic logged to audit_logs table
5. Traffic discovery      → GET /traffic/insights (see what tools/servers the agent uses)
6. Create rules           → POST /traffic/create-server-rules (auto-generate from traffic)
7. Review & enforce       → Set LEARNING_MODE=false, DENY_BY_DEFAULT=true
```

### Learning Mode: Safe Onboarding

Learning mode (`LEARNING_MODE=true`) is the key to handling new agents safely. When enabled:

- All traffic is **allowed** regardless of rules
- Every request that **would have been blocked** is logged with `would_have_blocked: true`
- The audit trail shows exactly what the agent does and what rules would fire
- No disruption to agent operations while policies are being tuned

This lets operators observe an agent's behavior before writing rules for it.

### Traffic Discovery: Understanding What an Agent Does

After an agent runs for a while in learning mode, the traffic discovery service (`app/services/traffic_discovery.py`) parses audit logs to build a picture of the agent's behavior:

```
GET /api/v1/integrations/traffic/insights?agent_id=<uuid>&hours=168
```

Returns grouped traffic patterns:

```json
{
  "service_groups": [
    {
      "server_key": "github",
      "display_name": "GitHub (MCP)",
      "source_type": "mcp",
      "commands": [
        {"command": "mcp__github__create_issue", "count": 45, "covered": false},
        {"command": "mcp__github__list_repos", "count": 120, "covered": true}
      ]
    },
    {
      "server_key": "git",
      "display_name": "git",
      "source_type": "cli",
      "commands": [
        {"command": "git push", "count": 30, "covered": false},
        {"command": "git status", "count": 200, "covered": true}
      ]
    }
  ]
}
```

The discovery service recognizes 40+ known MCP servers (GitHub, Slack, Gmail, AWS, Docker, Stripe, etc.) and correctly parses tool name formats:
- **MCP format:** `mcp__github__create_issue` → server "github", tool "create_issue"
- **CLI format:** `git push origin main` → server "git", command "push"
- **Built-in tools:** `browser`, `exec`, `bash`, `write`, `read`

### Auto-Generating Rules from Traffic

Once traffic patterns are visible, operators can auto-generate rules:

```
POST /api/v1/integrations/traffic/create-server-rules
{ "server_name": "github", "agent_id": "<uuid>" }
```

For **known servers** (GitHub, Slack, etc.), this creates curated rules with specialized patterns — e.g., allow reads, require approval for writes, deny destructive actions like `delete_repo`.

For **unknown servers**, it creates 3 generic defaults:
1. Allow read operations
2. Require approval for write operations
3. Deny destructive operations

### Coverage Analysis

Check which commands have rules and which don't:

```
GET /api/v1/integrations/traffic/coverage?command=mcp__github__delete_repo
```

Returns whether the command is covered by any active rule, and which rules match.

---

## Traffic Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AI AGENT                                     │
│  (OpenClaw, Claude Code, Cursor, ChatGPT, Gemini, etc.)           │
└───────────────┬─────────────────────────────────┬───────────────────┘
                │                                 │
         Shell commands                    MCP tool calls
         File access                       Browser actions
         Network requests                  Skill invocations
                │                                 │
                ▼                                 ▼
┌──────────────────────┐            ┌──────────────────────┐
│   Shell Wrapper      │            │   Plugin / Extension │
│   snapper-shell.sh   │            │   snapper-guard.ts   │
│   (bash hook)        │            │   background.js      │
└──────────┬───────────┘            └──────────┬───────────┘
           │                                   │
           └─────────────┬─────────────────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │  POST /evaluate     │
              │  X-API-Key: snp_... │
              │  { agent_id,        │
              │    request_type,    │
              │    command,         │
              │    tool_name, ... } │
              └──────────┬──────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │   Agent Lookup      │
              │   (API key or       │
              │    external_id)     │
              │                     │
              │   Unknown? → DENY   │
              │   Suspended? → DENY │
              └──────────┬──────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │   Rule Engine       │
              │                     │
              │   Load rules        │◄──── Redis cache (10s TTL)
              │   (global + agent)  │
              │   Sort by priority  │
              │                     │
              │   For each rule:    │
              │   ├─ DENY? stop     │
              │   ├─ APPROVAL? flag │
              │   ├─ ALLOW? note    │
              │   └─ next rule      │
              │                     │
              │   Threat override   │◄──── Background threat score
              │   Learning mode     │      (>= 80 → DENY)
              └──────────┬──────────┘
                         │
                    ┌────┼────┐
                    │    │    │
                    ▼    ▼    ▼
                 ALLOW  DENY  REQUIRE_APPROVAL
                    │    │         │
                    │    │         ├─→ Telegram notification
                    │    │         ├─→ Slack notification
                    │    │         └─→ Poll /approvals/{id}/status
                    │    │
                    ▼    ▼
              ┌─────────────────────┐
              │   Audit Log         │
              │   (every decision)  │
              │                     │
              │   + Threat signals  │──→ Redis Stream → Celery worker
              │   + SIEM events     │──→ Webhook / Syslog / Splunk
              │   + Prometheus      │──→ Metrics counter
              └─────────────────────┘
```

---

## Authentication

Agents authenticate via one of two methods:

1. **API Key** (preferred): `X-API-Key: snp_abc123...` header. The key is generated at agent registration and uniquely identifies the agent.

2. **External ID** (fallback): `agent_id` field in the request body is matched against the agent's `external_id` column. Less secure (no secret), suitable for learning mode or internal networks.

When `REQUIRE_API_KEY=true` (recommended for production), requests without a valid API key are denied immediately.

---

## Multi-Tenant Isolation

In cloud mode, all traffic is org-scoped:

- Agents belong to an organization
- Rules are scoped to the agent's organization (plus global rules with `organization_id = NULL`)
- Audit logs are tagged with `organization_id`
- Traffic discovery results are filtered by org
- One org's agents cannot see or be affected by another org's rules

This means multiple tenants can run on the same Snapper instance with complete isolation.
