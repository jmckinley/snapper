# Snapper User Guide

Snapper is an **Agent Application Firewall (AAF)**. It inspects and enforces security policy on traffic in both directions between your AI agent and the outside world — blocking dangerous commands, detecting PII exfiltration, preventing malicious skill installation, requiring human approval for sensitive operations, and protecting your personal data.

Snapper supports **OpenClaw**, **Claude Code**, **Cursor**, **Windsurf**, **Cline**, and custom agents.

This guide walks through everything you need as a Snapper user, from first setup to advanced PII vault workflows.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Quick Setup with `snapper init`](#quick-setup-with-snapper-init)
3. [Telegram Bot](#telegram-bot)
3b. [Slack Bot](#slack-bot)
4. [Rules](#rules)
5. [Approval Workflow](#approval-workflow)
6. [PII Vault](#pii-vault)
7. [PII Protection Modes](#pii-protection-modes)
8. [Emergency Controls](#emergency-controls)
9. [Agent Setup](#agent-setup)
10. [Audit Dashboard](#audit-dashboard)
11. [Integrations & Traffic Discovery](#integrations--traffic-discovery)
12. [Dashboard](#dashboard)
13. [Troubleshooting](#troubleshooting)

---

## Getting Started

### What Snapper Does

When your AI agent tries to run a command or use a tool, Snapper intercepts the request and checks it against your rules:

```
AI Agent wants to run: rm -rf /important-data
        |
        v
   Snapper Hook intercepts
        |
        v
   Rule Engine evaluates
        |
        +-- ALLOW    --> agent proceeds
        +-- DENY     --> agent is blocked, you get notified
        +-- APPROVAL --> you get a Telegram or Slack notification with [Approve] [Deny] buttons
```

### First Steps

1. **Install Snapper** — See [Getting Started](GETTING_STARTED.md) for Docker setup
2. **Connect your agent** — For production with OpenClaw, `deploy.sh` handles this automatically. Otherwise, run `python scripts/snapper-cli.py init` (auto-detects and configures your agent)
3. **Set up notifications** — See [TELEGRAM_SETUP.md](TELEGRAM_SETUP.md) or [SLACK_SETUP.md](SLACK_SETUP.md)
4. **Configure rules** — Use templates or create custom rules (this guide covers both)

Once set up, Snapper runs silently in the background. You'll only hear from it when something needs your attention.

---

## Quick Setup with `snapper init`

The fastest way to connect an agent is the `snapper init` CLI command:

```bash
python scripts/snapper-cli.py init
```

It will:
1. Check that Snapper is running
2. Auto-detect installed agents (OpenClaw, Claude Code, Cursor, Windsurf, Cline)
3. Let you pick one (or auto-select if only one is found)
4. Register the agent and apply a security profile
5. Write hook configuration to the agent's config directory

**Options:**

| Flag | Description |
|------|-------------|
| `--agent <type>` | Skip auto-detect (`openclaw`, `claude-code`, `cursor`, `windsurf`, `cline`, `custom`) |
| `--profile <name>` | Security profile (`recommended`, `strict`, `permissive`) |
| `--url <url>` | Override Snapper URL (default: `http://localhost:8000`) |

**Examples:**

```bash
# Auto-detect and configure
python scripts/snapper-cli.py init

# Explicitly configure Cursor
python scripts/snapper-cli.py init --agent cursor

# Use strict security profile
python scripts/snapper-cli.py init --agent windsurf --profile strict
```

---

## Telegram Bot

The Telegram bot is your primary interface to Snapper. It sends you real-time notifications when agents are blocked and lets you manage rules, approvals, and your PII vault from your phone.

### Command Reference

| Command | What it does |
|---------|-------------|
| `/help` | Show all commands |
| `/status` | Check Snapper is running and connected |
| `/rules` | List your active security rules |
| `/test run <cmd>` | Test whether a command would be allowed |
| `/pending` | List requests waiting for your approval |
| `/approve <id>` | Approve a pending request |
| `/deny <id>` | Deny a pending request |
| `/vault` | Show vault help |
| `/vault list` | List your encrypted PII entries |
| `/vault add <label> <type>` | Add a new PII entry |
| `/vault delete <token>` | Delete a specific entry |
| `/vault delete *` | Delete all entries (with confirmation) |
| `/vault domains <token> add <domain>` | Restrict entry to specific sites |
| `/pii` | Show current PII protection mode |
| `/pii protected` | Require approval before PII is sent |
| `/pii auto` | Auto-resolve vault tokens (no approval) |
| `/purge` | Purge PII data from agent storage |
| `/trust` | View trust scores for all your agents |
| `/trust reset [name]` | Reset trust score to 1.0 (all agents, or named) |
| `/trust enable [name]` | Enable trust enforcement (all agents, or named) |
| `/trust disable [name]` | Disable trust enforcement (all agents, or named) |
| `/block` | Emergency block ALL agent actions |
| `/unblock` | Resume normal operation |
| `/dashboard` | Open Snapper dashboard in browser |

### Notification Types

**Blocked command** — An agent tried something your rules don't allow:
```
BLOCKED: Command denied
Agent: openclaw-main
Command: rm -rf /tmp/data

[Allow Once] [Allow Always] [View Rule]
```

- **Allow Once** — Let this specific command through (expires in 5 minutes)
- **Allow Always** — Create a permanent allow rule for this command pattern
- **View Rule** — See which rule blocked it

**Approval request** — An agent needs your OK to proceed:
```
APPROVAL REQUIRED: Browser form submission
Agent: openclaw-main
Action: browser fill
Site: https://expedia.com/checkout

[Approve] [Deny]
```

**PII submission detected** — Your personal data is about to be sent:
```
PII SUBMISSION DETECTED

Agent: OpenClaw
Action: browser fill
Site: https://expedia.com/checkout
Amount: $1,247.50

Data being sent:
  - Credit Card: ****-****-****-1234 exp 12/27 (my Visa)
  - Name: J*** S*** (Travel Name)

[Approve] [Deny]
```

---

## Slack Bot

The Slack bot provides the same functionality as the Telegram bot, using slash commands and Block Kit interactive buttons. It uses **Socket Mode**, so no public URL or webhook setup is needed.

### Command Reference

| Command | What it does |
|---------|-------------|
| `/snapper-help` | Show all commands |
| `/snapper-status` | Check Snapper connection |
| `/snapper-rules` | View active security rules |
| `/snapper-test run <cmd>` | Test whether a command would be allowed |
| `/snapper-pending` | List pending approvals |
| `/snapper-vault` | Show vault help |
| `/snapper-vault list` | List your encrypted PII entries |
| `/snapper-vault add <label> <type>` | Add a new PII entry (multi-step DM flow) |
| `/snapper-vault delete <token>` | Delete a specific entry |
| `/snapper-pii` | Show current PII protection mode |
| `/snapper-pii protected` | Require approval before PII is sent |
| `/snapper-pii auto` | Auto-resolve vault tokens (no approval) |
| `/snapper-trust` | View trust scores for all your agents |
| `/snapper-trust reset [name]` | Reset trust score to 1.0 |
| `/snapper-trust enable [name]` | Enable trust enforcement |
| `/snapper-trust disable [name]` | Disable trust enforcement |
| `/snapper-block` | Emergency block ALL agent actions |
| `/snapper-unblock` | Resume normal operation |
| `/snapper-purge` | Clean up old bot messages |
| `/snapper-dashboard` | Open Snapper dashboard in browser |

### Notification Examples

**Blocked command:**
```
⚠️ WARNING: Action Blocked

Agent openclaw-main attempted: rm -rf /tmp/test
Blocked by: Block Dangerous Commands

[✅ Allow Once] [📝 Allow Always]
```

**Approval request:**
```
⚠️ APPROVAL REQUIRED: Browser form submission

Agent: openclaw-main
Action: browser fill
Site: https://expedia.com/checkout

[Approve]  [Deny]
```

**PII detection:**
```
🔒 PII Submission Detected

Agent: OpenClaw
Action: browser fill
Site: https://expedia.com/checkout

Data being sent:
  - Credit Card: ****-****-****-1234 exp 12/27 (My Visa)

[Approve]  [Deny]
```

See [Slack Setup Guide](SLACK_SETUP.md) for full configuration details.

---

## Rules

Rules define what your AI agents can and cannot do. They are evaluated in priority order (highest first), and the first matching rule wins.

### Rule Types

| Rule Type | Purpose | Example |
|-----------|---------|---------|
| `command_allowlist` | Only allow specific commands | Allow `git`, `npm`, `python` |
| `command_denylist` | Block specific commands | Block `rm -rf`, `curl \| bash` |
| `credential_guard` | Prevent credential exposure | Block commands containing API keys |
| `skill_trust` | Control which agent skills are allowed | Block untrusted MCP tools |
| `network_egress` | Control outbound network access | Only allow *.github.com |
| `rate_limit` | Limit how often actions can happen | Max 10 commands per minute |
| `time_restriction` | Restrict when agents can operate | Only allow 9am-5pm |
| `version_enforcement` | Require specific tool versions | Require Node.js >= 18 |
| `sandbox_enforcement` | Require sandbox for risky tools | Force Docker sandbox for browser |
| `human_in_loop` | Require approval for matching commands | Approve all `sudo` commands |
| `pii_gate` | Detect and protect personal data | Require approval when PII is submitted |
| `file_access` | Control file system access | Block access to ~/.ssh/ |

### Using Templates

Snapper comes with pre-built rule templates for common setups. Apply them via the API:

```bash
# List available templates
curl -s https://your-snapper:8443/api/v1/rules/templates | jq '.templates[].id'

# Apply a template
curl -s -X POST https://your-snapper:8443/api/v1/rules/templates/openclaw-safe-commands/apply \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "your-agent-id"}'
```

**Built-in templates:**
- `openclaw-safe-commands` — Allow common safe commands (git, ls, cat, etc.)
- `openclaw-sync-operations` — Allow file sync and backup operations
- `openclaw-dangerous-blocks` — Block destructive commands (rm -rf, mkfs, etc.)
- `openclaw-approval-required` — Require approval for installs, sudo, etc.

### Testing Rules

Before relying on rules in production, test them:

**Via Telegram:**
```
/test run rm -rf /
→ DENIED by rule "Block dangerous commands"

/test run git status
→ ALLOWED
```

**Via API:**
```bash
curl -s -X POST https://your-snapper:8443/api/v1/rules/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "openclaw-main",
    "request_type": "run",
    "command": "git push origin main"
  }' | jq '.decision'
```

### Learning Mode vs Enforcement

Each agent can run in one of two modes:

- **Learning mode** — Rules are evaluated but not enforced. Violations are logged so you can tune rules before going live.
- **Enforcement mode** — Rules are enforced. Blocked actions are stopped, approval-required actions pause until you respond.

Toggle via the dashboard or API:
```bash
curl -X PUT https://your-snapper:8443/api/v1/agents/{id} \
  -H "Content-Type: application/json" \
  -d '{"enforcement_mode": true}'
```

---

## Approval Workflow

When a rule evaluates to `require_approval`, here's what happens:

1. The agent's action is paused
2. Snapper sends you a Telegram or Slack notification with context and **[Approve] / [Deny]** buttons
3. You review and tap a button
4. The agent receives the decision and either proceeds or stops

**Timeouts:** If you don't respond within the configured timeout (default: 5 minutes), the request is automatically denied. This is a safety measure — if you're away, the agent can't proceed with sensitive actions.

**From Telegram:**
Just tap the button on the notification.

**From the API:**
```bash
# Check pending approvals
curl -s https://your-snapper:8443/api/v1/approvals/pending

# Approve
curl -X POST https://your-snapper:8443/api/v1/approvals/{request_id}/decide \
  -H "Content-Type: application/json" \
  -d '{"decision": "approved"}'
```

---

## PII Vault

The PII Vault lets you give AI agents access to your personal data (credit cards, addresses, etc.) without exposing the raw values. Data is encrypted at rest and only decrypted momentarily when you approve its use.

### How It Works

```
1. You store your credit card via Telegram or Slack
   → Encrypted with AES-128, stored in PostgreSQL
   → You get a token: {{SNAPPER_VAULT:a7f3b2c1}}

2. You tell your AI agent: "Book a flight, use {{SNAPPER_VAULT:a7f3b2c1}} for payment"

3. When the agent fills the payment form, Snapper intercepts:
   → Detects the vault token
   → Sends you a Telegram or Slack notification showing what's being sent and where
   → Waits for your approval

4. You approve → Snapper decrypts the value and passes it to the agent
   → The agent fills the form with your real card number
   → The decrypted value is never stored, only used in transit
```

### Supported Data Types

| Type | Aliases | Steps | What's collected |
|------|---------|-------|-----------------|
| Credit Card | `cc`, `card`, `credit`, `creditcard` | 3 | Card number, expiration, CVC |
| Name | `name` | 2 | First name, last name |
| Address | `addr`, `address` | 4 | Street, city, state, ZIP |
| Bank Account | `bank`, `account` | 2 | Routing number, account number |
| Phone | `phone`, `tel`, `mobile` | 1 | Phone number |
| Email | `email`, `mail` | 1 | Email address |
| SSN | `ssn`, `social` | 1 | Social Security Number |
| Passport | `passport` | 1 | Passport number |
| Custom | `custom` | 1 | Any value |

### Adding Entries via Telegram

**Credit card (3-step):**
```
You:  /vault add "My Visa" cc
Bot:  Step 1/3: Reply with the card number
You:  4111111111111234        ← deleted immediately
Bot:  Step 2/3: Reply with the expiration date
You:  12/27                   ← deleted immediately
Bot:  Step 3/3: Reply with the CVC/CVV
You:  123                     ← deleted immediately
Bot:  Vault entry created!
      Label: My Visa
      Category: credit_card
      Masked: ****-****-****-1234 exp 12/27
      Token: {{SNAPPER_VAULT:a7f3b2c1}}
```

**Address (4-step):**
```
You:  /vault add "Home" addr
Bot:  Step 1/4: Reply with the street address
You:  123 Main St, Apt 4B    ← deleted immediately
Bot:  Step 2/4: Reply with the city
You:  Springfield             ← deleted immediately
Bot:  Step 3/4: Reply with the state
You:  IL                      ← deleted immediately
Bot:  Step 4/4: Reply with the ZIP code
You:  62704                   ← deleted immediately
Bot:  Vault entry created!
      Masked: 123 M*** S***, S***, IL 62704
      Token: {{SNAPPER_VAULT:b3c4d5e6}}
```

**Name (2-step):**
```
You:  /vault add "Travel Name" name
Bot:  Step 1/2: Reply with the first name
You:  John                    ← deleted immediately
Bot:  Step 2/2: Reply with the last name
You:  Smith                   ← deleted immediately
Bot:  Vault entry created!
      Masked: J*** S***
      Token: {{SNAPPER_VAULT:c4d5e6f7}}
```

**Bank account (2-step):**
```
You:  /vault add "Chase Checking" bank
Bot:  Step 1/2: Reply with the routing number (9 digits)
You:  021000021               ← deleted immediately
Bot:  Step 2/2: Reply with the account number
You:  1234567890              ← deleted immediately
Bot:  Vault entry created!
      Masked: Routing: ****0021 / Acct: ****7890
      Token: {{SNAPPER_VAULT:d5e6f7a8}}
```

**Single-step types (phone, email, SSN, passport, custom):**
```
You:  /vault add "Personal Email" email
Bot:  Please reply with your email address.
You:  john@example.com        ← deleted immediately
Bot:  Vault entry created!
      Masked: j***@example.com
      Token: {{SNAPPER_VAULT:e6f7a8b9}}
```

At any point during multi-step entry, type `/cancel` to abort.

**Adding entries via Slack** works the same way — use `/snapper-vault add "label" type` to start the flow, then reply with values in DMs. Type `cancel` at any step to abort.

### Managing Entries

```
/vault list                              — See all your entries (masked values only)
/vault delete {{SNAPPER_VAULT:a7f3b2c1}} — Delete a specific entry
/vault delete *                          — Delete ALL entries (requires confirmation)
```

### Domain Restrictions

Limit where your PII can be sent:

```
/vault domains {{SNAPPER_VAULT:a7f3b2c1}} add *.expedia.com
/vault domains {{SNAPPER_VAULT:a7f3b2c1}} add *.delta.com
/vault domains {{SNAPPER_VAULT:a7f3b2c1}} remove *.expedia.com
```

With domain restrictions, Snapper will deny any attempt to use that token on a site outside your whitelist — even if you accidentally approve.

### Security Design

- **Encryption:** Values are encrypted with Fernet (AES-128-CBC + HMAC-SHA256) using a key derived from your Snapper SECRET_KEY via HKDF
- **Multi-tenant:** Each user's entries are isolated by their Telegram chat ID or Slack user ID. You can only see and manage your own data.
- **Auto-delete messages:** Every message containing raw PII is deleted from Telegram immediately after processing
- **Masked display:** Raw values are never shown — only masked versions (e.g., `****-****-****-1234`)
- **Usage tracking:** Each token tracks use count, last used timestamp, and last used domain
- **Expiration:** Entries can have max uses and expiration dates
- **Soft delete:** Deleted entries are marked inactive, not physically removed (for audit trail)

---

## PII Protection Modes

Control how Snapper handles PII detection:

| Mode | Command | Behavior |
|------|---------|----------|
| **Protected** | `/pii protected` | Detects PII in agent actions and requires your approval before proceeding. This is the recommended mode. |
| **Auto** | `/pii auto` | Vault tokens are resolved automatically without approval. Use this when you trust the agent and want faster operation. PII is still logged. |

Check current mode:
```
/pii
→ PII Gate Mode: protected
```

In **protected** mode, when an agent submits data containing vault tokens or raw PII:
1. The action is paused
2. You get a rich notification showing the destination site, data fields (masked), and dollar amounts if present
3. You approve or deny
4. On approval, vault tokens are decrypted and passed through

In **auto** mode, vault tokens are resolved immediately. The action is logged but not paused.

**Multiple PII gates:** You can have both modes active at different priorities. A higher-priority auto-mode rule will take precedence over a lower-priority protected-mode rule for vault-only tokens. This lets you auto-resolve known vault tokens while still requiring approval for raw PII detected by a broader rule.

---

## Emergency Controls

### Block All

If something goes wrong, block every agent action instantly:

**Via Telegram:**
```
/block
→ Are you sure? This will block ALL agent actions.
  [CONFIRM BLOCK ALL] [Cancel]
```

**Via Slack:**
```
/snapper-block
→ Are you sure? This will block ALL agent actions.
  [CONFIRM BLOCK ALL] [Cancel]
```

Once blocked, all agent requests are denied until you unblock. A red alert appears in the dashboard.

### Unblock

**Via Telegram:** `/unblock`
**Via Slack:** `/snapper-unblock`
```
→ Normal operation resumed.
```

### When to Use

- Your agent is behaving unexpectedly
- You notice unauthorized actions in the audit log
- You need to investigate before allowing further actions
- During an active security incident

---

## Agent Setup

The easiest way to set up any agent is `python scripts/snapper-cli.py init` (see above). Below are the manual setup details for each agent.

### OpenClaw (Recommended: Plugin)

**Production (VPS):** If you deployed with `deploy.sh`, OpenClaw integration is automatic — the agent is registered, security rules are applied, hooks are installed, and env vars are configured. No manual steps needed. See [Zero-Config Deployment](OPENCLAW_INTEGRATION.md#zero-config-deployment).

**Local development** or manual setup — the `snapper-guard` plugin integrates directly with OpenClaw's tool pipeline:

1. Register your agent in Snapper (via dashboard or API)
2. Copy the plugin to your OpenClaw config
3. Set `SNAPPER_URL` in your OpenClaw environment
4. Restart OpenClaw

See [OPENCLAW_INTEGRATION.md](OPENCLAW_INTEGRATION.md) for full setup.

### Claude Code

Uses PreToolUse hooks in `~/.claude/settings.json`:

1. Install hook: copy `scripts/claude-code-hook.sh` to `~/.claude/hooks/pre_tool_use.sh`
2. Add to `~/.claude/settings.json`:
   ```json
   { "hooks": { "PreToolUse": [{ "matcher": "", "hooks": [{ "type": "command", "command": "~/.claude/hooks/pre_tool_use.sh" }] }] } }
   ```
3. Set env: `export SNAPPER_URL=http://localhost:8000 SNAPPER_AGENT_ID=claude-code-$(hostname)`

### Cursor

Uses preToolUse hooks in `~/.cursor/hooks/hooks.json`:

1. Install hook: copy `scripts/cursor-hook.sh` to `~/.cursor/hooks/snapper_pre_tool_use.sh`
2. Create/merge `~/.cursor/hooks/hooks.json`:
   ```json
   { "preToolUse": [{ "command": "~/.cursor/hooks/snapper_pre_tool_use.sh" }] }
   ```
3. Set env in `~/.cursor/.env.snapper`: `SNAPPER_URL`, `SNAPPER_AGENT_ID`, `SNAPPER_API_KEY`

Cursor uses exit code 2 (not 1) to block tool calls.

### Windsurf

Uses multiple hook types in `~/.codeium/windsurf/hooks/hooks.json`:

1. Install hook: copy `scripts/windsurf-hook.sh` to `~/.codeium/windsurf/hooks/snapper_pre_tool_use.sh`
2. Create/merge `~/.codeium/windsurf/hooks/hooks.json`:
   ```json
   { "pre_run_command": [{ "command": "..." }], "pre_write_code": [{ "command": "..." }], "pre_mcp_tool_use": [{ "command": "..." }] }
   ```
3. Set env in `~/.codeium/windsurf/.env.snapper`

Windsurf uses exit code 2 to block and separate hooks for commands, file writes, and MCP tools.

### Cline

Uses auto-discovered executable scripts in `~/.cline/hooks/`:

1. Install hook: copy `scripts/cline-hook.sh` to `~/.cline/hooks/pre_tool_use` (no extension)
2. Make executable: `chmod +x ~/.cline/hooks/pre_tool_use`
3. Set env in `~/.cline/.env.snapper`

Cline always exits 0 and uses JSON stdout (`{"cancel": true}`) to signal blocks.

### How Hooks Work

```
Agent calls tool (e.g., "bash: rm -rf /tmp")
        |
        v
Hook script fires (before tool execution)
        |
        v
POST /api/v1/rules/evaluate
  { agent_id, command, tool_name, tool_input }
        |
        v
Snapper evaluates rules, returns decision:
  - "allow"            → hook signals allow, tool runs
  - "deny"             → hook signals block, tool stopped
  - "require_approval" → hook polls /approvals/status until you respond
```

Each agent uses a slightly different block signal (exit code 1, exit code 2, or JSON output) — the hook scripts handle this automatically.

---

## Audit Dashboard

The Audit page (`/audit`) provides observability into what your agents are doing:

- **Summary stats** — Total evaluations, allowed %, blocked %, and pending approvals for the last 24 hours. Click any stat card to filter the log table.
- **Activity timeline** — Hourly bar chart showing allowed (green) vs blocked (red) actions, giving you an at-a-glance view of agent activity patterns.
- **Filterable log viewer** — Search by message text, filter by date range, agent, action type, or severity. Expandable rows show full JSON details.
- **Pagination** — Navigate through large audit logs with previous/next controls.

The stats are powered by `GET /api/v1/audit/stats?hours=24` which returns aggregated counts and an hourly breakdown.

---

## Integrations & Traffic Discovery

The Integrations page (`/integrations`) is where you manage rule templates and see what your agents are actually doing.

### Traffic Discovery

Snapper passively detects MCP servers and tools from live agent traffic — no configuration needed. Every time an agent calls `evaluate`, Snapper parses the `command` and `tool_name` to identify the service.

**What it detects:**
- **MCP servers** — `mcp__github__create_issue` → GitHub (MCP)
- **CLI tools** — `git status`, `curl https://api.example.com` → Git, cURL
- **Built-in tools** — `browser`, `exec` → Browser, Exec
- **OpenClaw format** — `slack_post_message` → Slack (MCP)

**Using the Insights view:**

1. Visit `/integrations` — the "Discovered Activity" section shows services your agents have used
2. Each service card shows: total evaluation count, coverage status (green = all commands covered, red = uncovered commands)
3. Expand a card to see individual commands with counts, last seen, and decision breakdown (allow/deny/approve)
4. Uncovered commands have a **"Create Rule"** button — pick an action (allow/deny/approve) and pattern mode (prefix/exact)
5. If a matching template exists, you'll see an **"Enable Template"** link

**Period selector:** Switch between 24h, 7d, and 30d views. Agent filter lets you scope to a specific agent.

**Empty state:** If no traffic has been recorded yet, you'll see a message explaining that activity will appear once agents start sending requests.

### Rule Templates

Snapper includes 10 pre-built rule templates for common services:

| Template | Rules | What It Covers |
|----------|-------|---------------|
| **Shell / Bash** | 4 | Safe commands (ls, git, cat), block destructive (rm -rf, mkfs), approval for installs |
| **Filesystem** | 3 | File read/write patterns + MCP filesystem server |
| **GitHub** | 4 | Git CLI + MCP GitHub server (reads allowed, writes approved, deletes blocked) |
| **Browser** | 3 | Browser tool, Puppeteer, Playwright MCP servers |
| **Network / HTTP** | 3 | curl, wget, HTTP + MCP fetch server |
| **AWS** | 3 | AWS CLI + MCP AWS server |
| **Database** | 3 | PostgreSQL, SQLite, MongoDB MCP servers |
| **Slack** | 4 | Slack MCP server (selectable: choose which rules to enable) |
| **Gmail / Email** | 3 | Gmail and Google Mail MCP servers |
| **Custom MCP** | 3 | Enter any server name — auto-generates read/write/delete rules |

**Enabling a template:**
1. Click **Enable** on any template card
2. Rules are created with `source=integration` for easy management
3. The template card shows "Enabled" with a rule count
4. Click **Disable** to soft-delete all rules from that template

**Selectable templates** (like Slack) let you pick which rules to enable — some may be off by default.

### Custom MCP Server

For MCP servers not in the template list, use **Custom MCP**:

1. Click the "Custom MCP Server" card (or use the "Add MCP Server" input)
2. Enter the server name (e.g., `google_calendar`, `notion`, `linear`)
3. Snapper generates 3 rules:
   - **Allow reads** — Pattern: `^mcp__google_calendar__(read|get|list|search|query).*`
   - **Approve writes** — Pattern: `^mcp__google_calendar__(create|update|write|send|post|set).*`
   - **Block destructive** — Pattern: `^mcp__google_calendar__(delete|drop|destroy|remove|purge).*`

The server name autocomplete shows 40+ recognized MCP servers with display names.

**Via API:**
```bash
# Smart defaults for any server
curl -X POST https://your-snapper:8443/api/v1/integrations/traffic/create-server-rules \
  -H "Content-Type: application/json" \
  -d '{"server_name": "notion"}'

# Or use the custom_mcp template
curl -X POST https://your-snapper:8443/api/v1/integrations/custom_mcp/enable \
  -H "Content-Type: application/json" \
  -d '{"custom_server_name": "notion"}'
```

### Legacy Rules

If you previously enabled integrations that have been simplified (e.g., Linear, Notion, Discord), those rules continue to work — they evaluate normally against agent traffic. They appear in a "Legacy Rules" section at the bottom of the Integrations page with a note explaining they were created from templates that have been consolidated.

Manage legacy rules on the Rules page, or disable them from the Integrations page.

---

## Dashboard

The web dashboard at `https://your-snapper:8443` provides:

- **Overview** — Agent status, recent activity, pending approvals
- **Rules** — Create, edit, and manage security rules
- **Agents** — Register agents, toggle enforcement mode, view trust scores
- **Audit** — Activity stats, timeline chart, filterable log viewer with pagination
- **Settings** — Configure alerts, integration settings, API keys
- **Help** — In-app setup guide for all agent types, FAQ, troubleshooting

---

## Troubleshooting

### Bot not responding to messages

1. Check webhook: send `/status` — if no response, webhook may be misconfigured
2. Verify on server: `curl -s https://api.telegram.org/bot<TOKEN>/getWebhookInfo`
3. Check `pending_update_count` — if high, Telegram can't reach your server
4. Check app logs: `docker logs snapper-app-1 --tail=50`

### "Entry not found" when deleting

The token must be exact, including the `{{` and `}}`. Copy it from `/vault list`.

### Multi-step entry timed out

Each step has a 5-minute timeout. If you take too long between steps, the pending state expires. Start over with `/vault add`.

### Messages not being deleted

The bot needs admin rights in group chats to delete messages. In private chats, the bot can only delete messages for 48 hours after they were sent.

### Agent actions not being intercepted

1. Verify the agent is registered: check `/rules` or the dashboard
2. Verify the hook is installed: check agent config
3. Verify enforcement mode is on (learning mode logs but doesn't block)
4. Check the agent's Snapper URL is correct

### Approval timed out

Default timeout is 5 minutes. If you miss the notification, the request is automatically denied. The agent will need to retry the action.

### PII not detected

- Ensure a `pii_gate` rule exists for your agent (use the template or create one)
- Check that `/pii` shows `protected` mode
- Vault tokens must match the exact format: `{{SNAPPER_VAULT:xxxxxxxx}}`

### Vault token not resolving after approval

- Token may be expired (check `max_uses` or `expires_at`)
- Domain restriction may be blocking (check `/vault domains`)
- Token may belong to a different user (multi-tenant isolation)

### Slack bot not responding to slash commands

1. Verify `SLACK_BOT_TOKEN` and `SLACK_APP_TOKEN` are set in `.env`
2. Check that Socket Mode is enabled in the Slack app settings
3. Restart containers: `docker compose up -d --force-recreate`
4. Check logs: `docker compose logs app | grep -i slack`
5. Verify slash commands are defined in your Slack app configuration

### Slack notifications going to wrong channel

Check the agent's `owner_chat_id`:
- Must start with `U` (e.g., `U0ACYA78DSR`) for Slack DM routing
- Numeric values route to Telegram instead
- Update via dashboard (edit agent) or API
