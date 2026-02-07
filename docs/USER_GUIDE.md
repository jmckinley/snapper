# Snapper User Guide

Snapper is a security firewall for AI agents. It sits between your AI agent and the actions it takes, enforcing rules you define — blocking dangerous commands, requiring approval for sensitive operations, and protecting your personal data.

This guide walks through everything you need as a Snapper user, from first setup to advanced PII vault workflows.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Telegram Bot](#telegram-bot)
3. [Rules](#rules)
4. [Approval Workflow](#approval-workflow)
5. [PII Vault](#pii-vault)
6. [PII Protection Modes](#pii-protection-modes)
7. [Emergency Controls](#emergency-controls)
8. [Agent Setup](#agent-setup)
9. [Dashboard](#dashboard)
10. [Troubleshooting](#troubleshooting)

---

## Getting Started

### What Snapper Does

When your AI agent (OpenClaw) tries to run a command or use a tool, Snapper intercepts the request and checks it against your rules:

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
        +-- APPROVAL --> you get a Telegram notification with [Approve] [Deny] buttons
```

### First Steps

1. **Install Snapper** — See [Getting Started](GETTING_STARTED.md) for Docker setup
2. **Set up Telegram** — See [TELEGRAM_SETUP.md](TELEGRAM_SETUP.md) for bot creation
3. **Connect your agent** — See [OPENCLAW_INTEGRATION.md](OPENCLAW_INTEGRATION.md)
4. **Configure rules** — Use templates or create custom rules (this guide covers both)

Once set up, Snapper runs silently in the background. You'll only hear from it when something needs your attention.

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
| `/block` | Emergency block ALL agent actions |
| `/unblock` | Resume normal operation |

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
2. Snapper sends you a Telegram notification with context and **[Approve] / [Deny]** buttons
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
1. You store your credit card via Telegram
   → Encrypted with AES-128, stored in PostgreSQL
   → You get a token: {{SNAPPER_VAULT:a7f3b2c1}}

2. You tell your AI agent: "Book a flight, use {{SNAPPER_VAULT:a7f3b2c1}} for payment"

3. When the agent fills the payment form, Snapper intercepts:
   → Detects the vault token
   → Sends you a Telegram notification showing what's being sent and where
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
- **Multi-tenant:** Each user's entries are isolated by their Telegram chat ID. You can only see and manage your own data.
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

---

## Emergency Controls

### Block All

If something goes wrong, block every agent action instantly:

```
/block
→ Are you sure? This will block ALL agent actions.
  [CONFIRM BLOCK ALL] [Cancel]
```

Once blocked, all agent requests are denied until you unblock. A red alert appears in the dashboard.

### Unblock

```
/unblock
→ Normal operation resumed.
```

### When to Use

- Your agent is behaving unexpectedly
- You notice unauthorized actions in the audit log
- You need to investigate before allowing further actions
- During an active security incident

---

## Agent Setup

### OpenClaw (Recommended: Plugin)

The `snapper-guard` plugin integrates directly with OpenClaw's tool pipeline:

1. Register your agent in Snapper (via dashboard or API)
2. Copy the plugin to your OpenClaw config
3. Set `SNAPPER_URL` in your OpenClaw environment
4. Restart OpenClaw

See [OPENCLAW_INTEGRATION.md](OPENCLAW_INTEGRATION.md) for full setup.

### How the Hook Works

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
  - "allow"            → hook exits 0, tool runs
  - "deny"             → hook exits 1, tool blocked
  - "require_approval" → hook polls /approvals/status until you respond
```

---

## Dashboard

The web dashboard at `https://your-snapper:8443` provides:

- **Overview** — Agent status, recent activity, pending approvals
- **Rules** — Create, edit, and manage security rules
- **Agents** — Register agents, toggle enforcement mode, view trust scores
- **Audit Log** — Full history of all evaluations, approvals, and violations
- **Settings** — Configure alerts, integration settings, API keys

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
