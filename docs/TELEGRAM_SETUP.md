# Telegram Setup Guide

This guide walks you through setting up a Telegram bot for Snapper. Once configured, you can test rules, approve requests, and control Snapper from your phone.

## Step 1: Create Your Bot

1. Open Telegram and search for **@BotFather**
2. Send `/newbot`
3. Choose a name (e.g., "Snapper Security")
4. Choose a username following this convention:
   - `snapper_<yourname>_bot` (e.g., `snapper_john_bot`)
   - `snapper_<company>_bot` (e.g., `snapper_acme_bot`)
   - `<yourname>_snapper_bot` (e.g., `john_snapper_bot`)

   **Tip:** Telegram bot names must end in `bot` and be unique. Using your name/company makes it memorable and avoids conflicts.

5. Copy the **bot token** (looks like `123456789:ABCdefGHI...`)

## Step 2: Configure Snapper

### Option A: Environment Variables

Add to your `.env` file:

```bash
TELEGRAM_BOT_TOKEN=your-bot-token-here
TELEGRAM_CHAT_ID=your-chat-id-here  # Optional, see Step 3
```

For production deployments, edit `/opt/snapper/.env` and restart:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --force-recreate
```

### Option B: Dashboard

1. Go to Settings in the Snapper dashboard
2. Under "Notifications", find Telegram
3. Paste your bot token
4. Click "Save"

## Step 3: Get Your Chat ID

1. Send any message to your new bot (e.g., `/start`)
2. Snapper will respond with your **Chat ID**
3. Copy this ID and add it to your `.env` as `TELEGRAM_CHAT_ID`

Alternatively, visit: `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates`

## Step 4: Set Up Webhook (Production Only)

For production deployments with a public URL, set up a webhook so Telegram pushes updates to Snapper:

```bash
curl -X POST "https://api.telegram.org/bot<YOUR_TOKEN>/setWebhook" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://your-server:8443/api/v1/telegram/webhook"}'
```

**Note:** Telegram requires HTTPS. Self-signed certificates work if you provide them to the API:

```bash
curl -X POST "https://api.telegram.org/bot<YOUR_TOKEN>/setWebhook" \
  -F "url=https://your-server:8443/api/v1/telegram/webhook" \
  -F "certificate=@/path/to/cert.pem"
```

## Bot Commands

Once configured, your bot supports these commands:

| Command | Description |
|---------|-------------|
| `/start` | Welcome message and chat ID |
| `/help` | List all commands |
| `/status` | Check Snapper connection |
| `/rules` | View active security rules |
| `/pending` | List pending approval requests |
| `/approve <id>` | Approve a request |
| `/deny <id>` | Deny a request |
| `/test run <cmd>` | Test a shell command |
| `/test install <skill>` | Test a skill installation |
| `/test access <file>` | Test file access |
| `/test network <host>` | Test network egress |
| `/vault` | Manage encrypted PII vault |
| `/vault add <label> <category>` | Store PII, get vault token |
| `/vault list` | List your entries (masked) |
| `/vault delete <token>` | Remove a vault entry |
| `/vault domains <token> add <domain>` | Manage allowed domains |
| `/pii` | Show current PII gate mode |
| `/pii protected` | Require approval for PII submissions |
| `/pii auto` | Auto-resolve vault tokens (no approval) |
| `/purge` | List agents for PII purge |
| `/purge <agent_id>` | Purge PII from agent data |
| `/purge *` | Purge PII from ALL agents |
| `/block` | Emergency block ALL actions |
| `/unblock` | Resume normal operation |
| `/dashboard` | Open Snapper dashboard in browser |

## Testing Rules

The `/test` command simulates agent actions to verify your rules work:

```
/test run ls -la
```
Result: ALLOWED (if you have a rule permitting `ls`)

```
/test run rm -rf /
```
Result: BLOCKED (dangerous command denied)

When a test is blocked, you'll see inline buttons:
- **Allow Once** — Allow this specific command for 5 minutes (no permanent rule)
- **Allow Always** — Create a permanent allow rule for this command
- **View Rule** — See which rule blocked it

## Block Notifications

When an agent's command is blocked in production, Snapper sends a Telegram notification with quick-action buttons:

```
⚠️ WARNING: Action Blocked: Block Dangerous Commands

Agent `OpenClaw` attempted: `rm -rf /tmp/test`

Blocked by: Denied by rule: Block Dangerous Commands

📋 Agent: openclaw-main
🔧 Command: rm -rf /tmp/test

[✅ Allow Once] [📝 Allow Always]
```

**Button actions:**
- **Allow Once** — Stores a one-time approval in Redis (5 min TTL). The next time the agent tries this exact command, it will be allowed once, then the approval expires.
- **Allow Always** — Creates a permanent ALLOW rule for this command pattern, so it will always be allowed going forward.

## Emergency Controls

If something goes wrong, use `/block` to immediately stop ALL agent actions:

1. Send `/block`
2. Confirm by tapping "CONFIRM BLOCK ALL"
3. All agent actions are now denied

To resume normal operation:
```
/unblock
```

This deactivates the emergency block rule.

## PII Purge

The `/purge` command removes personally identifiable information (PII) from agent data, supporting GDPR compliance:

1. Send `/purge` to see a list of agents
2. Send `/purge <agent_id>` with the first 8 characters of the agent ID
3. Review what will be deleted and confirm

**Purge all agents:**
```
/purge *
```

**What gets purged:**
- Conversation history containing PII patterns
- Memory files (SOUL.md, MEMORY.md)
- Cached session data in Redis
- Audit log entries containing PII patterns

**PII patterns detected (US, UK, Canada, Australia):**

| Region | Pattern |
|--------|---------|
| US | SSN, ZIP codes, phone numbers |
| UK | National Insurance Number, NHS Number, postcodes, phone |
| Canada | Social Insurance Number, postal codes, phone |
| Australia | Tax File Number, Medicare, postcodes, phone |
| Global | Credit cards, IBAN, email, IP addresses, street addresses |

**Example:**
```
/purge a1b2c3d4
```

The bot will show a confirmation dialog. Tap "CONFIRM PURGE" to proceed.

**Note:** For complete PII removal from OpenClaw agents, also run `openclaw agent --purge-pii` on the agent's host.

## PII Vault

The PII vault lets you store sensitive data (credit cards, names, addresses) encrypted in Snapper and give AI agents tokens to reference them instead of raw values.

### Storing PII

```
/vault add "My Visa" credit_card
```

The bot will prompt you to enter the actual card number. Once entered, it's encrypted and you receive a token:

```
Vault entry created:
  Label: My Visa
  Token: {{SNAPPER_VAULT:a7f3b2c1}}
  Masked: ****-****-****-1234

Give this token to your AI agent instead of the real value.
```

### Using Vault Tokens

Tell your AI agent: "Use `{{SNAPPER_VAULT:a7f3b2c1}}` for the credit card field"

When the agent fills a browser form with this token, Snapper intercepts it and:
- **Protected mode** (`/pii protected`): Sends a Telegram approval request showing the masked data and destination site
- **Auto mode** (`/pii auto`): Resolves the token automatically without approval

### PII Approval Notifications

When PII is detected in protected mode:

```
PII Submission Detected: PII Gate Protection

Agent OpenClaw wants to: browser fill

Site: https://expedia.com/checkout
Data being sent:
  Credit Card: ****-****-****-1234

[Approve]  [Deny]
```

### Managing Vault Entries

```
/vault list              # See all your entries (masked)
/vault delete a7f3b2c1   # Remove an entry
/vault domains a7f3b2c1 add *.expedia.com  # Restrict to specific sites
```

### Domain Restrictions

You can restrict a vault entry to specific domains. If the agent tries to use the token on an unauthorized site, the token won't resolve:

```
/vault domains a7f3b2c1 add *.expedia.com
/vault domains a7f3b2c1 add *.delta.com
```

## Multiple Bots

If you run multiple services (e.g., Snapper and OpenClaw), use **separate bots** for each:

| Service | Bot Name Example | Purpose |
|---------|------------------|---------|
| Snapper | `@snapper_john_bot` | Rule testing, approvals, emergency controls |
| OpenClaw | `@openclaw_john_bot` | AI chat interface |

This prevents confusion and keeps conversations separate.

## Troubleshooting

### Bot not responding

1. Check webhook is set: `curl https://api.telegram.org/bot<TOKEN>/getWebhookInfo`
2. Verify Snapper can reach Telegram: `docker compose logs app | grep telegram`
3. Ensure `TELEGRAM_BOT_TOKEN` is set in `.env`
4. Restart with `--force-recreate` to pick up env changes

### Responses going to wrong bot

If you changed bot tokens, the container may have cached the old one:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --force-recreate
```

### Webhook returns 404

Verify the webhook URL ends with `/api/v1/telegram/webhook` (not just `/telegram/webhook`).

### Self-signed certificate issues

When using self-signed certs, you must upload the certificate to Telegram:

```bash
curl -F "url=https://your-server:8443/api/v1/telegram/webhook" \
     -F "certificate=@/etc/caddy/certs/cert.pem" \
     "https://api.telegram.org/bot<TOKEN>/setWebhook"
```

## OpenClaw Integration

When OpenClaw is integrated with Snapper, approval requests appear in Telegram:

1. OpenClaw tries to run `npm install express`
2. Snapper's "Require Approval for Installs" rule triggers
3. You receive a Telegram notification with the command details
4. Tap **Approve** or **Deny** to decide

The decision is sent back to OpenClaw, which either executes or blocks the command.

See [OpenClaw Integration Guide](OPENCLAW_INTEGRATION.md) for setup details.

### PII Approval via Telegram

When PII is detected in a browser form fill (protected mode), the approval notification shows:
- Which agent is submitting data
- The destination website URL
- What PII categories are being sent (masked values)
- Approve/Deny buttons

After approval, vault tokens are decrypted and the real values are passed to the agent's browser tool.

## Security Notes

- **Bot tokens are secrets** — Never commit them to git or share publicly
- **Webhook verification** — Snapper validates webhook calls come from Telegram
- **Chat ID restriction** — Optionally set `TELEGRAM_CHAT_ID` to only respond to specific chats
- **Emergency block** — Creates a priority-10000 deny rule that overrides all others

## Prefer Slack?

Snapper also supports a full-featured Slack bot with slash commands and interactive Block Kit buttons. Socket Mode means no public URL or webhook setup is needed. See [Slack Setup Guide](SLACK_SETUP.md).
