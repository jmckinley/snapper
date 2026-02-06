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
| `/block` | Emergency block ALL actions |
| `/unblock` | Resume normal operation |

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
- **Allow Once** — Pass this time only (no rule created)
- **Allow Always** — Create a permanent allow rule
- **View Rule** — See which rule blocked it

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

## Security Notes

- **Bot tokens are secrets** — Never commit them to git or share publicly
- **Webhook verification** — Snapper validates webhook calls come from Telegram
- **Chat ID restriction** — Optionally set `TELEGRAM_CHAT_ID` to only respond to specific chats
- **Emergency block** — Creates a priority-10000 deny rule that overrides all others
