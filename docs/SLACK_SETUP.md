# Slack Setup Guide

This guide walks you through setting up a Slack bot for Snapper. Once configured, you can test rules, approve requests, manage your PII vault, and control Snapper — all from Slack using slash commands and interactive buttons.

Snapper's Slack bot uses **Socket Mode**, so no public URL or webhook endpoint is needed.

## Step 1: Create Your Slack App

### Option A: Import from Manifest (Recommended)

1. Go to [api.slack.com/apps](https://api.slack.com/apps)
2. Click **"Create New App"**
3. Select **"From an app manifest"**
4. Choose your workspace
5. Paste the contents of `slack-app-manifest.json` from this repo (or copy the JSON below)
6. Click **"Create"**

<details>
<summary>App Manifest JSON</summary>

```json
{
  "display_information": {
    "name": "Snapper Approval Bot",
    "description": "Agent Application Firewall - approvals, rule management, PII vault, trust scoring",
    "background_color": "#1a1a2e"
  },
  "features": {
    "app_home": {
      "home_tab_enabled": false,
      "messages_tab_enabled": true,
      "messages_tab_read_only_enabled": false
    },
    "bot_user": {
      "display_name": "Snapper",
      "always_online": true
    },
    "slash_commands": [
      { "command": "/snapper-rules", "description": "View active security rules" },
      { "command": "/snapper-test", "description": "Test rule enforcement", "usage_hint": "run ls -la" },
      { "command": "/snapper-vault", "description": "Manage PII vault entries", "usage_hint": "list | add MyVisa cc | delete token" },
      { "command": "/snapper-trust", "description": "View/manage agent trust scores", "usage_hint": "reset | enable | disable" },
      { "command": "/snapper-block", "description": "Emergency block ALL agent actions" },
      { "command": "/snapper-unblock", "description": "Resume normal operations" },
      { "command": "/snapper-status", "description": "Check system health" },
      { "command": "/snapper-pending", "description": "List pending approval requests" },
      { "command": "/snapper-pii", "description": "Toggle PII gate mode", "usage_hint": "protected | auto" },
      { "command": "/snapper-purge", "description": "Clean up bot messages", "usage_hint": "7d | 2h | all" },
      { "command": "/snapper-help", "description": "Show all available commands" },
      { "command": "/snapper-dashboard", "description": "Open Snapper dashboard in browser" }
    ]
  },
  "oauth_config": {
    "scopes": {
      "bot": ["chat:write", "commands", "im:history", "im:write", "users:read", "app_mentions:read"]
    }
  },
  "settings": {
    "event_subscriptions": { "bot_events": ["message.im"] },
    "interactivity": { "is_enabled": true },
    "socket_mode_enabled": true,
    "token_rotation_enabled": false
  }
}
```

</details>

### Option B: Manual Creation

1. Go to [api.slack.com/apps](https://api.slack.com/apps) → **"Create New App"** → **"From scratch"**
2. Name: **Snapper Approval Bot**, pick your workspace
3. **Socket Mode:** Settings → Socket Mode → Toggle **On** → Generate an app-level token with `connections:write` scope → Copy the `xapp-...` token
4. **Bot Scopes:** OAuth & Permissions → Bot Token Scopes → Add: `chat:write`, `commands`, `im:history`, `im:write`, `users:read`, `app_mentions:read`
5. **Install to Workspace:** OAuth & Permissions → Install to Workspace → Copy the `xoxb-...` Bot Token
6. **Slash Commands:** Slash Commands → Create all 12 commands listed in the [Command Reference](#slash-command-reference)
7. **Interactivity:** Interactivity & Shortcuts → Toggle **On** (no URL needed for Socket Mode)
8. **Events:** Event Subscriptions → Toggle **On** → Subscribe to bot event: `message.im`

## Step 2: Configure Snapper

### Option A: Environment Variables

Add to your `.env` file:

```bash
SLACK_BOT_TOKEN=xoxb-your-bot-token
SLACK_APP_TOKEN=xapp-your-app-level-token
SLACK_ALERT_CHANNEL=                      # Optional: default channel ID for alerts
```

For production deployments, edit `/opt/snapper/.env` and restart:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --force-recreate
```

### Option B: Dashboard

1. Go to Settings in the Snapper dashboard
2. Under "Notifications", find Slack
3. Paste your bot token and app token
4. Click "Save"

## Step 3: Get Your Slack User ID

Your Slack user ID is used to route approval notifications to your DMs.

1. In Slack, click your profile picture → **Profile**
2. Click the **...** (more) menu → **Copy member ID**
3. Your user ID looks like `U0ACYA78DSR`

Alternatively, send `/snapper-help` in a DM to the bot — the response will include your user ID.

### Link Your Agents

When registering agents (via dashboard or API), set the **owner_chat_id** to your Slack user ID. This tells Snapper where to send approval notifications for that agent:

- Slack user IDs start with `U` → notifications go to Slack DMs
- Numeric Telegram chat IDs → notifications go to Telegram

## Step 4: Verify Connection

1. Restart containers to pick up the new env vars:
   ```bash
   docker compose up -d --force-recreate
   ```

2. Check app logs for the Slack connection message:
   ```bash
   docker compose logs app | grep -i slack
   # Look for: "Slack bot started"
   ```

3. Send a test command in Slack:
   ```
   /snapper-status
   ```
   You should see a response with Snapper's connection status.

## Slash Command Reference

| Command | Description |
|---------|-------------|
| `/snapper-help` | Show all available commands |
| `/snapper-status` | Check Snapper connection and system health |
| `/snapper-rules` | View active security rules |
| `/snapper-pending` | List pending approval requests |
| `/snapper-test run <cmd>` | Test if a shell command is allowed |
| `/snapper-vault` | Manage encrypted PII vault |
| `/snapper-vault list` | List your vault entries (masked values) |
| `/snapper-vault add <label> <type>` | Store PII, get a vault token |
| `/snapper-vault delete <token>` | Remove a vault entry |
| `/snapper-trust` | View trust scores for your agents |
| `/snapper-trust reset [name]` | Reset trust score to 1.0 |
| `/snapper-trust enable [name]` | Enable trust enforcement |
| `/snapper-trust disable [name]` | Disable trust enforcement |
| `/snapper-pii` | Show current PII gate mode |
| `/snapper-pii protected` | Require approval for PII submissions |
| `/snapper-pii auto` | Auto-resolve vault tokens |
| `/snapper-block` | Emergency block ALL agent actions |
| `/snapper-unblock` | Resume normal operation |
| `/snapper-purge` | Clean up old bot messages |
| `/snapper-dashboard` | Open Snapper dashboard in browser |

## Approval Notifications

When an agent action requires approval, Snapper sends a Block Kit message to your Slack DM:

```
⚠️ APPROVAL REQUIRED: Browser form submission

Agent: openclaw-main
Action: browser fill
Site: https://expedia.com/checkout

[Approve]  [Deny]
```

Tap a button to approve or deny. The agent receives the decision and proceeds or stops.

When a test command is blocked, you'll see quick-action buttons:

```
⚠️ WARNING: Action Blocked

Agent openclaw-main attempted: rm -rf /tmp/test
Blocked by: Block Dangerous Commands

[✅ Allow Once] [📝 Allow Always]
```

- **Allow Once** — Allow this specific command for 5 minutes
- **Allow Always** — Create a permanent allow rule

## PII Vault via Slack

You can manage your PII vault entirely through Slack DMs with the bot. The multi-step flow works the same as Telegram:

**Adding a credit card:**
```
You:  /snapper-vault add "My Visa" cc
Bot:  Step 1/3: Reply with the card number
You:  4111111111111234
Bot:  Step 2/3: Reply with the expiration date
You:  12/27
Bot:  Step 3/3: Reply with the CVC/CVV
You:  123
Bot:  ✅ Vault entry created!
      Label: My Visa
      Category: credit_card
      Masked: ****-****-****-1234 exp 12/27
      Token: {{SNAPPER_VAULT:a7f3b2c1}}
```

**PII detection in protected mode:**
```
🔒 PII Submission Detected

Agent: OpenClaw
Action: browser fill
Site: https://expedia.com/checkout
Amount: $1,247.50

Data being sent:
  - Credit Card: ****-****-****-1234 exp 12/27 (My Visa)
  - Name: J*** S*** (Travel Name)

[Approve]  [Deny]
```

All supported data types (credit cards, names, addresses, bank accounts, phone, email, SSN, passport, custom) work the same way as in Telegram. Type `cancel` at any step to abort.

## Emergency Controls

Block all agent actions instantly:

```
/snapper-block
→ Are you sure? This will block ALL agent actions.
  [CONFIRM BLOCK ALL] [Cancel]
```

Resume normal operation:
```
/snapper-unblock
→ ✅ Normal operation resumed.
```

## Multiple Bots

If you use both Snapper and OpenClaw with Slack, keep them as **separate Slack apps**:

| Service | Slack App Name | Purpose |
|---------|---------------|---------|
| Snapper | Snapper Approval Bot | Rule testing, approvals, PII vault, emergency controls |
| OpenClaw | OpenClaw Bot | AI chat interface |

This prevents command conflicts and keeps conversations separate.

## Troubleshooting

### Bot not responding to slash commands

1. Check that the app is installed to your workspace (OAuth & Permissions → Install)
2. Verify `SLACK_BOT_TOKEN` and `SLACK_APP_TOKEN` are set in `.env`
3. Restart containers: `docker compose up -d --force-recreate`
4. Check logs: `docker compose logs app | grep -i slack`
5. Verify Socket Mode is enabled in the Slack app settings

### Socket Mode disconnects

Socket Mode connections can drop if the app restarts. Snapper auto-reconnects, but check:
- App logs for reconnection messages
- That the `SLACK_APP_TOKEN` (`xapp-...`) is valid

### Slash commands not showing in Slack

1. Verify all 11 commands are defined in the Slack app (Slash Commands page)
2. Re-install the app to your workspace if you added commands after the initial install
3. Try typing `/snapper-` — Slack should autocomplete available commands

### Notifications going to Telegram instead of Slack

Check the agent's `owner_chat_id`:
- Must start with `U` (e.g., `U0ACYA78DSR`) for Slack routing
- Numeric values route to Telegram
- Update via dashboard (edit agent) or API

### "not_authed" errors in logs

Your `SLACK_BOT_TOKEN` is invalid or expired. Generate a new one from OAuth & Permissions in your Slack app settings.

## Telegram vs Slack

Both notification channels are fully supported with feature parity. Pick whichever you prefer (or use both for different agents):

| Feature | Telegram | Slack |
|---------|----------|-------|
| Approval notifications | Yes | Yes |
| Rule testing | `/test run <cmd>` | `/snapper-test run <cmd>` |
| PII vault management | `/vault` (multi-step DM) | `/snapper-vault` (multi-step DM) |
| Trust scoring | `/trust` | `/snapper-trust` |
| Emergency controls | `/block` / `/unblock` | `/snapper-block` / `/snapper-unblock` |
| Connection mode | Webhook (needs public URL) | Socket Mode (no public URL needed) |
| Quick-action buttons | Inline keyboard | Block Kit buttons |
| Setup complexity | Create bot + set webhook | Create app + enable Socket Mode |

## Security Notes

- **Bot and app tokens are secrets** — Never commit them to git or share publicly
- **Socket Mode** — All communication is outbound from Snapper to Slack's servers, so no inbound ports or public URLs are needed
- **DM isolation** — Approval notifications are sent as DMs to the agent owner, not to channels
- **Emergency block** — Creates a priority-10000 deny rule that overrides all others

## Prefer Telegram?

Snapper also supports a full-featured Telegram bot with inline buttons and webhook-based notifications. See [Telegram Setup Guide](TELEGRAM_SETUP.md).
