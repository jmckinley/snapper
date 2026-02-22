# Browser Extension

Snapper's Chrome extension enforces security policy directly inside AI chat interfaces. It monitors 70+ AI services across three integration tiers, scans for PII before submission, blocks or gates tool calls in real time, and reports shadow AI usage back to your Snapper instance.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Supported AI Services](#supported-ai-services)
3. [Tool Call Interception](#tool-call-interception)
4. [PII Scanning](#pii-scanning)
5. [Shadow AI Detection](#shadow-ai-detection)
6. [Config Sync (Phone-Home Updates)](#config-sync-phone-home-updates)
7. [Authentication](#authentication)
8. [Settings Reference](#settings-reference)
9. [Enterprise Managed Deployment](#enterprise-managed-deployment)
10. [Popup Dashboard](#popup-dashboard)
11. [Fail-Safe Behavior](#fail-safe-behavior)
12. [File Reference](#file-reference)

---

## Architecture Overview

The extension is built on Chrome Manifest V3 and consists of four layers:

```
┌──────────────────────────────────────────────────────┐
│                   Popup (popup.html)                 │
│  Status dot ・ Recent decisions ・ Visit stats        │
├──────────────────────────────────────────────────────┤
│              Settings Page (options.html)             │
│  Connection ・ Auth ・ PII ・ Service toggles ・ Sync  │
├──────────────────────────────────────────────────────┤
│            Background Service Worker                 │
│  background.js                                       │
│  ├─ Tool evaluation (POST /rules/evaluate)           │
│  ├─ Approval polling (GET /approvals/{id}/status)    │
│  ├─ Config sync (GET /extension/config, ETag-aware)  │
│  ├─ Shadow AI reporting (POST /shadow-ai/report)     │
│  ├─ Auth token management (refresh, retry on 401)    │
│  ├─ Device fingerprinting (UUID + platform metadata) │
│  └─ Session cache (allow decisions, 5-min TTL)       │
├──────────────────────────────────────────────────────┤
│               Content Scripts                        │
│  Per-service (Tier 1):                               │
│    chatgpt.js ・ claude.js ・ gemini.js ・ copilot.js │
│    grok.js ・ deepseek.js ・ perplexity.js            │
│    github-copilot.js                                 │
│  Generic (Tier 2): generic-ai.js                     │
│  Shared: shared.js ・ pii-scanner.js                 │
│  Styles: overlay.css                                 │
└──────────────────────────────────────────────────────┘
         │                          │
         ▼                          ▼
   AI Service DOM              Snapper Server
   (tool output,              /api/v1/rules/evaluate
    input fields,             /api/v1/approvals/{id}/status
    file uploads)             /api/v1/extension/config
                              /api/v1/shadow-ai/report
                              /api/v1/auth/extension/login
```

**Data flow for a tool call:**

1. Content script detects tool output in the DOM (e.g., code interpreter result block)
2. Sends message to background service worker via `chrome.runtime.sendMessage()`
3. Background worker POSTs to `/api/v1/rules/evaluate` with tool name, input, and agent ID
4. Server evaluates against all active rules and returns a decision
5. Content script renders the appropriate overlay (allow = passthrough, deny = red banner, require_approval = yellow banner + polling)

---

## Supported AI Services

### Tier 1 — Deep Integration (8 services)

Custom content scripts with service-specific DOM selectors, tool-type detection, and fetch monkey-patching.

| Service | Domains | Tools Detected |
|---------|---------|----------------|
| **ChatGPT** | chatgpt.com, chat.openai.com | Code Interpreter, Web Browsing, DALL-E, File Upload |
| **Claude** | claude.ai | Tool Use, Computer Use, Artifacts, File Analysis |
| **Gemini** | gemini.google.com | Extensions, Code Execution, Web Search |
| **Microsoft Copilot** | copilot.microsoft.com | Web Search, Code Generation, Image Creator |
| **Grok** | grok.com | Web Search, Code Execution, Image Generation |
| **DeepSeek** | chat.deepseek.com | Code Execution, Web Search, File Upload (fetch intercept) |
| **Perplexity** | perplexity.ai | Pro Search, File Analysis |
| **GitHub Copilot Web** | github.com/copilot | Code Generation, Workspace Context |

### Tier 2 — Standard Monitoring (20 services)

Monitored via `generic-ai.js` with generic DOM selectors for input fields, submit buttons, and file uploads. PII scanning and shadow AI tracking are fully supported.

| Category | Services |
|----------|----------|
| **Chat** | Mistral Le Chat, Poe, Meta AI, HuggingChat |
| **Coding** | Cursor, Replit, v0.dev, bolt.new, Lovable |
| **Writing** | Jasper, Copy.ai, Writesonic, Notion AI, Writer, Grammarly |
| **Image/Video** | Midjourney, Leonardo.ai, Ideogram, Runway, Sora |

### Tier 3 — Visit-Only Tracking (31 services)

Page navigations detected via `chrome.webNavigation.onCompleted` and reported as shadow AI visits. No DOM interception.

Together AI, Cohere, Anyscale, Fireworks AI, Groq, OpenRouter, Replicate, Stability AI, PhotoRoom, Canva AI, Adobe Firefly, Descript, Otter.ai, Coda AI, Tome, Gamma, Beautiful.ai, Tabnine, Codeium, Sourcegraph Cody, Amazon Q, Windsurf, Phind, You.com, Pi AI, Character.AI, Inflection, and others.

### Service Toggles

Each service can be individually enabled or disabled in the Settings page under the **AI Services** tab. Services are organized by category (All, Chat, Coding, Writing, Image/Video) with tier and risk badges for visibility.

The server can also remotely disable services via the `blocked_services` field in the config sync response — no extension update required.

---

## Tool Call Interception

### How Detection Works

Tier 1 content scripts use three interception methods:

**1. DOM Observation** — A `MutationObserver` watches `document.body` for new nodes matching service-specific selectors (e.g., `[data-testid*="code-interpreter"]` on ChatGPT, `[class*="tool_use"]` on Claude).

**2. Fetch Monkey-Patching** — On ChatGPT and DeepSeek, `window.fetch` is wrapped to intercept POST requests containing file attachments or tool invocations before they reach the API.

**3. Event Listeners** — File `<input>` change events, drag-and-drop, and clipboard paste events are captured to detect file uploads and PII exposure.

### Tool Types

| Category | Tool Names | Request Type |
|----------|------------|--------------|
| Code Execution | `code_interpreter`, `artifact_execute`, `code_execution`, `code_generation` | `command` |
| Web Access | `web_browse`, `web_search`, `pro_search`, `extension` (Gemini) | `network` |
| File Operations | `file_upload`, `file_analysis` | `file_access` |
| Image Generation | `dalle`, `image_generation`, `image_creator` | `tool` |
| Agent Tools | `computer_use` (Claude), `workspace_context` (GitHub Copilot), `tool_use` | `tool` |

### Evaluation Flow

```
Content Script                    Background Worker                 Snapper Server
     │                                  │                                │
     │  sendMessage({type:"evaluate"})  │                                │
     ├─────────────────────────────────>│                                │
     │                                  │  POST /api/v1/rules/evaluate   │
     │                                  ├───────────────────────────────>│
     │                                  │  {decision, reason, rule_name} │
     │                                  │<───────────────────────────────┤
     │  {decision: "allow"}             │                                │
     │<─────────────────────────────────┤                                │
     │  → passthrough                   │                                │
     │                                  │                                │
     │  {decision: "deny"}              │                                │
     │<─────────────────────────────────┤                                │
     │  → red deny overlay              │                                │
     │                                  │                                │
     │  {decision: "require_approval"}  │                                │
     │<─────────────────────────────────┤                                │
     │  → yellow approval banner        │                                │
     │  → poll every 5s for up to 5min  │                                │
```

### Session Caching

Allow decisions are cached in memory for **5 minutes** (keyed by `toolName:JSON(toolInput)`). Deny and require_approval decisions are **never cached** — every occurrence goes to the server for a fresh evaluation.

### Overlay UI

- **Deny:** Red inline banner on the blocked tool output showing the tool name, matched rule, and denial reason
- **Approval:** Yellow pulsing banner with clock icon and approval request ID. Polls `/api/v1/approvals/{id}/status` every 5 seconds for up to 5 minutes
- **Allow:** No overlay — tool output renders normally

---

## PII Scanning

Client-side PII detection runs **before** user messages are sent, catching sensitive data at the input boundary.

### Detected PII Types (18 patterns)

| Category | Patterns |
|----------|----------|
| **Financial** | Visa, Mastercard, Amex, Discover credit cards, bank routing numbers, IBAN |
| **Identity** | SSN (with/without dashes), US passport, driver's license, date of birth, medical record numbers |
| **Contact** | Email addresses, US phone numbers, international phone numbers, IPv4 addresses |
| **Credentials** | AWS access keys, AWS secret keys, generic API keys (`api_key=...`), Bearer tokens, PEM private keys |
| **Snapper** | Vault tokens (`{{SNAPPER_VAULT:<hex>}}`) |

### Blocking Modes

| Mode | Behavior |
|------|----------|
| **Warn** (default) | Modal shows detected PII with "Cancel" and "Send Anyway" buttons. User can override. |
| **Block** | Modal shows detected PII with "OK" button only. Submission is prevented — no bypass. |

### Where Scanning Runs

- **Input fields:** Scans the textarea or contenteditable element when the user clicks the send/submit button
- **Clipboard:** Monitors paste events in capture phase. In warn mode, shows a notification. In block mode, prevents the paste entirely.
- **File uploads:** Detected via `<input type="file">` change events and drag-and-drop — evaluated as `file_upload` tool calls

---

## Shadow AI Detection

The extension identifies unauthorized AI service usage and reports it to Snapper for enterprise visibility.

### Detection Tiers

| Tier | Method | Reporting |
|------|--------|-----------|
| **Tier 2** | Content script fires `report_visit` message on page load | Immediate |
| **Tier 3** | `chrome.webNavigation.onCompleted` detects navigation to known AI domains | Immediate |

### Deduplication

Visit reports are deduplicated per domain per hour — navigating to the same AI service multiple times within an hour generates only one report.

### Reporting Endpoint

```
POST /api/v1/shadow-ai/report
{
  "detection_type": "browser_visit",
  "hostname": "together.xyz",
  "url": "https://together.xyz/chat",
  "source": "together_ai",
  "agent_id": "browser-extension"
}
```

### Disabling

Set **Shadow AI Tracking** to off in Settings. No visit reports will be sent.

---

## Config Sync (Phone-Home Updates)

The extension periodically fetches configuration updates from the Snapper server, allowing administrators to push policy changes without requiring an extension update.

### How It Works

1. On startup, a sync alarm fires after **1 minute**
2. Background worker calls `GET /api/v1/extension/config` with an `If-None-Match` ETag header
3. If config is unchanged, the server responds **304 Not Modified** (zero bandwidth)
4. If changed, the server sends a new config bundle and ETag
5. The alarm repeats at the configured interval (default: **60 minutes**)

### What Gets Synced

| Field | Purpose |
|-------|---------|
| `service_registry` | Overrides the hardcoded 70+ service list — add new services, change tiers, update domains |
| `blocked_services` | Array of service source IDs to disable (e.g., `["chatgpt", "deepseek"]`) |
| `feature_flags` | Future feature toggles pushed from server |
| `visit_domains` | Updated Tier 3 domain list for shadow AI tracking |
| `sync_interval_seconds` | Server can override how often the extension checks for updates |
| `config_version` | Version identifier logged for debugging |

### Auto-Update of Rules

When the server pushes an updated `service_registry`, the extension immediately uses it for all future evaluations. This means you can:

- **Add new AI services** to monitor without shipping an extension update
- **Change service tiers** (e.g., promote a Tier 2 service to Tier 1 behavior)
- **Block specific services** enterprise-wide by adding them to `blocked_services`
- **Update detection domains** as AI services change their URLs
- **Adjust sync frequency** from the server side (e.g., tighten to 15 minutes during an incident)

### Sync Settings

| Setting | Options | Default |
|---------|---------|---------|
| **Config Auto-Sync** | On / Off | On |
| **Sync Interval** | 15 min, 60 min, 6 hours, Manual only | 60 min |
| **Sync Now** button | Triggers immediate sync | — |

### Sync Status

The popup and settings page display:
- Last sync timestamp (or "never")
- Sync status: "current" (green), "error" (red), or "never" (gray)
- Number of services in synced registry
- Number of blocked services

### Device Tracking

On the first sync per browser session, the extension sends:
- **X-Device-Id** — A persistent UUID (generated once, stored in local storage)
- **X-Device-Meta** — Platform, language, timezone, CPU cores, memory (sent once per session)

This allows the server to track how many browser instances are running the extension and their environment characteristics.

---

## Authentication

### Sign-In Flow

1. Open **Settings** and enter your email and password
2. Extension calls `POST /api/v1/auth/extension/login`
3. Server returns `access_token`, `refresh_token`, and `expires_in`
4. Tokens are stored in `chrome.storage.local` and persist across browser restarts

### Token Management

- **Bearer token** is included in all API calls (`Authorization: Bearer <token>`)
- **Auto-refresh:** When the token is within 2 minutes of expiry, the background worker calls `/api/v1/auth/extension/refresh` automatically
- **401 retry:** If a request returns 401, the extension refreshes the token once and retries. If still 401, tokens are cleared (user must sign in again)
- **Sign-out** clears all auth tokens from storage

### Role Display

The popup shows the signed-in user's email and role badge (admin, operator, or viewer).

---

## Settings Reference

### Connection

| Setting | Storage Key | Default | Description |
|---------|-------------|---------|-------------|
| **Snapper URL** | `snapper_url` | (empty) | Base URL of your Snapper instance (e.g., `https://snapper.company.com:8443`) |
| **API Key** | `snapper_api_key` | (empty) | API key for `X-API-Key` header authentication |
| **Agent ID** | `agent_id` | `browser-extension` | Identifier sent with every evaluation request |
| **Fail Mode** | `fail_mode` | `closed` | `closed` = deny when unreachable; `open` = allow when unreachable |

### PII & Privacy

| Setting | Storage Key | Default | Description |
|---------|-------------|---------|-------------|
| **PII Scanning** | `pii_scanning` | On | Enable client-side PII detection on input |
| **PII Blocking Mode** | `pii_blocking_mode` | `warn` | `warn` = allow bypass; `block` = prevent submission |
| **Clipboard Monitoring** | `clipboard_monitoring` | On | Scan pasted text for PII |
| **Shadow AI Tracking** | `shadow_ai_tracking` | On | Report Tier 2/3 service visits |

### Config Sync

| Setting | Storage Key | Default | Description |
|---------|-------------|---------|-------------|
| **Auto-Sync** | `config_auto_sync` | On | Periodically fetch config updates |
| **Sync Interval** | `sync_interval_minutes` | 60 | 15, 60, 360 minutes, or 0 (manual only) |

### Per-Service Toggles

Each service has a `{source}_enabled` key (e.g., `chatgpt_enabled`, `claude_enabled`). All default to **true**. Toggling a service off stops all content script activity on that service's domains.

---

## Enterprise Managed Deployment

Chrome's managed storage API allows IT administrators to pre-configure and lock down extension settings via group policy (Windows) or MDM profiles (macOS/ChromeOS).

### Managed Storage Schema

The extension declares a managed storage schema in `manifest.json`. When managed storage values are detected, the Settings page:

- Pre-fills all fields with the managed values
- Disables all inputs (read-only)
- Shows a blue notice: "Settings are managed by your organization"

### Supported Managed Keys

All keys from the [Settings Reference](#settings-reference) are supported, plus:

| Key | Type | Description |
|-----|------|-------------|
| `blocked_services` | `string[]` | Service source IDs to force-disable |

### Example Chrome Policy (macOS)

```xml
<dict>
  <key>snapper_url</key>
  <string>https://snapper.company.com:8443</string>
  <key>snapper_api_key</key>
  <string>your-api-key-here</string>
  <key>fail_mode</key>
  <string>closed</string>
  <key>pii_blocking_mode</key>
  <string>block</string>
  <key>shadow_ai_tracking</key>
  <true/>
  <key>blocked_services</key>
  <array>
    <string>character_ai</string>
    <string>pi_ai</string>
  </array>
</dict>
```

---

## Popup Dashboard

The extension popup provides a quick status overview:

### Status Indicator

| Color | Meaning |
|-------|---------|
| Green | Connected to Snapper server |
| Red | Server unreachable or error |
| Gray | Snapper URL not configured |

### Recent Decisions (last 10)

Each entry shows:
- Decision badge: **allow** (green), **deny** (red), or **approval** (yellow)
- Tool name (e.g., `code_interpreter`, `web_browse`)
- Relative time (e.g., "5s", "2m", "1h", "3d")

### Config Sync Status

Shows last sync time and status. Green = current, red = error.

### Visit Stats

Top 5 shadow AI services visited this session with visit counts.

### Footer Links

- **Dashboard** — Opens Snapper web dashboard in a new tab
- **Settings** — Opens the extension options page

---

## Fail-Safe Behavior

| Mode | When Snapper Is Unreachable | Use Case |
|------|----------------------------|----------|
| **Closed** (default) | All tool calls are **denied**. Red overlay appears. | Security-first environments where blocking is preferred over allowing |
| **Open** | All tool calls are **allowed**. No overlays. | Environments where productivity must not be interrupted by connectivity issues |

The fail mode applies to network errors, timeouts, and any non-2xx response from the server. It does **not** affect PII scanning, which runs entirely client-side.

---

## File Reference

| File | Lines | Purpose |
|------|-------|---------|
| `extension/manifest.json` | 165 | Extension metadata, permissions, content script injection rules, managed storage schema |
| `extension/background.js` | 668 | Service worker: API calls, approval polling, config sync, auth tokens, decision caching |
| `extension/content/shared.js` | 197 | DOM utilities, overlay rendering, evaluation wrapper functions |
| `extension/content/pii-scanner.js` | 236 | 18 PII regex patterns, warning modal, input/clipboard interception |
| `extension/content/chatgpt.js` | 153 | ChatGPT DOM observation, fetch monkey-patching for file uploads |
| `extension/content/claude.js` | 134 | Claude tool_use, computer_use, artifact, file analysis detection |
| `extension/content/gemini.js` | 113 | Gemini extension calls, code execution blocks |
| `extension/content/copilot.js` | 122 | Copilot web search, code generation, image creation |
| `extension/content/grok.js` | 122 | Grok web search, code execution, image generation |
| `extension/content/deepseek.js` | 120 | DeepSeek code/search detection, fetch interception |
| `extension/content/perplexity.js` | 99 | Perplexity pro search, file analysis |
| `extension/content/github-copilot.js` | 101 | GitHub Copilot code generation, workspace context |
| `extension/content/generic-ai.js` | 191 | Generic fallback for Tier 2 services, file upload interception |
| `extension/data/service-registry.js` | 92 | Hardcoded registry of 70+ AI services with tiers, categories, risk levels |
| `extension/popup/popup.html` | 200 | Popup UI: status, decisions, visits, footer links |
| `extension/popup/popup.js` | 166 | Popup logic: connection test, decision rendering, sync status |
| `extension/options/options.html` | 424 | Settings form: connection, auth, PII, services, sync |
| `extension/options/options.js` | 358 | Settings load/save, sign-in/out, service toggles, managed storage detection |
| `extension/styles/overlay.css` | 189 | PII modal, deny banner, approval banner, button styles |

---

## API Endpoints Used

| Endpoint | Method | Purpose | Auth |
|----------|--------|---------|------|
| `/health` | GET | Connection test (popup, settings) | Optional |
| `/api/v1/rules/evaluate` | POST | Evaluate tool calls against policy | X-API-Key + Bearer |
| `/api/v1/approvals/{id}/status` | GET | Poll human-in-the-loop approval | Bearer |
| `/api/v1/extension/config` | GET | Fetch config bundle (ETag-aware) | X-API-Key + Bearer |
| `/api/v1/shadow-ai/report` | POST | Report shadow AI visits | X-API-Key + Bearer |
| `/api/v1/auth/extension/login` | POST | Sign in (email/password) | None |
| `/api/v1/auth/extension/refresh` | POST | Refresh auth token | refresh_token in body |
