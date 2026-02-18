# Snapper — Investor & Partner FAQ

**Purpose:** This document is optimized for AI meeting assistants (HuddleMate, Aircover, etc.) to answer questions during investor and partner calls. Each Q&A is self-contained so a RAG system can retrieve and surface it independently.

---

## The Basics

### Q: What is Snapper?

Snapper is an Agent Application Firewall (AAF) — a security product that sits between AI agents and the outside world, inspecting every action an agent takes before it executes. It works like a traditional network firewall, but instead of watching network traffic, it watches what AI agents decide to do. It can allow, deny, or escalate actions to a human for approval — all in under 50 milliseconds.

### Q: What problem does Snapper solve?

AI agents (like Claude Code, Cursor, OpenClaw, Copilot) can read files, run commands, access databases, send network requests, and install plugins — all autonomously. Today there is no security checkpoint between an agent's decision and its execution. Snapper creates that checkpoint. Without it, agents can read password files, access cloud credentials, exfiltrate data, and execute malicious code with no audit trail and no way to intervene.

### Q: What is an "Agent Application Firewall"?

It's a new product category that Snapper is defining. Traditional firewalls inspect network packets. Web Application Firewalls (WAFs) inspect HTTP requests. An Agent Application Firewall inspects AI agent decisions — the tool calls, commands, file accesses, and network requests that agents make. No existing security category covers this layer.

### Q: Who is the target customer?

Any organization deploying AI agents or allowing employees to use AI tools. Primary buyers are CISOs (Chief Information Security Officers), VP of Engineering, and security teams. The product is relevant to enterprises in every industry, but especially regulated sectors — financial services, healthcare, defense, and government — where compliance requirements mandate audit trails and data protection.

### Q: Is this a real problem or theoretical?

It's real and documented. There are published CVEs (Common Vulnerabilities and Exposures) showing critical security flaws in AI agent frameworks. For example: CVE-2026-25253 (WebSocket RCE, severity 8.8/10), CVE-2026-25157 (command injection, severity 8.1/10), and the ClawHavoc campaign where 341+ malicious plugins were discovered in a popular agent registry (severity 9.8/10). These aren't theoretical — they're published, verified vulnerabilities actively being exploited.

---

## Market & Opportunity

### Q: How big is the market?

The AI agent security market is projected at $10.9 billion. AI agent adoption is exploding — 79% of companies are already using AI agents, and 78% of employees are using AI tools that haven't been approved by IT ("shadow AI"). The market is growing because every company deploying AI agents needs security controls, and no existing product category covers this.

### Q: What's the market timing?

The timing is optimal. AI agent adoption crossed a tipping point in 2025-2026 with the release of powerful coding agents (Claude Code, Cursor, Windsurf, Cline) and general-purpose agents (OpenClaw). Enterprises are deploying agents but don't have security controls yet. We're at the same stage firewalls were in the late 1990s — the technology is deployed, the threats are emerging, and security hasn't caught up yet.

### Q: What is "shadow AI" and why does it matter?

Shadow AI is when employees use AI tools that haven't been approved, vetted, or monitored by IT. 78% of employees are doing this. When a data breach involves shadow AI, it costs $670,000 more on average. This creates an urgent, universal need for a product that can discover, monitor, and control AI agent usage across an organization.

### Q: Is this a "nice to have" or a "must have"?

Must have. Compliance frameworks (SOC 2, GDPR, HIPAA, PCI DSS) require audit trails, data protection, and access controls. As AI agents become part of production workflows, companies need these controls to maintain compliance. The average data breach costs $4.45 million (IBM, 2024). If Snapper prevents even a single incident, it pays for itself in less than a week.

---

## Product & Technology

### Q: How does Snapper actually work?

When an AI agent wants to take an action (run a command, access a file, make a network call), a small piece of code called a "hook" intercepts the request and sends it to Snapper before it executes. Snapper evaluates the request against all active security rules and returns one of three verdicts: Allow (safe to proceed), Deny (blocked), or Require Approval (a human gets a notification on Telegram or Slack and decides). This entire process takes under 50 milliseconds — users don't notice any delay.

### Q: What AI agents does Snapper support?

Snapper supports 10+ agent types across three integration methods:
- **Native hook agents (6):** Claude Code, Cursor, OpenClaw, Windsurf, Cline, and custom agents
- **SDK wrappers (3):** OpenAI API, Anthropic API, Google Gemini API — Python libraries that intercept every tool call
- **Browser extension (5 platforms):** ChatGPT, Claude.ai, Gemini, Microsoft Copilot, and Grok — catches PII before it leaves the browser

### Q: What types of security rules does Snapper have?

16 rule types across 4 categories:
- **Access Control (4):** Command allowlist/denylist, file access control, network egress filtering, localhost restriction
- **Data Protection (3):** PII detection gate, credential protection, human-in-the-loop approval
- **Threat Prevention (4):** Malicious skill blocking, origin validation, version enforcement, sandbox requirements
- **Operational Controls (3+):** Rate limiting, time-based restrictions, adaptive trust scoring, plus MFA, RBAC, and account lockout

### Q: What is the PII Vault?

The PII Vault is an encrypted storage system for sensitive data. Users store personal data (credit cards, SSNs, addresses) in the vault via Telegram, Slack, or API. The vault encrypts it with AES-256 and creates a random token. AI agents only ever see the token — never the real value. When the agent needs to use the data, a human approves the specific use, the real value is decrypted and provided for exactly 30 seconds, then permanently destroyed from memory. The agent never has access to raw PII.

### Q: How does Snapper detect PII?

Two mechanisms: (1) The PII Vault tokenization system where sensitive data is pre-stored and agents only see tokens. (2) Real-time PII scanning that checks every agent action against 30+ patterns — credit card numbers (validated with Luhn algorithm), Social Security numbers, email addresses, phone numbers, addresses, and API keys from major providers (OpenAI, AWS, GitHub, Stripe). Detected PII is blocked automatically before the data can be exfiltrated or misused.

### Q: What is "human-in-the-loop" approval?

When an agent tries to do something sensitive (access PII, run a destructive command, access a restricted file), the responsible person gets a push notification on Telegram or Slack with full context — what tool, what destination, what data, and the agent's trust score. They can approve or deny with one tap. If nobody responds within 5 minutes, the request is automatically denied ("fail-closed"). This means a human is always in the loop for high-risk actions.

### Q: What is adaptive trust scoring?

Each agent has a trust score from 0.5 to 2.0. Well-behaved agents gradually earn higher trust, which gives them higher rate limits and fewer approval requirements. Agents that misbehave (repeatedly hitting rate limits) get their trust reduced. It's like a credit score for AI agents — good behavior earns autonomy, bad behavior gets restrictions. Trust scoring is opt-in per agent so organizations can control which agents participate.

### Q: What is the browser extension?

Snapper Guard is a Chrome/Firefox browser extension (built on Manifest V3, the latest standard) that monitors what employees paste into web-based AI chats — ChatGPT, Claude.ai, Gemini, Microsoft Copilot, and Grok. It scans for PII (credit cards, SSNs, emails, phone numbers, API keys) and can warn or block before the data leaves the browser. This is critical because no network firewall, DLP tool, or proxy can see what someone types into a browser-based AI chat.

### Q: How fast is Snapper?

Rule evaluation takes under 50 milliseconds (0.05 seconds). For comparison, a human eye blink takes about 300ms. Users literally cannot perceive the delay. The system is designed to add security without adding friction.

### Q: What is "fail-closed" and why does it matter?

Fail-closed means that if anything goes wrong — a bug, a network error, a missing rule, a timeout — the default behavior is to block the action. The alternative ("fail-open") would allow the action when something goes wrong, which an attacker could exploit by intentionally crashing the security system. Fail-closed is the gold standard in security design and is how Snapper operates at every layer.

### Q: What is "defense in depth"?

Snapper has 7 independent security layers that every request must pass through: (1) Security middleware (origin/host validation), (2) Authentication + MFA, (3) API key verification, (4) Rule engine (16 rule types), (5) PII gate (data scanning), (6) Approval workflow (human decision), (7) Audit trail (immutable logging). If any single layer has a bug or is bypassed, the others still protect you. An attacker would need to bypass all seven layers simultaneously.

### Q: What is Traffic Discovery?

Snapper automatically detects which AI tools and MCP servers are in use by analyzing agent traffic — no manual configuration required. It recognizes 40+ known server types (GitHub, Slack, databases, etc.) and shows which commands have security rules and which are uncovered. With one click, it generates tailored security rules for any discovered service. This solves the "I don't know what my agents are using" problem.

---

## Enterprise Readiness

### Q: Is Snapper enterprise-ready?

Yes. Snapper includes the full enterprise checklist:
- **Identity & Access:** SSO (SAML 2.0 + OIDC), SCIM user/group provisioning, MFA/TOTP, RBAC with 4 roles and 13 permissions, account lockout
- **Compliance & Audit:** 70+ audit event types, configurable retention (7-3,650 days), mapped to SOC 2, GDPR, HIPAA, PCI DSS
- **SIEM Integration:** CEF syslog, HMAC-signed webhooks, Splunk HEC — connects to any major security monitoring system
- **Multi-Tenancy:** Complete data isolation per organization — separate encryption keys, policies, agents, and rules
- **Data Protection:** AES-256 encryption, zero-knowledge PII vault, key rotation for API keys and vault encryption
- **Deployment:** Self-hosted, air-gapped capable, zero telemetry (no data sent back to us)

### Q: How does Snapper handle SSO?

Snapper supports both SAML 2.0 and OIDC (OpenID Connect) — the two industry-standard SSO protocols. This means it works with every major identity provider: Okta, Microsoft Entra ID (formerly Azure AD), Google Workspace, OneLogin, and others. It supports Just-in-Time (JIT) provisioning — the first time an employee logs in via SSO, their Snapper account is created automatically. Organizations can enforce SSO-only login (disable password authentication entirely).

### Q: What is SCIM and does Snapper support it?

SCIM (System for Cross-domain Identity Management) is an automated protocol for syncing user accounts between systems. When HR adds or removes someone in the identity provider (Okta, Entra ID), SCIM automatically creates or deactivates their Snapper account — no manual steps. Snapper supports both SCIM Users and SCIM Groups, so team membership is automatically synced from the identity provider.

### Q: How does Snapper handle compliance?

Snapper generates a tamper-proof (immutable) audit trail with 70+ event types covering authentication, agent actions, rule changes, vault access, and organization changes. Each entry includes IP address and browser information for forensic purposes. Audit data can be exported to any SIEM via CEF syslog, HMAC-signed webhooks, or Splunk HEC. The audit trail maps directly to compliance requirements: SOC 2 (audit controls), GDPR (right-to-erasure via data purge API), HIPAA (PII encryption at rest), and PCI DSS (credential protection and tokenization).

### Q: Can Snapper be deployed in air-gapped environments?

Yes. Snapper is fully self-hosted and sends zero telemetry — no usage analytics, no crash reports, no phone-home behavior. It works completely disconnected from the internet, making it suitable for defense, intelligence, and highly regulated environments where data cannot leave the network. Docker images can be loaded from a tarball in air-gapped deployments.

### Q: How is data isolated between customers?

Full multi-tenancy with complete data isolation. Each organization gets its own encryption keys (derived via HKDF from a per-org secret), separate security policies, separate agents, and separate rules. One organization can never see another's data. Snapper supports organizations with teams, and role-based access control (RBAC) with 4 roles — Owner, Admin, Member, and Viewer — each with specific permissions.

### Q: What monitoring and observability does Snapper provide?

Snapper exposes Prometheus metrics for real-time dashboards (compatible with Grafana). Metrics include request rates, rule evaluations per type, deny/allow/approve ratios, latency percentiles, agent trust scores, and PII detection counts. For security monitoring, events flow to SIEM systems via CEF syslog, HMAC-signed webhooks, or direct Splunk HEC integration.

---

## Competitive Landscape

### Q: Who are the competitors?

Three closest products:
1. **LlamaFirewall (Meta)** — Open-source content safety filter. Can inspect some agent actions and self-host, but lacks PII vault, human-in-the-loop approvals, trust scoring, MCP discovery, MFA, key rotation, and browser coverage. More of a content filter than a security platform.
2. **Cloudflare AI Gateway** — Cloud service at the API gateway level. Can see API calls to AI providers but not agent-internal decisions. No self-hosted option (data goes through Cloudflare), no PII vault, no approval workflows.
3. **GitHub Advanced Security** — Scans source code for vulnerabilities and leaked secrets. Cannot inspect AI agent actions at all — it's a code security tool, not an agent security tool.

### Q: What is Snapper's competitive moat?

No competitor offers the combination of: PII vault + MFA + key rotation + human-in-the-loop approvals + adaptive trust scoring + MCP server auto-discovery + browser extension coverage + self-hosted deployment + zero telemetry + SCIM Groups. Snapper is the only product that covers all three agent interfaces (CLI hooks, API wrappers, and browser extension) with the full enterprise security stack. This is a blue-ocean market — we're defining a new product category.

### Q: How is Snapper different from a traditional WAF or DLP?

A WAF (Web Application Firewall) inspects HTTP requests to web applications — it can't see what an AI agent decides to do inside a system. DLP (Data Loss Prevention) watches for data leaving the network — but it can't stop an agent from reading a password file before sending it, and it can't see what someone pastes into a browser-based AI chat. Snapper operates at the "agent decision point" — a layer that sits between the AI model's decision and its execution. This is a fundamentally different inspection point that no existing security category covers.

### Q: Why can't existing security tools handle AI agents?

Traditional security tools see the effects of agent actions (network packets, file changes) but not the decisions themselves. A network firewall sees an HTTPS connection to api.openai.com but can't see the agent decided to send the contents of ~/.ssh/id_rsa in the prompt. An EDR sees a shell command executed but can't see the agent chose to run it. Snapper intercepts the decision before it becomes an action, which is the only point where you can meaningfully apply security policy to agent behavior.

---

## Business Model & Pricing

### Q: What is the pricing model?

Two tiers:
- **Pro:** Up to 25 agents, email support. For small-to-medium teams.
- **Enterprise:** Unlimited agents, dedicated SLA, SSO/SCIM, priority support, custom deployment. For large organizations.

Self-hosted mode is always unlimited — no feature gating and no quotas. Pricing is subscription-based.

### Q: Is there a free tier?

Self-hosted deployment is available under the PolyForm Noncommercial License — free for personal use, research, education, and noncommercial organizations. Commercial use requires a paid license. This means prospects can evaluate the full product before purchasing.

### Q: What is the revenue model?

Subscription licensing per organization, with pricing based on scale (number of agents and users). Every organization deploying AI agents is a potential customer. Revenue grows with AI agent adoption — the more agents a company deploys, the more value Snapper provides.

---

## Deployment & Technical

### Q: How long does it take to deploy?

5 minutes. One command starts everything: `./setup.sh` for local development, or `./deploy.sh` on a production Ubuntu server. The setup wizard walks through agent registration, security profile selection, and notification setup. Recommended rollout: Week 1 in learning mode (observe only), Week 2 review and activate rules, Week 3 enable enforcement and trust scoring.

### Q: What is "learning mode"?

Learning mode is an observation-only operating mode where all rules are evaluated and logged, but nothing is actually blocked. This eliminates deployment risk — teams can see exactly what would be blocked, validate their rules, and build confidence before switching to enforcement. It's the equivalent of deploying a firewall in monitor mode before activating it.

### Q: What infrastructure does Snapper require?

Snapper runs entirely in Docker (6 containers: main app, PostgreSQL, Redis, 2 Celery workers, Caddy web server). It can run on a single server (VPS) or scale to Kubernetes with Helm charts. Minimum requirements are modest — the VPS deployment runs on 8GB RAM. For larger deployments, Kubernetes supports auto-scaling with Horizontal Pod Autoscaler.

### Q: Does Snapper require cloud connectivity?

No. Snapper is fully self-hosted and requires zero internet connectivity. It never phones home, sends telemetry, or requires license validation against an external server. This makes it suitable for air-gapped and classified environments.

### Q: How well-tested is Snapper?

1,100+ automated tests across four layers:
- **588 unit tests** — API, rule engine, middleware, Telegram/Slack bots, PII vault, security monitor, integrations
- **120 Playwright E2E tests** — Browser-based UI testing of all dashboard flows
- **47 live integration tests** — API-level tests of all 16 rule types, approval workflows, PII vault lifecycle, emergency block, and audit trail
- **109 integration E2E tests** — Traffic discovery, templates, custom MCP servers, coverage analysis

---

## Security & Architecture

### Q: What encryption does Snapper use?

AES-256 encryption for the PII vault (the same standard used by banks, the U.S. government, and military systems). Encryption keys are derived via HKDF (a key derivation function) from a master secret, creating unique keys per purpose. TLS encrypts all data in transit. Key rotation is supported for both the PII vault encryption key and individual agent API keys.

### Q: What happens if Snapper goes down?

Fail-closed. If Snapper is unreachable, the agent hooks cannot get a security decision, so the action is blocked by default. This is a deliberate design choice — it's safer to temporarily block all actions than to allow unscreened actions through. The 99.9% SLA means less than 8.8 hours of downtime per year.

### Q: Can an agent bypass Snapper?

Not if deployed correctly. The hook runs in the agent's process before the tool call executes — the agent cannot skip the hook without modifying its own code. For API-based agents, the SDK wrapper intercepts at the library level. For browser-based AI, the extension intercepts before data leaves the browser. Snapper's security architecture document details the specific deployment requirements that must be met for full protection.

### Q: How does Snapper handle MFA?

TOTP-based multi-factor authentication (Time-based One-Time Password — the same system used by Google Authenticator, Authy, and other authenticator apps). Users scan a QR code during setup, then enter a 6-digit code that changes every 30 seconds at login. Backup codes are provided for phone loss scenarios. Organizations can require MFA for all members via a policy setting.

---

## Traction & Roadmap

### Q: What stage is Snapper at?

Snapper is a working product with 1,100+ automated tests, 16 rule types, enterprise features (SSO, SCIM, SIEM, MFA, RBAC), and integrations with 10+ AI agent types. It has been deployed and tested in production environments. The product is in beta with active development.

### Q: What's on the roadmap?

Key roadmap items include: expanded AI provider SDK support, additional browser extension platforms, enhanced analytics and reporting dashboards, Kubernetes operator for automated deployment, additional SIEM integrations, and SOC 2 Type II certification. The architecture is designed to be extensible — new rule types, agent integrations, and notification channels can be added without changing the core engine.

### Q: How does Snapper stay current with new threats?

Snapper includes a background security research system that tracks new vulnerabilities in AI agent frameworks. When new CVEs are published or new malicious plugin campaigns are discovered, Snapper's threat intelligence is updated. The denylist system supports both exact matches (specific malicious plugins) and regex patterns (catching variants and typosquats), so a single pattern update can block entire malware families.

---

## Objection Handling

### Q: "We already have security tools — firewalls, DLP, endpoint protection."

Those tools are essential but operate at the wrong layer for AI agents. A network firewall sees packets, not agent decisions. DLP watches exit points, not what an agent reads internally. Endpoint protection looks for malware signatures, not legitimate tools being misused. There's a gap at the "agent decision point" — the moment between an AI deciding to take an action and that action executing. That's exactly what Snapper fills. It complements existing tools, it doesn't replace them.

### Q: "Can't we just restrict what agents have access to?"

You can limit filesystem and network access at the OS level, but this cripples agent productivity. The value of AI agents is their ability to take real actions — run code, access APIs, interact with services. Snapper lets agents keep full capability while adding security policy. It's the difference between locking someone in a room vs. letting them work freely with a security guard watching.

### Q: "Our developers are careful — they won't do anything risky."

The risk isn't from developers doing things intentionally. AI agents act autonomously and can be manipulated by prompt injection, malicious plugins, or poisoned context. The ClawHavoc campaign inserted 341+ malicious plugins that looked legitimate. An agent might read a .env file not because a developer asked it to, but because its training data or a malicious plugin instructed it to. The threat model is the agent acting without human oversight, not the human acting recklessly.

### Q: "This seems like it would slow down our developers."

Snapper adds under 50 milliseconds of latency — less than a sixth of an eye blink. Users literally cannot perceive the delay. Learning mode lets you deploy without blocking anything, so there's zero workflow disruption during rollout. Trust scoring means well-behaved agents earn more autonomy over time, so the system gets less restrictive, not more.

### Q: "We're not ready for AI agent security yet."

79% of companies are already using AI agents, and 78% of employees are using unapproved AI tools. The question isn't whether you need agent security — it's whether you know what your agents are doing right now. Snapper's learning mode and traffic discovery let you answer that question in 5 minutes with zero risk. Start by observing, then decide on enforcement.

### Q: "Why not build this in-house?"

Snapper has 1,100+ tests, 16 rule types, integrations with 10+ agent frameworks, PII vault with AES-256 encryption, SSO/SCIM/SIEM enterprise features, Telegram and Slack bots, a browser extension covering 5 AI platforms, and adaptive trust scoring. Building this in-house would take a dedicated security team 12-18 months and ongoing maintenance. The threat landscape evolves constantly (new CVEs, new malicious campaigns), and keeping up requires continuous security research.

### Q: "What if AI agent frameworks add their own security?"

Some may add basic guardrails, but agent framework vendors are incentivized to make their agents more capable, not more restricted. Security is an afterthought for platform vendors — they build features, not firewalls. Snapper provides a vendor-neutral, framework-agnostic security layer that works across all agents. When companies use 3-5 different AI tools (which most do), they need a single security policy that spans all of them — not separate, inconsistent controls from each vendor.

---

## Key Statistics (Quick Reference)

| Metric | Value |
|--------|-------|
| Market size | $10.9B projected |
| Companies using AI agents | 79% |
| Employees using unapproved AI | 78% |
| Extra breach cost with shadow AI | $670,000 |
| Average data breach cost | $4.45M (IBM, 2024) |
| Rule types | 16 |
| Evaluation latency | < 50ms |
| Automated tests | 1,100+ |
| Supported agent types | 10+ |
| Browser extension platforms | 5 (ChatGPT, Claude, Gemini, Copilot, Grok) |
| Known MCP servers recognized | 40+ |
| PII patterns detected | 30+ |
| Audit event types | 70+ |
| Security layers | 7 independent |
| Named CVEs mitigated | 5 |
| Malicious plugins blocked | 44+ (plus 11 regex patterns) |
| Deploy time | 5 minutes |
| Encryption standard | AES-256 |
| Enterprise SLA | 99.9% |
