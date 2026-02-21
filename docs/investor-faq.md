# Snapper — Investor & Partner FAQ

**Purpose:** This document is optimized for AI meeting assistants (HuddleMate, Aircover, etc.) to answer questions during investor and partner calls. Each Q&A is self-contained so a RAG system can retrieve and surface it independently.

---

## The Basics

### Q: What is Snapper?

Snapper is an Agent Application Firewall (AAF) — a security product that sits between AI agents and the outside world, inspecting every action an agent takes before it executes. It works like a traditional network firewall, but instead of watching network traffic, it watches what AI agents decide to do. It can allow, deny, or escalate actions to a human for approval — all in under 50 milliseconds. Beyond rule-based control, Snapper includes a heuristic bad actor detection engine that identifies multi-step attack patterns, behavioral anomalies, and data exfiltration attempts that no static rule could catch.

### Q: What problem does Snapper solve?

AI agents (like Claude Code, Cursor, OpenClaw, Copilot) can read files, run commands, access databases, send network requests, and install plugins — all autonomously. Today there is no security checkpoint between an agent's decision and its execution. Snapper creates that checkpoint. Without it, agents can read password files, access cloud credentials, exfiltrate data, and execute malicious code with no audit trail and no way to intervene. Worse, a compromised or manipulated agent can execute multi-step attack chains — reading credentials, encoding them, and sending them to an external server — that look innocuous individually but are devastating in combination. Snapper detects these patterns automatically.

### Q: What is an "Agent Application Firewall"?

It's a new product category that Snapper is defining. Traditional firewalls inspect network packets. Web Application Firewalls (WAFs) inspect HTTP requests. An Agent Application Firewall inspects AI agent decisions — the tool calls, commands, file accesses, and network requests that agents make. No existing security category covers this layer. Snapper goes beyond simple rule matching with behavioral analysis — building per-agent profiles over time and detecting deviations that indicate compromise.

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

When an AI agent wants to take an action (run a command, access a file, make a network call), a small piece of code called a "hook" intercepts the request and sends it to Snapper before it executes. Snapper evaluates the request against all active security rules and returns one of three verdicts: Allow (safe to proceed), Deny (blocked), or Require Approval (a human gets a notification on Telegram or Slack and decides). This entire process takes under 50 milliseconds — users don't notice any delay. Simultaneously, Snapper extracts threat signals from the request in under 2 milliseconds and feeds them to a background analysis engine that tracks behavioral patterns, detects kill chains, and computes composite threat scores per agent.

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

### Q: What is the Bad Actor Detection Engine?

The Bad Actor Detection Engine is Snapper's heuristic threat detection system — the equivalent of an IDS/IPS (Intrusion Detection/Prevention System) purpose-built for AI agents. It operates in three layers:

1. **Signal Extraction (hot path, <2ms):** Every agent request is scanned for 13 threat signal types using compiled regex patterns — file reads of sensitive paths, credential access, network sends, encoding operations, privilege escalation, vault token probes, PII outbound attempts, steganographic content, and more. This runs inline with zero perceptible latency.

2. **Background Analysis (every 2 seconds):** A dedicated worker consumes threat signals from a Redis Stream and performs three analyses: (a) updates per-agent behavioral baselines over a 7-day rolling window, (b) advances kill chain state machines that track multi-step attack progressions, and (c) computes a composite threat score (0-100) that blends signal severity, kill chain progress, and behavioral deviation.

3. **Enforcement:** The threat score feeds directly into the rule engine. Agents scoring 80+ are automatically denied. Agents scoring 60-79 require human approval. Agents scoring 40-59 trigger alerts. This happens transparently — no rules need to be configured. The system learns what's normal for each agent and flags what isn't.

### Q: What are kill chains and why do they matter?

A kill chain is a sequence of actions that, individually, might look harmless but together indicate a coordinated attack. Snapper tracks 7 predefined kill chains:

1. **Data Exfiltration:** File read → network send (an agent reads a sensitive file, then sends it externally)
2. **Credential Theft:** Credential file access → network send (reads SSH keys or passwords, then exfiltrates)
3. **PII Harvest:** Multiple PII accesses → network send (collects personal data, then sends it out)
4. **Encoded Exfiltration:** File read → encoding → network send (reads data, base64-encodes it to evade detection, then sends)
5. **Privilege Escalation:** Privilege escalation → file read → network send (gains elevated access, reads restricted data, exfiltrates)
6. **Vault Token Extraction:** Vault token probe → PII outbound (tries to extract encrypted PII from the vault)
7. **Living-off-the-Land:** Uses legitimate tools (tar, curl, wget) in combination for malicious purposes

Each chain has time windows (30-300 seconds between stages) and tracks state per agent. When a kill chain completes, it generates a threat event, elevates the agent's threat score, and can trigger automatic quarantine. No competitor offers predefined kill chain state machines at the tool-execution level.

### Q: What are behavioral baselines?

Snapper builds a behavioral profile for each agent over a 7-day rolling window. It tracks which tools the agent normally uses, which network destinations it contacts, how much data it typically transfers, and what hours it operates. When an agent suddenly starts using tools it has never used before, contacting unusual destinations, transferring abnormally large payloads, or operating at unusual hours, the deviation is detected and contributes to the threat score. This catches "low and slow" attacks — like an agent gradually exfiltrating small amounts of data — that no static rule could detect.

### Q: How does Snapper handle approval automation?

Snapper includes an approval policy engine that can auto-approve or auto-deny requests matching specific patterns, reducing alert fatigue. Policies can match on agent name, tool, destination, command pattern, and time of day. For example: "Auto-approve all file reads from agent 'build-bot' between 9am-5pm" or "Auto-deny any network send containing base64-encoded data." The system also generates rule suggestions based on observed traffic patterns — it learns what agents typically do and recommends rules to codify normal behavior.

### Q: What is the PII Vault?

The PII Vault is an encrypted storage system for sensitive data. Users store personal data (credit cards, SSNs, addresses) in the vault via Telegram, Slack, or API. The vault encrypts it with AES-256-GCM and creates a random token. AI agents only ever see the token — never the real value. When the agent needs to use the data, a human approves the specific use, the real value is decrypted and provided for exactly 30 seconds, then permanently destroyed from memory. The agent never has access to raw PII.

### Q: How does Snapper detect PII?

Two mechanisms: (1) The PII Vault tokenization system where sensitive data is pre-stored and agents only see tokens. (2) Real-time PII scanning that checks every agent action against 30+ patterns — credit card numbers (validated with Luhn algorithm), Social Security numbers, email addresses, phone numbers, addresses, and API keys from major providers (OpenAI, AWS, GitHub, Stripe). Detected PII is blocked automatically before the data can be exfiltrated or misused. The threat detection engine adds a third layer — tracking PII access patterns over time and flagging agents that access PII at abnormal rates.

### Q: What is "human-in-the-loop" approval?

When an agent tries to do something sensitive (access PII, run a destructive command, access a restricted file), the responsible person gets a push notification on Telegram or Slack with full context — what tool, what destination, what data, and the agent's trust score. They can approve or deny with one tap. If nobody responds within 5 minutes, the request is automatically denied ("fail-closed"). This means a human is always in the loop for high-risk actions.

### Q: What is adaptive trust scoring?

Each agent has a trust score from 0.5 to 2.0. Well-behaved agents gradually earn higher trust, which gives them higher rate limits and fewer approval requirements. Agents that misbehave (repeatedly hitting rate limits) get their trust reduced. It's like a credit score for AI agents — good behavior earns autonomy, bad behavior gets restrictions. Trust scoring is opt-in per agent so organizations can control which agents participate. The trust system works alongside the threat detection engine — high threat scores can compound with low trust scores to quickly isolate compromised agents.

### Q: What is the browser extension?

Snapper Guard is a Chrome/Firefox browser extension (built on Manifest V3, the latest standard) that monitors what employees paste into web-based AI chats — ChatGPT, Claude.ai, Gemini, Microsoft Copilot, and Grok. It scans for PII (credit cards, SSNs, emails, phone numbers, API keys) and can warn or block before the data leaves the browser. This is critical because no network firewall, DLP tool, or proxy can see what someone types into a browser-based AI chat.

### Q: How fast is Snapper?

Rule evaluation takes under 50 milliseconds (0.05 seconds). Threat signal extraction adds less than 2.5 milliseconds on top of that. For comparison, a human eye blink takes about 300ms. Users literally cannot perceive the delay. The background threat analysis runs asynchronously every 2 seconds in a separate worker — it never adds latency to the agent's request path.

### Q: What is "fail-closed" and why does it matter?

Fail-closed means that if anything goes wrong — a bug, a network error, a missing rule, a timeout — the default behavior is to block the action. The alternative ("fail-open") would allow the action when something goes wrong, which an attacker could exploit by intentionally crashing the security system. Fail-closed is the gold standard in security design and is how Snapper operates at every layer.

### Q: What is "defense in depth"?

Snapper has 8 independent security layers that every request must pass through: (1) Security middleware (origin/host validation), (2) Authentication + MFA, (3) API key verification, (4) Rule engine (16 rule types), (5) PII gate (data scanning), (6) Threat detection engine (behavioral analysis + kill chains), (7) Approval workflow (human decision), (8) Audit trail (immutable logging). If any single layer has a bug or is bypassed, the others still protect you. An attacker would need to bypass all eight layers simultaneously.

### Q: What is Traffic Discovery?

Snapper automatically detects which AI tools and MCP servers are in use by analyzing agent traffic — no manual configuration required. It recognizes 40+ curated server types (GitHub, Slack, databases, etc.) and shows which commands have security rules and which are uncovered. With one click, it generates tailored security rules for any discovered service. This solves the "I don't know what my agents are using" problem.

Beyond traffic analysis, Snapper maintains an MCP Server Catalog of 27,000+ servers synced daily from 5 registries (mcp.so, Glama, Smithery, PulseMCP, Open Directory). Every server is automatically classified into one of 13 security categories — payment/finance, shell/system, identity/auth, data stores, cloud infrastructure, and more — using a 3-tier classification engine: compiled regex name matching (<1ms), description keyword scoring (<1ms), and BGE ML embedding similarity (~5ms). Each category has a predefined security posture (from "maximum" for payment processors to "default" for general-purpose tools), and the corresponding rule template is auto-applied the first time an agent accesses that server. This means every MCP server gets security coverage without manual configuration — payment servers require approval for all actions, shell servers deny most operations by default, and data stores allow reads but gate writes and destructive operations.

---

## Enterprise Readiness

### Q: Is Snapper enterprise-ready?

Yes. Snapper includes the full enterprise checklist:
- **Identity & Access:** SSO (SAML 2.0 + OIDC), SCIM user/group provisioning, MFA/TOTP, RBAC with 4 roles and 13 permissions, account lockout, session management with JWT
- **Compliance & Audit:** 70+ audit event types, configurable retention (7-3,650 days), mapped to SOC 2, GDPR, HIPAA, PCI DSS
- **SIEM Integration:** CEF syslog (including 6 dedicated threat event IDs), HMAC-signed webhooks, Splunk HEC — connects to any major security monitoring system
- **Multi-Tenancy:** Complete data isolation per organization — separate encryption keys, policies, agents, and rules
- **Platform Administration:** Meta admin dashboard with org provisioning, impersonation, feature flags, cross-org audit, user management, and platform-wide analytics
- **Data Protection:** AES-256-GCM encryption, zero-knowledge PII vault, key rotation for API keys and vault encryption
- **Threat Detection:** Heuristic bad actor detection with 13 signal types, 7 kill chain state machines, per-agent behavioral baselines, and composite threat scoring
- **Deployment:** Self-hosted, air-gapped capable, zero telemetry (no data sent back to us)

### Q: How does Snapper handle SSO?

Snapper supports both SAML 2.0 and OIDC (OpenID Connect) — the two industry-standard SSO protocols. This means it works with every major identity provider: Okta, Microsoft Entra ID (formerly Azure AD), Google Workspace, OneLogin, and others. It supports Just-in-Time (JIT) provisioning — the first time an employee logs in via SSO, their Snapper account is created automatically. Organizations can enforce SSO-only login (disable password authentication entirely).

### Q: What is SCIM and does Snapper support it?

SCIM (System for Cross-domain Identity Management) is an automated protocol for syncing user accounts between systems. When HR adds or removes someone in the identity provider (Okta, Entra ID), SCIM automatically creates or deactivates their Snapper account — no manual steps. Snapper supports both SCIM Users and SCIM Groups, so team membership is automatically synced from the identity provider.

### Q: How does Snapper handle compliance?

Snapper generates a tamper-proof (immutable) audit trail with 70+ event types covering authentication, agent actions, rule changes, vault access, threat events, and organization changes. Each entry includes IP address and browser information for forensic purposes. Audit data can be exported to any SIEM via CEF syslog, HMAC-signed webhooks, or Splunk HEC. The audit trail maps directly to compliance requirements: SOC 2 (audit controls), GDPR (right-to-erasure via data purge API), HIPAA (PII encryption at rest), and PCI DSS (credential protection and tokenization). Threat events include their own CEF event IDs (800-805) for security operations center (SOC) integration.

### Q: Can Snapper be deployed in air-gapped environments?

Yes. Snapper is fully self-hosted and sends zero telemetry — no usage analytics, no crash reports, no phone-home behavior. It works completely disconnected from the internet, making it suitable for defense, intelligence, and highly regulated environments where data cannot leave the network. Docker images can be loaded from a tarball in air-gapped deployments. The threat detection engine runs entirely on-premise — no cloud AI APIs are required (the optional AI review layer can be enabled but is off by default).

### Q: How is data isolated between customers?

Full multi-tenancy with complete data isolation. Each organization gets its own encryption keys (derived via HKDF from a per-org secret), separate security policies, separate agents, and separate rules. One organization can never see another's data. Snapper supports organizations with teams, and role-based access control (RBAC) with 4 roles — Owner, Admin, Member, and Viewer — each with specific permissions. A platform-level meta admin dashboard allows the service operator to provision organizations, manage quotas and feature flags, impersonate orgs for debugging, and view cross-org audit trails — all with full audit logging.

### Q: What monitoring and observability does Snapper provide?

Snapper exposes Prometheus metrics for real-time dashboards (compatible with Grafana). Metrics include request rates, rule evaluations per type, deny/allow/approve ratios, latency percentiles, agent trust scores, threat scores, and PII detection counts. For security monitoring, events flow to SIEM systems via CEF syslog, HMAC-signed webhooks, or direct Splunk HEC integration. Threat events have dedicated CEF event IDs (800-805) covering threat detection, score elevation, kill chain completion, agent quarantine, resolution, and false positive marking.

---

## Competitive Landscape

### Q: Who are the competitors?

Nine products compete in adjacent spaces, but none occupy Snapper's exact position:

1. **RunLayer** — Closest competitor. MCP-focused security proxy with request analysis and SSO integration. Lacks kill chain detection, behavioral baselines, composite threat scoring, PII vault, and browser extension coverage.
2. **Lakera Guard** — Prompt-level content safety with DLP. Strong injection detection (99.2%) but operates at the prompt layer, not the tool-execution layer. No kill chain detection, no behavioral baselines, no composite scoring.
3. **Invariant Labs (acquired by Snyk)** — Gateway proxy with static + runtime analysis and MCP scanning. Focus is LLM-level interception, not tool-level behavioral analysis. No kill chain state machines or integrated PII vault.
4. **Lasso Security** — Broad AI governance platform with Intent Deputy for behavioral-intent analysis. Closest to Snapper's behavioral detection, but Intent Deputy launched February 2026 and maturity is unclear. No predefined kill chains or composite threat scoring documented.
5. **Pangea** — API-first guardrails with 50-type PII detection. Content-inspection focused rather than behavioral-pattern analysis.
6. **NVIDIA NeMo Guardrails** — Open-source LLM-level guardrails. Strong ecosystem but adds ~500ms latency and operates at the prompt layer, not the tool-execution layer.
7. **CalypsoAI (acquired by F5, ~$180M)** — Runtime content inspection with red-teaming agents. Content safety and compliance focused, not multi-step behavioral detection.
8. **NeuralTrust** — Guardian Agents for real-time monitoring with sub-10ms latency. Strong governance but detailed behavioral analysis features not extensively documented.
9. **Protect AI** — Model supply chain security (scanning 1.5M+ models). Focus is model integrity, not runtime agent behavioral analysis.

### Q: What is Snapper's competitive moat?

Snapper is the only product that combines all of these capabilities in a single platform: multi-step kill chain detection (7 state machines) + per-agent behavioral baselines (7-day rolling) + composite threat scoring (0-100) + PII vault with AES-256-GCM encryption + human-in-the-loop approvals via Telegram and Slack + adaptive trust scoring + MCP server auto-discovery (40+ known servers) + browser extension coverage (5 platforms) + self-hosted deployment with zero telemetry + air-gapped operation. No competitor offers more than 3-4 of these. We benchmarked 18 capabilities across 9 competitors — Snapper leads in 14 of 18 categories. This is a blue-ocean market — we're defining a new product category.

### Q: How is Snapper different from a traditional WAF or DLP?

A WAF (Web Application Firewall) inspects HTTP requests to web applications — it can't see what an AI agent decides to do inside a system. DLP (Data Loss Prevention) watches for data leaving the network — but it can't stop an agent from reading a password file before sending it, and it can't see what someone pastes into a browser-based AI chat. Snapper operates at the "agent decision point" — a layer that sits between the AI model's decision and its execution. This is a fundamentally different inspection point that no existing security category covers. Snapper's kill chain detection catches multi-step attacks that DLP and WAF can never see — like an agent reading credentials, encoding them with base64, and exfiltrating them through a legitimate-looking curl command.

### Q: Why can't existing security tools handle AI agents?

Traditional security tools see the effects of agent actions (network packets, file changes) but not the decisions themselves. A network firewall sees an HTTPS connection to api.openai.com but can't see the agent decided to send the contents of ~/.ssh/id_rsa in the prompt. An EDR sees a shell command executed but can't see the agent chose to run it. Snapper intercepts the decision before it becomes an action, which is the only point where you can meaningfully apply security policy to agent behavior. The behavioral baseline engine adds another dimension — it knows what each agent normally does, so it can detect when an agent starts behaving abnormally even if the individual actions aren't flagged by any rule.

### Q: How does Snapper compare to Lasso Security's Intent Deputy?

Lasso's Intent Deputy, launched February 2026, evaluates whether tool calls align with agent objectives — meaningful behavioral analysis. However, Snapper's approach is fundamentally different: we track concrete multi-step kill chains (7 predefined attack patterns with time-windowed state machines), build statistical behavioral baselines per agent over 7-day rolling windows (tool usage, destination frequency, data volume, operating hours), and compute composite threat scores (0-100) that directly feed enforcement decisions. Intent Deputy focuses on intent alignment; Snapper focuses on attack pattern recognition and anomaly detection. We also integrate threat signals with PII vault awareness, SIEM output, and human-in-the-loop enforcement — creating a closed loop from detection to response.

---

## Business Model & Pricing

### Q: What is the pricing model?

Three tiers:
- **Free:** Up to 25 agents, 250 rules, 50 vault entries, 5 members, 2 teams. For individuals and small projects.
- **Pro ($29/mo):** Up to 10 agents, 100 rules, 50 vault entries, 5 members, 3 teams. For teams.
- **Enterprise ($99/mo):** Unlimited everything, dedicated SLA, SSO/SCIM, priority support, custom deployment. For large organizations.

Self-hosted mode is always unlimited — no feature gating and no quotas. Pricing is subscription-based.

### Q: Is there a free tier?

Self-hosted deployment is available under the PolyForm Noncommercial License — free for personal use, research, education, and noncommercial organizations. Commercial use requires a paid license. This means prospects can evaluate the full product before purchasing.

### Q: What is the revenue model?

Subscription licensing per organization, with pricing based on scale (number of agents and users). Every organization deploying AI agents is a potential customer. Revenue grows with AI agent adoption — the more agents a company deploys, the more value Snapper provides.

---

## Deployment & Technical

### Q: How long does it take to deploy?

5 minutes. One command starts everything: `./setup.sh` for local development, or `./deploy.sh` on a production Ubuntu server. The setup wizard walks through agent registration, security profile selection, and notification setup. Recommended rollout: Week 1 in learning mode (observe only), Week 2 review and activate rules, Week 3 enable enforcement, threat detection, and trust scoring.

### Q: What is "learning mode"?

Learning mode is an observation-only operating mode where all rules are evaluated and logged, but nothing is actually blocked. This eliminates deployment risk — teams can see exactly what would be blocked, validate their rules, and build confidence before switching to enforcement. It's the equivalent of deploying a firewall in monitor mode before activating it. During learning mode, the threat detection engine still builds behavioral baselines, so when enforcement is activated, the system already knows what's normal for each agent.

### Q: What infrastructure does Snapper require?

Snapper runs entirely in Docker (6 containers: main app, PostgreSQL, Redis, 2 Celery workers, Caddy web server). It can run on a single server (VPS) or scale to Kubernetes with Helm charts. Minimum requirements are modest — the VPS deployment runs on 8GB RAM. For larger deployments, Kubernetes supports auto-scaling with Horizontal Pod Autoscaler.

### Q: Does Snapper require cloud connectivity?

No. Snapper is fully self-hosted and requires zero internet connectivity. It never phones home, sends telemetry, or requires license validation against an external server. This makes it suitable for air-gapped and classified environments. The threat detection engine runs entirely on-premise. There is an optional AI-powered threat review layer (using Claude) that requires an API key, but it is disabled by default and the core heuristic engine works fully offline.

### Q: How well-tested is Snapper?

1,850+ automated tests across five layers:
- **1,300+ unit tests** — API, rule engine, middleware, Telegram/Slack bots, PII vault, security monitor, integrations, threat detection (48 threat-specific tests)
- **168 Playwright E2E tests** — Browser-based UI testing of all dashboard flows
- **95 live integration tests** — API-level tests of all 16 rule types, approval workflows, PII vault lifecycle, emergency block, trust scoring, and audit trail
- **90 integration E2E tests** — Traffic discovery, templates, custom MCP servers, coverage analysis
- **13 red-team threat simulation tests** — Automated attack scenarios testing all 7 kill chains, behavioral baseline deviation, slow-drip exfiltration, encoding stacking, steganographic detection, signal storms, and benign-traffic negative control

### Q: What is the Threat Simulator?

Snapper ships with a built-in red-team tool (`threat_simulator.py`) that exercises every detection pathway against a live instance. It runs 13 automated attack scenarios — each registering a fresh agent, executing a realistic attack sequence, waiting for background analysis, then verifying threat scores, kill chain events, and enforcement overrides. It tests data exfiltration, credential theft, PII harvesting, encoded exfiltration, privilege escalation, vault token extraction, living-off-the-land attacks, behavioral baseline deviation, slow-drip exfiltration, encoding stacking, steganographic content, signal storms, and a negative control with benign traffic. All 13 scenarios pass in under 100 seconds.

---

## Security & Architecture

### Q: What encryption does Snapper use?

AES-256-GCM encryption for the PII vault (the same standard used by banks, the U.S. government, and military systems). GCM mode provides authenticated encryption — it detects tampering, not just encrypts. Encryption keys are derived via HKDF (a key derivation function) from a master secret, creating unique keys per purpose. TLS encrypts all data in transit. Key rotation is supported for both the PII vault encryption key and individual agent API keys.

### Q: What happens if Snapper goes down?

Fail-closed. If Snapper is unreachable, the agent hooks cannot get a security decision, so the action is blocked by default. This is a deliberate design choice — it's safer to temporarily block all actions than to allow unscreened actions through. The 99.9% SLA means less than 8.8 hours of downtime per year.

### Q: Can an agent bypass Snapper?

Not if deployed correctly. The hook runs in the agent's process before the tool call executes — the agent cannot skip the hook without modifying its own code. For API-based agents, the SDK wrapper intercepts at the library level. For browser-based AI, the extension intercepts before data leaves the browser. Snapper's security architecture document details the specific deployment requirements that must be met for full protection.

### Q: How does Snapper handle MFA?

TOTP-based multi-factor authentication (Time-based One-Time Password — the same system used by Google Authenticator, Authy, and other authenticator apps). Users scan a QR code during setup, then enter a 6-digit code that changes every 30 seconds at login. Backup codes are provided for phone loss scenarios. Organizations can require MFA for all members via a policy setting.

### Q: How does Snapper's dashboard authentication work?

Snapper requires authentication to access the management dashboard — there is no anonymous access. Users register with email and password, then log in to receive JWT (JSON Web Token) session cookies. Access tokens expire every 30 minutes and are automatically refreshed using a 7-day refresh token. Failed login attempts trigger account lockout after 5 tries (30-minute cooldown). Agent API calls use separate API key authentication (X-API-Key headers) so agents are never blocked by dashboard auth changes. The entire auth flow uses httponly, secure, same-site cookies — immune to XSS token theft.

### Q: How does threat detection integrate with SIEM?

Threat events emit 6 dedicated CEF (Common Event Format) event IDs for seamless SOC integration:
- **800:** Threat signal detected
- **801:** Threat score elevated above threshold
- **802:** Kill chain completed
- **803:** Agent quarantined
- **804:** Threat resolved
- **805:** Marked as false positive

These flow through the same CEF syslog, webhook, and Splunk HEC channels as all other Snapper events. SOC teams can create alerts, dashboards, and playbooks around these event IDs in their existing SIEM (Splunk, Sentinel, QRadar, etc.).

---

## Traction & Roadmap

### Q: What stage is Snapper at?

Snapper is a working product with 1,850+ automated tests, 16 rule types, a heuristic bad actor detection engine with 7 kill chains, enterprise features (SSO, SCIM, SIEM, MFA, RBAC, multi-tenancy), dashboard authentication with JWT sessions, and integrations with 10+ AI agent types. It has been deployed and tested in production environments with full enforcement mode active. The product is in beta with active development, a live threat simulator that validates all detection pathways, a meta admin platform dashboard with org provisioning and impersonation.

### Q: What's on the roadmap?

Key roadmap items include: expanded AI provider SDK support, additional browser extension platforms, enhanced threat analytics and reporting dashboards, Kubernetes operator for automated deployment, additional SIEM integrations, SOC 2 Type II certification, and ML-powered threat classification to complement the heuristic engine. The architecture is designed to be extensible — new rule types, agent integrations, kill chain definitions, and notification channels can be added without changing the core engine.

### Q: How does Snapper stay current with new threats?

Three mechanisms: (1) A background security research system that tracks new CVEs and malicious plugin campaigns in AI agent frameworks. The denylist system supports both exact matches and regex patterns, so a single pattern update can block entire malware families. (2) The behavioral baseline engine continuously adapts — it learns what's normal for each agent over a 7-day rolling window, so new attack patterns are flagged as anomalies even without specific rules. (3) The optional AI-powered threat review layer can analyze suspicious signal clusters using Claude to identify novel attack patterns that heuristics alone might miss.

---

## Objection Handling

### Q: "We already have security tools — firewalls, DLP, endpoint protection."

Those tools are essential but operate at the wrong layer for AI agents. A network firewall sees packets, not agent decisions. DLP watches exit points, not what an agent reads internally. Endpoint protection looks for malware signatures, not legitimate tools being misused. There's a gap at the "agent decision point" — the moment between an AI deciding to take an action and that action executing. That's exactly what Snapper fills. It complements existing tools, it doesn't replace them. And none of those tools can detect multi-step kill chains at the agent tool-call level — that's entirely new.

### Q: "Can't we just restrict what agents have access to?"

You can limit filesystem and network access at the OS level, but this cripples agent productivity. The value of AI agents is their ability to take real actions — run code, access APIs, interact with services. Snapper lets agents keep full capability while adding security policy. It's the difference between locking someone in a room vs. letting them work freely with a security guard watching.

### Q: "Our developers are careful — they won't do anything risky."

The risk isn't from developers doing things intentionally. AI agents act autonomously and can be manipulated by prompt injection, malicious plugins, or poisoned context. The ClawHavoc campaign inserted 341+ malicious plugins that looked legitimate. An agent might read a .env file not because a developer asked it to, but because its training data or a malicious plugin instructed it to. The threat model is the agent acting without human oversight, not the human acting recklessly.

### Q: "This seems like it would slow down our developers."

Snapper adds under 50 milliseconds of latency — less than a sixth of an eye blink. Threat signal extraction adds less than 2.5ms on top of that. Users literally cannot perceive the delay. Learning mode lets you deploy without blocking anything, so there's zero workflow disruption during rollout. Trust scoring means well-behaved agents earn more autonomy over time, so the system gets less restrictive, not more.

### Q: "We're not ready for AI agent security yet."

79% of companies are already using AI agents, and 78% of employees are using unapproved AI tools. The question isn't whether you need agent security — it's whether you know what your agents are doing right now. Snapper's learning mode and traffic discovery let you answer that question in 5 minutes with zero risk. Start by observing, then decide on enforcement. Meanwhile, the threat detection engine is building behavioral baselines from day one — so when you do activate enforcement, the system already knows what's normal.

### Q: "Why not build this in-house?"

Snapper has 1,850+ tests, 16 rule types, integrations with 10+ agent frameworks, PII vault with AES-256-GCM encryption, SSO/SCIM/SIEM enterprise features, Telegram and Slack bots, a browser extension covering 5 AI platforms, adaptive trust scoring, a heuristic bad actor detection engine with 7 kill chain state machines, and a built-in red-team threat simulator. Building this in-house would take a dedicated security team 18-24 months and ongoing maintenance. The threat landscape evolves constantly (new CVEs, new malicious campaigns, new attack patterns), and keeping up requires continuous security research and detection engineering.

### Q: "What if AI agent frameworks add their own security?"

Some may add basic guardrails, but agent framework vendors are incentivized to make their agents more capable, not more restricted. Security is an afterthought for platform vendors — they build features, not firewalls. Snapper provides a vendor-neutral, framework-agnostic security layer that works across all agents. When companies use 3-5 different AI tools (which most do), they need a single security policy that spans all of them — not separate, inconsistent controls from each vendor.

### Q: "How do you detect attacks that rules can't catch?"

That's exactly what the heuristic bad actor detection engine is for. Static rules catch known-bad patterns (specific malicious commands, blocked file paths). But a sophisticated attacker can craft actions that pass every individual rule — reading a benign-looking file, encoding data with a legitimate tool, sending it via a normal HTTP client. Snapper's kill chain detection tracks sequences of actions over time and flags when the pattern matches a known attack progression. Behavioral baselines catch anomalies — an agent that normally runs 5 commands per hour suddenly running 50 is suspicious even if each command is individually allowed. Composite scoring blends multiple weak signals into a strong detection signal. This is the same approach used by modern EDR (Endpoint Detection and Response) systems, adapted for the AI agent threat model.

### Q: "What's your false positive rate?"

The system is designed for low false positives through multiple mechanisms: (1) Composite scoring means no single signal triggers enforcement — multiple signals must converge. (2) Behavioral baselines adapt per agent, so a tool that's unusual for one agent but normal for another won't trigger a false alarm. (3) Threat scores decay over time (300-second TTL), so transient anomalies don't persist. (4) The resolution workflow lets security teams mark events as false positives, and the built-in threat simulator validates all 13 detection scenarios with zero false positive rate in negative control tests (benign traffic scores 0.0). (5) Score thresholds are configurable — organizations can tune sensitivity to their risk tolerance.

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
| Threat signal extraction | < 2.5ms |
| Automated tests | 2,000+ |
| Supported agent types | 10+ |
| Browser extension platforms | 5 (ChatGPT, Claude, Gemini, Copilot, Grok) |
| Known MCP servers recognized | 27,000+ cataloged, 40+ curated |
| PII patterns detected | 30+ |
| Threat signal types | 13 |
| Kill chain state machines | 7 |
| Behavioral baseline window | 7-day rolling |
| Threat score range | 0-100 composite |
| Audit event types | 70+ |
| CEF threat event IDs | 6 (800-805) |
| Security layers | 8 independent |
| Named CVEs mitigated | 5 |
| Malicious plugins blocked | 44+ (plus 11 regex patterns) |
| Competitors benchmarked | 9 products, 18 capabilities |
| Deploy time | 5 minutes |
| Encryption standard | AES-256-GCM |
| Meta admin test coverage | 35 E2E + 13 unit |
| Multi-user E2E tests | 85 |
| MCP security categories | 13 |
| MCP catalog sources | 5 registries (daily sync) |
| Enterprise SLA | 99.9% |
