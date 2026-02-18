# Snapper CIO Presentation — Internal Talking Points Guide

**Purpose:** This document explains each slide in the CIO security briefing in plain language. Use it to prepare for investor meetings, partner conversations, and internal briefings. You don't need to be technical to present this deck confidently. Every technical term is explained the first time it appears.

---

## Slide 1 — Title

**What it says:** Snapper is an "Agent Application Firewall" with the tagline "Your agents keep full power. You keep full control."

**What to say:** Snapper is a security product for AI agents. AI agents are software programs that can take actions on their own — writing code, browsing the web, sending emails, accessing databases. Right now, companies are deploying these agents with no security controls. Snapper sits between the agent and the outside world, inspecting every action before it happens. Think of it like a firewall, but instead of watching network traffic, it watches what AI agents decide to do.

**Key phrase:** "Agent Application Firewall" — this is a new product category we're defining.

> **Term: Firewall** — A security system that monitors and controls incoming and outgoing traffic based on rules. Traditional firewalls watch network data (like web requests). Snapper is a new kind of firewall that watches AI agent decisions instead.
>
> **Term: AI Agent** — A software program powered by a large language model (like ChatGPT or Claude) that can take real actions: run commands, read files, make API calls, send messages. Unlike a chatbot that just answers questions, an agent actually does things.

---

## Slide 2 — AI Adoption Is Exploding

**What it says:** Stats showing massive AI adoption and a "shadow AI" problem.

**What to say:** AI agent adoption is happening whether IT departments approve it or not. 79% of companies are already using AI agents, and 78% of employees are using AI tools that haven't been approved by their IT team. This is called "shadow AI" — when employees use AI tools that the company hasn't vetted, doesn't monitor, and can't control. The cost impact is real — when a data breach involves unapproved AI tools, it costs $670,000 more on average.

**Why it matters to investors:** This is a massive, growing market ($10.9B projected). The problem is urgent and universal. Every company with AI agents needs this.

**Talking point for partners:** "Your customers are already deploying AI agents. The question isn't whether they'll need security — it's who provides it."

> **Term: Shadow AI** — AI tools used by employees without IT department approval or oversight. Think of it like employees bringing their own unmanaged laptops to work — but worse, because these AI tools can access company data and take actions.
>
> **Term: Data Breach** — An incident where sensitive, confidential, or protected data is accessed or stolen by unauthorized parties. Breaches trigger legal obligations, fines, and reputation damage.

---

## Slide 3 — What Your Agents Can Do Right Now

**What it says:** AI agents have unrestricted access to sensitive systems.

**What to say:** Today's AI agents can read password files, access cloud credentials, run any command on a computer, and send data to the internet — all without anyone knowing. There's no approval step, no audit trail, and no way to limit what they do. Traditional security tools can't see what an agent decides to do — they only see the network traffic that results from it. By then, it's too late.

**Key analogy:** "A network firewall is like a security guard at the building entrance. But the agent is already inside the building, sitting at an employee's desk, with their login credentials."

> **Term: `.env`, `~/.ssh/`, `~/.aws/`** — These are files on a developer's computer that store passwords, encryption keys, and cloud service credentials. If an AI agent reads these files and sends them somewhere, an attacker gets full access to the company's cloud infrastructure, code repositories, and databases.
>
> **Term: Audit Trail** — A chronological record of who did what, when, and where. Like a security camera recording — if something goes wrong, you can go back and see exactly what happened. Without an audit trail, you can't investigate incidents or prove compliance.
>
> **Term: CI/CD Pipeline** — Continuous Integration / Continuous Delivery. This is the automated system that builds, tests, and deploys software. If an agent modifies this pipeline, it could inject malicious code into every release the company ships.

---

## Slide 4 — This Is Already Being Exploited

**What it says:** Real, documented security vulnerabilities in AI agent frameworks.

**What to say:** These aren't theoretical risks — they're real attacks that have already happened. The table shows 5 documented vulnerabilities, including one (ClawHavoc) where 341+ malicious plugins were discovered in a popular AI agent's community registry. The severity scores on these range from 7.5 to 9.8 out of 10 — that's "high" to "critical" in the security industry's rating system.

**Why this matters:** This proves the threat is real and present, not hypothetical. Security teams and CISOs will recognize these as credible, documented threats.

> **Term: CVE (Common Vulnerabilities and Exposures)** — A public catalog of known security vulnerabilities. Each gets a unique ID like "CVE-2026-25253." When a security team sees a CVE number, they know it's a real, verified vulnerability — not marketing hype. CVEs are issued by a government-backed authority (MITRE).
>
> **Term: CVSS (Common Vulnerability Scoring System)** — A severity score from 0 to 10. Think of it like a hurricane category:
> - 0–3.9 = Low (minor issue)
> - 4.0–6.9 = Medium (should be fixed)
> - 7.0–8.9 = High (needs urgent attention)
> - 9.0–10.0 = Critical (drop everything and fix this)
>
> **Term: RCE (Remote Code Execution)** — The worst type of vulnerability. It means an attacker can run any command on your system from the internet. It's the digital equivalent of handing someone the keys to your office and your admin password.
>
> **Term: CISO (Chief Information Security Officer)** — The executive responsible for a company's cybersecurity strategy. This is a primary buyer persona for Snapper.

---

## Slide 5 — Nothing In Your Stack Covers This

**What it says:** Existing security products don't address AI agent risks.

**What to say:** Companies already spend millions on security tools — firewalls, DLP, endpoint protection. But none of these can see what an AI agent decides to do. Traditional firewalls inspect network packets — they can't read an agent's intent. DLP solutions watch for data leaving the network — they can't stop an agent from reading a password file before sending it. This is a gap in every company's security posture.

**The opportunity:** "There's a missing layer — the 'Agent Decision Point.' That's exactly what Snapper provides."

> **Term: DLP (Data Loss Prevention)** — Security tools that monitor data leaving the company network — email attachments, file uploads, cloud storage sync. The problem: DLP watches the exit doors, but an AI agent operates inside the building. DLP can't stop the agent from reading sensitive files; it can only try to catch the data leaving afterward.
>
> **Term: Endpoint Protection** — Security software installed on individual computers (like antivirus). It looks for malware and suspicious files but doesn't understand what an AI agent is doing because the agent's actions look like normal computer operations.
>
> **Term: Security Posture** — The overall strength of a company's security program. Think of it as a report card — if you have a gap in agent security, your posture has a blind spot.

---

## Slide 6 — The Agent Application Firewall

**What it says:** Snapper's core approach and key stats.

**What to say:** Snapper creates a new security checkpoint between an AI agent's decision and its execution. Every time an agent wants to do something (run a command, access a file, make a network call), Snapper inspects it first. Three key capabilities:

1. **Auto-Discovery** — Snapper watches traffic and automatically identifies which AI tools and agents are running, even ones IT didn't know about. It recognizes 40+ popular AI server types out of the box.

2. **Three interception methods** — It can inspect CLI agents, API-based agents, and web-based AI chats (through a browser extension).

3. **16 rule types** — Different security checks for different threats: blocking dangerous commands, protecting PII, rate limiting, time restrictions, and more. All evaluated in under 50 milliseconds — the user doesn't even notice the delay.

**Stats to highlight:** 16 rule types, under 50ms latency, 1,100+ automated tests, supports 6 native agent frameworks.

> **Term: CLI (Command-Line Interface)** — A text-based way to interact with a computer by typing commands. Developer tools like Claude Code, Cursor, and OpenClaw run in the CLI. These are the most common AI coding agents.
>
> **Term: API (Application Programming Interface)** — A way for software programs to talk to each other. When a company builds an AI-powered app, it makes API calls to services like OpenAI or Anthropic. Snapper can inspect these calls.
>
> **Term: MCP (Model Context Protocol)** — A standard developed by Anthropic that lets AI agents connect to external tools and services (databases, file systems, web browsers, etc.) through a common interface. Think of MCP as a universal adapter — one standard that works with many tools. Snapper can automatically detect which MCP servers are in use and create security rules for them.
>
> **Term: PII (Personally Identifiable Information)** — Data that can identify a specific person: Social Security numbers, credit card numbers, email addresses, phone numbers, medical records. Protecting PII is required by laws like GDPR, HIPAA, and PCI DSS.
>
> **Term: Rate Limiting** — Controlling how many requests an agent can make in a given time period. Like a speed limit — it prevents an agent from overwhelming systems or exfiltrating large amounts of data quickly.
>
> **Term: Latency** — The delay added by a system. Snapper adds less than 50 milliseconds (0.05 seconds) to each agent action. For comparison, a human blink takes about 300ms. Users literally cannot perceive this delay.

---

## Slide 7 — How Snapper Works

**What it says:** The technical flow of how a request is evaluated.

**What to say (simplified):** When an AI agent wants to take an action, here's what happens:

1. The agent sends its request to Snapper (this happens automatically via a "hook" — a small piece of code that intercepts the request before it runs)
2. Snapper checks the request against all active rules
3. Snapper returns one of three answers:
   - **Allow** — go ahead, it's safe
   - **Deny** — blocked, the action doesn't happen
   - **Approve** — a human needs to review this (they get a notification on Telegram or Slack)

All of this happens in under 50 milliseconds. The agent and the user don't notice any delay.

**Key design decisions to mention:**
- "Fail-closed" means if anything goes wrong (a bug, a network error, a missing rule), the default is to block. This is the gold standard in security.
- It works with any AI framework — it's not tied to one vendor.

> **Term: Hook** — A small piece of code that runs automatically before or after a specific event. In Snapper's case, the hook runs before every tool call the agent makes. Think of it like an email filter that checks every outgoing email before it's sent — except for AI agent actions.
>
> **Term: Fail-closed vs. Fail-open** — Two philosophies for what happens when something goes wrong:
> - **Fail-closed** (Snapper's approach): If the security system crashes or can't make a decision, it blocks the action. Safe, but might temporarily inconvenience users.
> - **Fail-open** (the dangerous alternative): If the security system crashes, it allows the action. Convenient, but an attacker can exploit this by intentionally crashing the security system.
>
> **Term: Endpoint / API Endpoint** — A specific URL that a program can call to perform an action. Snapper's main endpoint is `POST /api/v1/rules/evaluate` — this is the single URL that every agent hook calls to get a security decision.

---

## Slide 8 — Defense in Depth — 16 Rule Types

**What it says:** The 16 types of security rules organized into 4 categories.

**What to say:** Snapper has 16 different types of security checks, covering four threat areas:

- **Access Control** (4 rule types) — What is the agent allowed to run? Which files can it access? What websites can it reach? Can it access localhost services?
- **Data Protection** (3 rule types) — Is the agent handling PII? Is it accessing passwords or API keys? Does a human need to approve this action?
- **Threat Prevention** (4 rule types) — Is the agent trying to use a known-malicious plugin? Is it coming from an unauthorized source? Is it the right software version? Does it need a sandbox?
- **Operational Controls** (3 rule types) — Is the agent making too many requests too fast? Is it operating outside business hours? Has it earned enough trust?

Rules are evaluated in priority order, and a DENY always wins — meaning if one rule says allow and another says deny, deny takes precedence. This is standard security practice.

**Why 16 types matters:** This isn't a simple allow/deny product. Each rule type addresses a specific, real-world threat that security teams care about.

> **Term: Denylist / Allowlist** — A denylist is a list of explicitly forbidden items (blocked commands, blocked websites). An allowlist is the opposite — only items on the list are permitted, everything else is blocked. Allowlists are more secure but more restrictive.
>
> **Term: Network Egress Filtering** — Controlling what external servers an agent can communicate with. "Egress" means outbound traffic. This prevents an agent from sending your data to an attacker's server.
>
> **Term: Sandbox** — An isolated environment where code runs without access to the real system. Like a padded room — the agent can do whatever it wants inside, but nothing escapes. Snapper can require that certain agents run in a sandbox.
>
> **Term: Sliding Window (Rate Limiting)** — A method of counting requests over a rolling time period. Instead of resetting the count every minute on the minute, it continuously looks at the last 60 seconds. This prevents "burst" attacks where someone makes 100 requests at 11:59 and another 100 at 12:00.

---

## Slide 9 — PII Vault & Real-Time Detection

**What it says:** How Snapper protects personal and sensitive data.

**What to say:** The PII Vault is one of Snapper's most differentiated features. It works in 5 steps:

1. **Store:** A user adds sensitive data (credit card number, SSN, etc.) to the vault via Telegram, Slack, or the API
2. **Encrypt:** Snapper encrypts it with AES-256 encryption and creates a "token" — a random code that represents the data
3. **Tokenize:** The agent only ever sees the token (like `{{SNAPPER_VAULT:a1b2c3d4}}`), never the real value
4. **Approve:** When the agent needs to use the data, a human approves the specific use via Telegram or Slack
5. **Resolve:** The real value is decrypted and provided for just 30 seconds, then permanently destroyed from memory

Additionally, Snapper scans every agent action for 30+ patterns that look like PII (Social Security numbers, credit cards validated with Luhn algorithm, email addresses, phone numbers, API keys from OpenAI/AWS/GitHub/Stripe) and blocks them automatically.

**Key differentiator:** "The agent never sees the real data. It works with tokens, and a human approves every use. PII never appears in logs or agent memory."

> **Term: AES-256 Encryption** — Advanced Encryption Standard with a 256-bit key. This is the same encryption standard used by banks, the U.S. government, and military systems. "256-bit" means the key has 2^256 possible combinations — more than the number of atoms in the observable universe. It is considered unbreakable with current technology.
>
> **Term: HKDF (Key Derivation Function)** — A mathematical process that generates encryption keys from a master secret. Instead of storing one key for everything, HKDF creates unique keys for each purpose. If one key is compromised, the others remain safe.
>
> **Term: Tokenization** — Replacing sensitive data with a random, non-reversible placeholder (a "token"). The token has no mathematical relationship to the original data — you can't reverse-engineer a credit card number from its token. Only the vault can map the token back to the real value.
>
> **Term: Luhn Algorithm** — A checksum formula used to validate credit card numbers. When Snapper scans for PII, it doesn't just look for 16-digit numbers — it mathematically verifies they are valid credit card numbers to reduce false alarms.
>
> **Term: TTL (Time to Live)** — How long data exists before it's automatically deleted. The PII vault uses a 30-second TTL — meaning the decrypted value is available for exactly 30 seconds after approval, then it's permanently erased. This minimizes the window of exposure.
>
> **Term: Key Rotation** — Periodically replacing encryption keys with new ones and re-encrypting all data. Like changing the locks on your building — even if someone stole an old key, it no longer works. Snapper supports rotation for both the PII vault encryption key and individual agent API keys.

---

## Slide 10 — Human-in-the-Loop & Adaptive Trust

**What it says:** Real-time approval workflows and trust scoring.

**What to say:** Two powerful features:

**Human-in-the-Loop Approvals:** When an agent tries to do something sensitive (like charging a credit card or accessing PII), the person responsible gets a notification on Telegram or Slack with full context — what tool, what destination, what data is involved, and the agent's trust score. They can approve or deny with one tap. If nobody responds within 5 minutes, the request is automatically denied (fail-closed).

**Adaptive Trust Scoring:** Each agent has a trust score from 0.5 to 2.0. Well-behaved agents gradually earn higher trust, which gives them more autonomy (higher rate limits, fewer approval requirements). Agents that misbehave (e.g., repeatedly hitting rate limits) get their trust reduced. This means the system gets smarter over time — less friction for good agents, more scrutiny for risky ones.

**Analogy:** "It's like a credit score for AI agents. Good behavior earns autonomy. Bad behavior gets restrictions."

> **Term: Human-in-the-Loop (HITL)** — A system design where a human makes the final decision for sensitive operations, rather than the software acting autonomously. This is a common requirement in regulated industries (finance, healthcare, defense) where fully autonomous decisions aren't acceptable.
>
> **Term: Trust Score** — A number assigned to each agent ranging from 0.5 (heavily restricted) to 2.0 (highly trusted). The score multiplies the agent's rate limits — so a trusted agent (2.0) can make twice as many requests as baseline, while a restricted agent (0.5) can only make half. The score is calculated based on the agent's behavior: only rate-limit violations reduce trust (not policy denials), and good behavior gradually restores it. This is opt-in per agent.

---

## Slide 11 — Every Agent. Every Interface.

**What it says:** Snapper covers CLI agents, API-based agents, and web-based AI chats.

**What to say:** Snapper covers three types of AI usage:

1. **Native Hook Agents** (6 supported) — These are coding tools developers use daily: Claude Code, Cursor, OpenClaw, Windsurf, Cline, and custom agents. Snapper integrates natively, meaning it plugs into the agent's built-in hook system with no code changes required.

2. **SDK Wrappers** — For companies building their own AI-powered applications using APIs from OpenAI, Anthropic, or Google Gemini, Snapper provides wrapper libraries that intercept every tool action. Developers add a few lines of code and every AI action is automatically inspected.

3. **Browser Extension — Snapper Guard** (5 platforms) — Employees paste sensitive data into web-based AI chats (ChatGPT, Claude.ai, Gemini, Microsoft Copilot, Grok). Snapper Guard is a browser extension that catches PII before it leaves the browser. This is a huge deal — no network tool, firewall, or DLP can see this traffic because it happens inside the browser.

**Plus: Traffic Discovery** — Snapper watches audit logs and automatically identifies which AI servers and tools are in use. It recognizes 40+ known server types (GitHub, Slack, databases, etc.) and can create tailored security rules with one click.

**Key talking point:** "The browser extension is critical because it closes the 'shadow AI' gap. No network tool can see what someone pastes into a ChatGPT window."

> **Term: SDK (Software Development Kit)** — A set of tools and libraries that developers use to build software. An "SDK wrapper" is a layer that wraps around an existing SDK to add functionality — in this case, adding Snapper security checks to every AI API call without changing the developer's existing code.
>
> **Term: Browser Extension** — A small program that adds features to a web browser (like Chrome or Edge). Snapper Guard is a Manifest V3 extension — the latest, most secure extension standard from Google. It runs inside the browser and can scan text before it's sent to a website.
>
> **Term: Manifest V3** — The current version of Google Chrome's extension platform. It's more secure and privacy-friendly than the previous version (V2). Building on V3 means Snapper Guard meets the latest browser security standards and won't be deprecated.
>
> **Term: Traffic Discovery** — Snapper's ability to automatically detect which AI tools and servers are running by analyzing the agent actions it sees. Instead of requiring manual configuration ("tell us every tool you use"), Snapper watches the traffic and says "I see you're using GitHub, Slack, and a database — want me to create security rules for those?"

---

## Slide 12 — Built for Your Stack

**What it says:** Enterprise readiness checklist across 6 categories.

**What to say:** This slide is for procurement teams and CISOs who have a checklist of requirements. Snapper checks every box:

- **Identity & Access:** SSO, SCIM provisioning, MFA, RBAC with 4 roles and 13 permissions, account lockout after failed login attempts.
- **Compliance & Audit:** A tamper-proof audit trail with 70+ event types. Configurable data retention. Mapped to SOC 2, GDPR, HIPAA, and PCI DSS.
- **SIEM Integration:** Connects to every major security monitoring system through 3 standard protocols.
- **Multi-Tenancy:** Each customer organization's data is completely isolated — separate encryption keys, separate policies.
- **Data Protection:** AES-256 encryption, zero-knowledge PII vault, key rotation for both API keys and vault encryption.
- **Deployment:** Self-hosted, air-gapped, zero telemetry.

**Why this matters:** "Enterprise sales live or die on this slide. If any of these boxes are unchecked, the deal stalls in procurement."

> **Term: SSO (Single Sign-On)** — A system that lets users log into multiple applications with one set of credentials. Instead of having a separate username and password for Snapper, employees use the same login they use for everything else (via Okta, Microsoft Entra, Google, etc.). IT loves this because it means one place to manage access, and when someone leaves the company, disabling their SSO account locks them out of everything instantly.
>
> **Term: SAML 2.0 and OIDC** — Two industry-standard protocols for SSO. SAML (Security Assertion Markup Language) is the older, more enterprise-focused standard. OIDC (OpenID Connect) is the newer, more modern standard. Snapper supports both, which means it works with every major identity provider (Okta, Microsoft Entra, Google, OneLogin, etc.).
>
> **Term: SCIM (System for Cross-domain Identity Management)** — An automated way to sync user accounts between systems. When HR adds a new employee in Okta, SCIM automatically creates their Snapper account. When someone is terminated, SCIM automatically deactivates their access — no manual steps, no forgotten accounts lingering. SCIM Groups extends this to teams — when an Okta group changes, the corresponding Snapper team updates automatically.
>
> **Term: MFA / TOTP (Multi-Factor Authentication / Time-based One-Time Password)** — Requiring a second proof of identity beyond just a password. TOTP is the most common method — the user opens an authenticator app (like Google Authenticator or Authy) and enters a 6-digit code that changes every 30 seconds. Snapper also provides backup codes (one-time-use codes saved offline) in case the user loses their phone.
>
> **Term: RBAC (Role-Based Access Control)** — Assigning permissions based on roles rather than individual users. Snapper has 4 roles:
> - **Owner** — Full control including billing and org deletion
> - **Admin** — Can manage rules, agents, vault, and members
> - **Member** — Can manage their own agents only
> - **Viewer** — Read-only access to dashboards and audit logs
>
> Each role has specific permissions (13 total), so you can't accidentally give someone more access than they need.
>
> **Term: SIEM (Security Information and Event Management)** — A centralized platform that collects, analyzes, and alerts on security events from across the organization. Popular SIEMs include Splunk, Microsoft Sentinel, IBM QRadar, and Elastic SIEM. Every enterprise has one, and security teams need Snapper's data flowing into it.
>
> **Term: Multi-Tenancy** — The ability to serve multiple organizations from a single installation while keeping their data completely separate. Each organization gets its own encryption keys, policies, agents, and rules. One customer can never see another customer's data.
>
> **Term: Zero-Knowledge** — A design principle where the service provider cannot read the customer's data. Snapper's PII vault is zero-knowledge — the data is encrypted with keys derived from the customer's secret, and Snapper itself cannot decrypt the values without that secret.
>
> **Term: Air-Gapped** — A deployment that is completely disconnected from the internet. Required by organizations handling classified information (defense, intelligence) or highly regulated data (certain healthcare and financial systems). Snapper works fully air-gapped because it never needs to phone home.
>
> **Term: Zero Telemetry** — Snapper sends no data back to McKinley Labs. No usage analytics, no crash reports, no phone-home behavior. The customer's data stays entirely on their own infrastructure. This is a major differentiator — most SaaS products collect extensive telemetry.

---

## Slide 13 — SSO, SCIM & Multi-Tenant RBAC

**What it says:** Deep dive into identity and access management.

**What to say (simplified):**

- **SSO:** Employees log into Snapper using their existing company credentials (Okta, Microsoft Entra, Google). No separate password to manage. IT can enforce that passwords are disabled entirely — SSO only. Snapper supports JIT (Just-in-Time) provisioning, meaning the first time an employee logs in via SSO, their Snapper account is created automatically.

- **SCIM:** When HR adds or removes someone in the identity provider, Snapper automatically creates or deactivates their access. No manual steps. When someone is terminated, their Snapper access is revoked instantly. SCIM Groups means when IdP groups change (e.g., "Engineering Team"), the corresponding Snapper team updates automatically.

- **RBAC:** Four roles — Owner, Admin, Member, Viewer — each with specific permissions. A Viewer can see dashboards and audit logs but can't change rules. An Admin can manage rules and agents but can't change billing. There are 13 specific permissions that map to these roles.

- **MFA:** TOTP-based, with QR code setup and backup codes. Orgs can require MFA for all members via a policy setting.

- **Account Lockout:** After 5 failed login attempts, the account locks for 30 minutes. Admins can unlock it immediately via the API or dashboard.

> **Term: JIT (Just-in-Time) Provisioning** — Automatically creating a user account the first time someone logs in via SSO, rather than requiring an admin to create the account in advance. This reduces admin workload and ensures no one is waiting for access.
>
> **Term: IdP (Identity Provider)** — The system that manages user identities and authentication. Examples: Okta, Microsoft Entra ID (formerly Azure AD), Google Workspace, OneLogin. The IdP is the "source of truth" for who works at the company and what groups they belong to.
>
> **Term: Account Lockout** — Automatically disabling an account after a number of failed login attempts. This prevents "brute-force" attacks where an attacker tries thousands of password combinations. Snapper locks after 5 failures for 30 minutes, and admins can unlock immediately.

---

## Slide 14 — Audit Trail, SIEM & Monitoring

**What it says:** Compliance and observability capabilities.

**What to say:** Every action in Snapper is recorded in a tamper-proof audit log — 70+ different event types covering authentication (logins, logouts, MFA events), agent actions (tool calls, approvals, denials), rule changes (who changed what, when), vault access, organization changes, and more. Each entry includes the user's IP address and browser information for forensic purposes.

The audit data can be exported to any major security monitoring system through three industry-standard methods:
- **CEF Syslog** — the universal standard that every SIEM can ingest
- **HMAC-signed Webhooks** — push notifications to any URL, with cryptographic signatures proving they came from Snapper
- **Splunk HEC** — direct integration with the most popular enterprise SIEM

For monitoring, Snapper exposes Prometheus metrics that can power Grafana dashboards for real-time visibility into agent activity, rule evaluations, and security posture.

**Compliance mapping:** SOC 2 (audit controls), GDPR (right-to-erasure via data purge API), HIPAA (PII encryption), PCI DSS (credential protection).

**The retention policy** is configurable per organization — you set how long to keep logs (7 to 3,650 days), and old records are automatically cleaned up.

> **Term: CEF (Common Event Format)** — A standard log format created by ArcSight (now part of Micro Focus/OpenText). It's the lingua franca of security logging — virtually every SIEM can read CEF. By outputting in CEF, Snapper integrates with any security monitoring tool without custom configuration.
>
> **Term: Syslog** — A standard protocol for sending log messages across a network. Think of it as a universal postal service for security events — Snapper drops events into syslog, and the SIEM picks them up.
>
> **Term: HMAC (Hash-based Message Authentication Code)** — A cryptographic technique that proves a message is authentic and hasn't been tampered with. When Snapper sends a webhook, it includes an HMAC signature. The receiver can verify the signature to confirm the message actually came from Snapper and wasn't modified in transit.
>
> **Term: Splunk HEC (HTTP Event Collector)** — Splunk's native method for receiving data over HTTP. Instead of going through syslog (which adds a middle layer), HEC sends data directly to Splunk. This is the fastest, most reliable integration path for Splunk users.
>
> **Term: Prometheus / Grafana** — Prometheus is an open-source monitoring system that collects numeric metrics (how many requests per second, how many denials, average latency). Grafana is an open-source dashboard tool that visualizes those metrics in real-time graphs and charts. Together, they're the industry standard for operational monitoring.
>
> **Term: SOC 2 Type II** — An audit standard for service organizations that demonstrates they have effective security controls in place over a period of time. SOC 2 compliance is often required by enterprise customers before they'll purchase a security product.
>
> **Term: GDPR (General Data Protection Regulation)** — European Union law governing personal data protection. Requires organizations to protect personal data and give individuals the right to have their data deleted. Snapper's PII vault and data purge API directly support GDPR compliance.
>
> **Term: HIPAA (Health Insurance Portability and Accountability Act)** — U.S. law requiring protection of health information. Relevant when AI agents handle medical data. Snapper's PII encryption satisfies the "encryption at rest" requirement.
>
> **Term: PCI DSS (Payment Card Industry Data Security Standard)** — Security standards for organizations that handle credit card data. Snapper's credential protection rules and PII vault tokenization directly support PCI DSS compliance.

---

## Slide 15 — Seven Independent Enforcement Layers

**What it says:** Defense-in-depth architecture with 7 security layers.

**What to say:** Snapper doesn't rely on a single security check. There are 7 independent layers that a request must pass through:

1. **Security Middleware** — Validates the request is coming from an allowed source (checks the Host header and Origin header to prevent spoofing)
2. **Auth + MFA** — Verifies the user's identity with password + TOTP code, checks for account lockout, and enforces role-based permissions
3. **API Key Authentication** — Verifies the agent has a valid, non-revoked API key
4. **Rule Engine** — Evaluates up to 16 rule types in priority order against the specific tool call
5. **PII Gate** — Scans the request body for personal data patterns and vault tokens
6. **Approval Workflow** — Escalates to a human decision-maker via Telegram or Slack when required
7. **Audit Trail** — Records everything immutably for compliance and forensics

**Why this matters:** If any one layer fails or has a bug, the others still protect you. An attacker would need to bypass all seven layers to execute an unauthorized action. And the default behavior at every layer is to deny — there's no "fail open" vulnerability.

**Analogy:** "Think of it as 7 locked doors between an attacker and your data, where each lock uses a different key."

> **Term: Defense in Depth** — A security strategy that uses multiple independent layers of protection. The principle: no single security mechanism is perfect, so you layer them. If an attacker bypasses one layer, the next layer catches them. This is a fundamental principle in cybersecurity, borrowed from military defense strategy.
>
> **Term: Middleware** — Software that sits between the incoming request and the application logic. It processes every request before the main application sees it. Snapper's security middleware validates that requests come from allowed sources — if the Host or Origin header doesn't match the configuration, the request is rejected before it reaches any business logic.
>
> **Term: Host Header / Origin Header** — HTTP headers that identify where a request came from. Attackers can forge these to trick systems into accepting malicious requests. Snapper validates both headers to prevent spoofing attacks.
>
> **Term: Short-Circuit** — Stopping evaluation as soon as a definitive answer is found. When a DENY rule matches, Snapper immediately blocks the request without checking remaining rules. This is both a security feature (DENY always wins) and a performance optimization.
>
> **Term: Immutable (Audit Trail)** — Cannot be changed or deleted after creation. Snapper's audit logs are write-once — even an admin cannot modify or delete a log entry. This is critical for compliance because it proves the logs haven't been tampered with.

---

## Slide 16 — No One Else Does This

**What it says:** Competitive comparison table showing Snapper vs. 3 alternatives.

**What to say:** We compared Snapper against the three closest products:

- **LlamaFirewall (Meta)** — Open-source, from Meta/Facebook. The closest competitor. It can inspect some agent actions and can be self-hosted, but it lacks PII vault, human-in-the-loop approvals, trust scoring, MCP discovery, MFA, key rotation, and browser coverage. It's more of a content safety filter than a full security platform.

- **Cloudflare AI Gateway** — A cloud service from Cloudflare that sits at the API gateway level, meaning it can see API calls going to AI providers but can't see what an agent decides to do internally. No self-hosted option (your data goes through Cloudflare's servers). No PII vault or approval workflows.

- **GitHub Advanced Security** — Focused only on scanning source code for vulnerabilities and leaked secrets. It can't inspect AI agent actions at all — it's a code security tool, not an agent security tool.

**The bottom line:** No competitor offers the combination of PII vault + MFA + key rotation + human-in-the-loop approvals + trust scoring + MCP server discovery + browser extension coverage. Snapper is the only complete Agent Application Firewall.

**For investors:** "This is a blue-ocean opportunity. We're defining a new product category that no one else has fully addressed."

> **Term: Blue Ocean** — A business strategy term meaning an uncontested market space (vs. "red ocean" = fiercely competitive). We're not competing for share in an existing market — we're creating a new category.
>
> **Term: API Gateway** — A server that sits between clients and backend services, managing API traffic. Cloudflare's AI Gateway operates at this level — it can see API calls but not the agent's internal decision-making. This is a fundamental architectural limitation that Snapper doesn't have.

---

## Slide 17 — The Cost of Doing Nothing

**What it says:** ROI analysis comparing "no agent security" vs. Snapper.

**What to say:** The average data breach costs $4.45 million (IBM, 2024). Compliance fines for mishandling data range from $100K to over $1M. Manual security review of AI agent activity takes 10+ hours per week for security teams.

With Snapper: breaches are prevented at the decision layer (before data is exposed), compliance is enforced automatically, manual review burden drops by 80%+, and there's a complete audit trail from day one.

**The key calculation:** "If Snapper prevents even a single security incident, it pays for itself in less than a week."

**For investors:** The 1,100+ automated tests and 99.9% enterprise SLA demonstrate production-grade quality.

> **Term: SLA (Service Level Agreement)** — A contractual guarantee of uptime and performance. "99.9% SLA" means Snapper guarantees to be available 99.9% of the time — that's less than 8.8 hours of downtime per year. Enterprise customers require SLAs to manage risk.
>
> **Term: ROI (Return on Investment)** — The financial return relative to the cost. Snapper's ROI argument is straightforward: the product costs far less than a single security incident, and it also saves 10+ hours per week of manual security review labor.

---

## Slide 18 — Deploy Anywhere

**What it says:** Three deployment options and pricing tiers.

**What to say:** Snapper runs on the customer's own infrastructure — never on our servers. Three deployment methods:

1. **Docker Compose** — One command (`./setup.sh`), starts 6 containers, automatic TLS encryption. Best for proof-of-concept and small deployments.
2. **Kubernetes with Helm** — For larger production environments with auto-scaling.
3. **Single VPS** — A simple Ubuntu server with Let's Encrypt certificates.

Self-hosted mode is always unlimited — no feature gating, no quotas. Air-gapped deployments are supported for regulated industries like defense and healthcare.

**Pricing is two tiers:** Pro (up to 25 agents, email support) and Enterprise (unlimited, dedicated SLA, SSO/SCIM).

**For partners:** "Self-hosted with zero telemetry is a huge differentiator in regulated industries where data can't leave the building."

> **Term: Docker / Docker Compose** — Docker is a technology that packages software into "containers" — self-contained units that include everything the software needs to run. Docker Compose is a tool that starts multiple containers together. Snapper uses 6 containers: the main app, a database (PostgreSQL), a cache (Redis), two background workers (Celery), and a web server (Caddy). One command starts everything.
>
> **Term: Container** — A lightweight, portable package that includes an application and all its dependencies. Think of it as a shipping container for software — it works the same way regardless of where you deploy it (laptop, server, cloud).
>
> **Term: Kubernetes (K8s)** — An orchestration platform for managing containers at scale. If Docker Compose is running 6 containers on one server, Kubernetes is running hundreds of containers across many servers with automatic load balancing, failover, and scaling. Used by large enterprises.
>
> **Term: Helm** — A package manager for Kubernetes. Instead of manually configuring dozens of Kubernetes files, `helm install snapper` sets everything up with sensible defaults. Like an installer wizard for Kubernetes.
>
> **Term: VPS (Virtual Private Server)** — A virtual machine hosted in the cloud. Think of it as renting a computer — you get full control without maintaining physical hardware. Common providers: AWS, DigitalOcean, Hetzner, Linode.
>
> **Term: TLS (Transport Layer Security)** — The encryption that makes websites show a padlock icon (HTTPS). TLS encrypts all data in transit between the user's browser and the server. Snapper automatically sets up TLS certificates so all communication is encrypted.
>
> **Term: Let's Encrypt** — A free, automated certificate authority that provides TLS certificates. Snapper's VPS deployment automatically obtains and renews these certificates.
>
> **Term: HPA (Horizontal Pod Autoscaler)** — A Kubernetes feature that automatically adds more instances of an application when demand increases. If 100 agents are making requests simultaneously, HPA spins up more Snapper instances to handle the load, then scales back down when it's quiet.

---

## Slide 19 — Zero to Enforcing in 5 Minutes

**What it says:** Three-step setup process.

**What to say:** Snapper is designed for fast time-to-value:

1. **Install (1 minute):** One command downloads and starts everything.
2. **Configure (2 minutes):** A setup wizard walks you through registering your first agent and connecting a notification channel (Telegram or Slack).
3. **Enforce (2 minutes):** Start in "learning mode" — Snapper watches and logs everything but doesn't block anything. This lets you see what your agents are doing without any risk of breaking workflows.

**The recommended rollout:**
- Week 1: Learning mode — observe traffic, identify what's running
- Week 2: Review traffic patterns and activate smart default rules
- Week 3: Enable trust scoring and fine-tune per-agent policies

**Why this matters:** "Learning mode eliminates the fear of deployment. You see everything, risk nothing, and enforce when you're confident."

> **Term: Learning Mode** — A Snapper operating mode where all rules are evaluated and logged, but nothing is actually blocked. Think of it as "observe only" — you can see what would have been blocked without affecting any workflows. This dramatically reduces deployment risk because you can validate your rules before enforcing them.
>
> **Term: POC (Proof of Concept)** — A small-scale trial to demonstrate that a product works as claimed. Snapper's 5-minute setup is designed to make POCs effortless — a technical team can have it running and inspecting agent traffic in a single meeting.

---

## Slide 20 — Let's Secure Your Agents

**What it says:** Call to action with three options.

**What to say:** Three paths forward:
1. **Schedule a Demo** — For stakeholders who want to see it in action
2. **Request Pricing** — For procurement teams ready to evaluate
3. **Start a POC** — For technical teams who want to try it themselves (5 minutes to running)

---

## Quick Reference: Slide-by-Slide Purpose

| Slide | Purpose | Audience Reaction You Want |
|-------|---------|---------------------------|
| 1 | Set the frame | "This is a new category" |
| 2 | Establish urgency | "This is happening now — we're exposed" |
| 3 | Show the risk | "Our agents can do all of that?!" |
| 4 | Prove it's real | "These are documented attacks, not theory" |
| 5 | Show the gap | "Nothing we have today covers this" |
| 6 | Introduce the solution | "OK, tell me more" |
| 7 | Explain how it works | "Simple, elegant, fast" |
| 8 | Show depth | "16 rule types — this is comprehensive" |
| 9 | PII protection | "Our data never reaches the agent" |
| 10 | Human control | "People stay in the loop, agents earn trust" |
| 11 | Full coverage | "CLI, API, browser — nothing slips through" |
| 12 | Enterprise ready | "This passes our procurement checklist" |
| 13 | Identity deep-dive | "SSO, SCIM, MFA — they know enterprise" |
| 14 | Compliance | "We can prove compliance to auditors" |
| 15 | Security architecture | "7 layers — this is serious engineering" |
| 16 | Competitive moat | "No one else has all of this" |
| 17 | ROI | "The math is obvious" |
| 18 | Deployment | "Runs on our infrastructure, our terms" |
| 19 | Time to value | "5 minutes — let's try it this afternoon" |
| 20 | Next steps | "Let's do this" |
