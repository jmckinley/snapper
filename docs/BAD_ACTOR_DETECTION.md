# Bad Actor Detection: Snapper vs. the Competitive Landscape

**Version:** 1.0
**Date:** February 2026
**Classification:** Technical Reference -- Investors, CISOs, Enterprise Security Teams

---

## 1. Executive Summary

AI agents are no longer confined to answering questions. They read files, execute code, call APIs, move data between systems, and make decisions with minimal human oversight. This autonomy introduces a class of security threats that traditional application firewalls were never designed to handle: multi-step attack chains where a compromised or manipulated agent uses legitimate tools in sequence to exfiltrate data, escalate privileges, or extract credentials -- all while each individual action appears benign.

Snapper's Bad Actor Detection Engine addresses this gap with a purpose-built behavioral analysis pipeline that operates at the agent-tool boundary. Rather than relying solely on prompt-level inspection (the dominant approach in the market), Snapper extracts 13 signal types from every request in under 2ms, feeds them into an asynchronous analysis pipeline that maintains per-agent behavioral baselines over 7-day rolling windows, and evaluates requests against 7 predefined kill chain state machines. The result is a composite threat score (0-100) that feeds back into the rule engine in real time, enabling graduated enforcement from alerting through human-in-the-loop approval to automatic denial.

What distinguishes Snapper from the broader AI security market is its focus on **post-prompt behavioral analysis** -- detecting bad actors not by what they say, but by what they do. While competitors have built strong defenses against prompt injection, jailbreaks, and content violations, few offer the multi-step kill chain detection, per-agent behavioral baselines, integrated PII vault awareness, and air-gapped-compatible architecture that Snapper provides. This document maps those capabilities against the competitive landscape, relevant OWASP and MITRE frameworks, and the emerging requirements of enterprise security teams deploying autonomous AI agents.

---

## 2. Snapper's Bad Actor Detection Engine

### 2.1 Architecture Overview

Snapper's detection engine is designed around a fundamental constraint: the hot path (request evaluation) must remain fast, while heavy analysis runs asynchronously. The architecture has three layers:

```
Request In
    |
    v
+----------------------------+
| Hot-Path Signal Extraction |  <2ms overhead per request
| (13 signal types, compiled |  Synchronous, inline
|  regex + pattern matching) |
+----------------------------+
    |
    v (fire-and-forget)
+----------------------------+
| Redis Streams Pipeline     |  Signals published async
| (consumed every 2 seconds  |  No hot-path blocking
|  by Celery worker)         |
+----------------------------+
    |
    v
+----------------------------+
| Background Analysis Engine |  Behavioral baselines
| - Kill chain state machines|  Anomaly scoring
| - Baseline comparison      |  Composite threat score
| - Detector signatures      |  Score -> Rule Engine
+----------------------------+
    |
    v (optional, opt-in)
+----------------------------+
| AI Review Layer            |  Claude-powered analysis
| (every 15 min, 30-min      |  Catches subtle patterns
|  activity windows)          |  Disabled by default
+----------------------------+
```

**Key design principles:**

- **Air-gapped compatible.** The full detection engine operates without any external API calls. The AI review layer is opt-in and disabled by default.
- **Fail-open on analysis errors.** If the background pipeline fails, the hot path is unaffected. Detection degrades gracefully; it never blocks legitimate traffic due to its own errors.
- **<2.5ms total hot-path overhead.** Signal extraction uses compiled regexes and pattern matching. No ML inference on the hot path.
- **Enterprise SIEM integration.** CEF event IDs 800-805 for Splunk, syslog, and webhook outputs.

### 2.2 Signal Types (13)

Every request passing through Snapper has 13 signal types extracted synchronously:

| Signal | Description |
|--------|-------------|
| `FILE_READ` | Agent reads files from filesystem or storage |
| `NETWORK_SEND` | Agent sends data to external endpoints |
| `CREDENTIAL_ACCESS` | Agent accesses API keys, tokens, passwords, or secrets |
| `PII_OUTBOUND` | Personally identifiable information detected in outbound data |
| `PII_ACCUMULATION` | Multiple PII items gathered from different sources |
| `ENCODING_DETECTED` | Base64, hex, URL encoding, or other encoding in payloads |
| `VAULT_TOKEN_PROBE` | Attempts to access or enumerate PII vault tokens |
| `PRIVILEGE_ESCALATION` | Agent attempts to gain elevated permissions |
| `STEGANOGRAPHIC_CONTENT` | Zero-width characters, high-entropy hidden data |
| `TOOL_ANOMALY` | Agent uses a tool it has not historically used |
| `HIGH_ENTROPY_PAYLOAD` | Payload entropy exceeds baseline (potential encrypted exfil) |
| `NEW_DESTINATION` | Data sent to an endpoint not seen in behavioral baseline |
| `VOLUME_SPIKE` | Outbound data volume exceeds rolling average by Z-score threshold |

### 2.3 Kill Chain State Machines (7)

Snapper's most distinctive detection capability is its kill chain engine -- predefined multi-step attack sequences modeled as state machines with time-windowed transitions:

| Kill Chain | Stages | Time Window | Score Impact |
|------------|--------|-------------|-------------|
| **Data Exfiltration** | `file_read` -> `network_send` | 60s | +40 |
| **Credential Theft** | `credential_access` -> `network_send` | 120s | +50 |
| **PII Harvest & Exfil** | 3+ `pii_outbound` -> `network_send` | 300s | +45 |
| **Encoded Exfiltration** | `file_read` -> `encoding_detected` -> `network_send` | 30s per stage | +50 |
| **Priv-Esc to Exfil** | `privilege_escalation` -> `file_read` -> `network_send` | 120s + 60s | +55 |
| **Vault Token Extraction** | `vault_token_probe` -> `pii_outbound` | 180s | +60 |
| **Living-off-the-Land Exfil** | `tool_anomaly` -> `network_send` | 60s | +35 |

Each kill chain is a finite state machine with per-stage timeout windows. If the time window elapses without the next stage firing, the chain resets. Completed chains contribute their score impact to the agent's composite threat score.

### 2.4 Behavioral Baselines

Snapper maintains per-agent behavioral profiles over a 7-day rolling window:

- **Tool usage histograms** -- frequency distribution of which tools the agent normally uses
- **Destination frequency maps** -- which external endpoints the agent normally communicates with
- **Bytes-out moving averages** -- with Z-score anomaly detection for volume spikes
- **Time-of-day patterns** -- when the agent is normally active
- **New destination detection** -- any endpoint not seen in the rolling window is flagged

These baselines enable detection of behavioral drift -- an agent that suddenly starts reading files it never accessed before, sending data to new endpoints, or operating outside its normal hours.

### 2.5 Detection Signatures

**PII Misuse Detectors (5):**
1. PII sent to untrusted or new destination
2. Vault token extraction chain (probe followed by outbound PII)
3. PII accumulation (3+ items from different sources within 5 minutes)
4. Raw PII detected in network requests (high-value vs. low-value scoring)
5. PII embedded within encoded data

**Data Exfiltration Detectors (7):**
1. File read followed by network send
2. Credential access followed by outbound transmission
3. Encoding stacking (multiple encoding types applied in sequence)
4. Volume anomaly (Z-score deviation from baseline)
5. Slow-drip exfiltration (15-minute periodic pattern detection)
6. New destination combined with sensitive data
7. Data flow reversal (outbound/inbound ratio anomaly)

**Behavioral Detectors (5):**
1. Tool usage anomaly (new tool used in sensitive context)
2. Privilege escalation (single action and chained escalation)
3. Steganographic content (zero-width characters, anomalous entropy)
4. Living-off-the-land (legitimate tools chained for exfiltration)
5. Cross-agent pattern matching (future roadmap)

### 2.6 Enforcement

The composite threat score (0-100) maps to graduated enforcement actions:

| Score Range | Action |
|-------------|--------|
| >= 80 | **Automatic DENY** -- overrides rule engine, blocks request |
| >= 60 | **REQUIRE_APPROVAL** -- human-in-the-loop via Telegram/Slack |
| >= 40 | **Alert** -- notification sent to Telegram, Slack, or SIEM |
| < 40 | **Log only** -- signal recorded for baseline building |

Additional enforcement capabilities:
- `ThreatEvent` records persisted to database with resolution workflow
- CEF event IDs 800-805 for enterprise SIEM integration (Splunk HEC, syslog, webhooks)
- Configurable thresholds per deployment
- Auto-quarantine option for high-severity detections

### 2.7 AI Review Layer

An opt-in layer that uses Claude to analyze 30-minute activity windows every 15 minutes:

- Detects behavioral shifts that statistical methods might miss
- Identifies social engineering preparation patterns
- Flags multi-agent coordination anomalies
- Confidence-weighted score adjustments (capped at +30)
- **Air-gapped safe:** disabled by default, exits immediately without API key configured

---

## 3. Competitive Landscape

### 3.1 RunLayer

**Overview:** RunLayer launched in November 2025 with $11M in seed funding from Khosla Ventures and Felicis, with MCP creator David Soria Parra as an advisor. The company focuses on securing Model Context Protocol (MCP) connections for enterprises, with customers including Gusto, dbt Labs, Instacart, and Opendoor.

**Security Capabilities:**
- Real-time threat detection for MCP-specific attack vectors (tool poisoning, prompt injection, shadow tools)
- Attribute-Based Access Control (ABAC) policies with context-aware authorization (user, device, client, server, request)
- Complete audit trails for all MCP interactions
- MCP server scanning before approval for deployment
- Multi-tier detection system designed for low-latency operation
- Integration with identity providers (Okta, Entra)

**Strengths:** Deep MCP protocol expertise; strong enterprise identity integration; purpose-built for the MCP ecosystem; well-funded with blue-chip customers.

**Gaps (based on publicly available information):** No evidence of multi-step kill chain detection, per-agent behavioral baselines, PII vault integration, or air-gapped deployment support. Focus appears to be MCP-layer security (tool poisoning, access control) rather than post-execution behavioral analysis. No public documentation of SIEM integration (CEF/syslog) or human-in-the-loop approval workflows triggered by behavioral scoring.

### 3.2 Lakera Guard

**Overview:** Lakera Guard is a real-time AI security platform focused on prompt injection defense, with deployments at companies including Dropbox. Their threat intelligence database contains tens of millions of attack data points, growing by approximately 100,000 entries per day.

**Security Capabilities:**
- Prompt injection detection (99.2% accuracy) including indirect injections, role-playing attacks, and context manipulation
- Data leakage prevention with PII detection, masking, and blocking
- Content violation detection (offensive, hateful, sexual, violent content)
- Malicious URL/domain detection
- System prompt extraction prevention
- SOC2, GDPR, and NIST compliance
- Available as SaaS or self-hosted

**Strengths:** Industry-leading prompt injection detection; massive proprietary threat intelligence database with zero-day protection; proven at enterprise scale (Dropbox); strong compliance certifications.

**Gaps (based on publicly available information):** Primarily focused on prompt-level inspection (input/output screening). No public evidence of multi-step kill chain detection, per-agent behavioral baselines over time, or composite threat scoring from tool-level signals. DLP capabilities focus on content inspection rather than behavioral pattern analysis. MITRE ATLAS alignment documented but focused on prompt-layer techniques.

### 3.3 Invariant Labs (acquired by Snyk, June 2025)

**Overview:** Invariant Labs, an ETH Zurich spin-off, was acquired by Snyk in mid-2025 and integrated into the Snyk AI Trust Platform. They built Guardrails, a transparent security layer for LLM and MCP-powered applications, along with the widely-used `mcp-scan` vulnerability scanner.

**Security Capabilities:**
- Gateway proxy between agents and LLM providers, applying policies at runtime
- PII, secrets, copyright infringement, and prompt injection detection
- Static code analysis of agent tools and implementations
- MCP server vulnerability scanning (`mcp-scan`)
- Image analysis (OCR) and HTML parsing for hidden threat detection
- Behavioral monitoring for agent drift from intended roles
- Rule-based guardrailing with contextual security rules
- Open-source toolkit with enterprise features

**Strengths:** Strong research pedigree (ETH Zurich); comprehensive static + runtime analysis; MCP-scan is an industry standard tool; now backed by Snyk's enterprise distribution.

**Gaps (based on publicly available information):** Behavioral monitoring appears to be drift-detection focused rather than multi-step attack chain analysis. No public evidence of kill chain state machines, composite threat scoring, or integrated PII vault awareness. Gateway architecture focuses on LLM-level interception rather than tool-execution-level signal extraction. Air-gapped deployment support not documented.

### 3.4 PromptArmor

**Overview:** PromptArmor operates primarily as a third-party AI risk management (TPRM) platform rather than a runtime agent firewall. The company assesses and monitors AI features across vendor portfolios, testing against 26 risk vectors mapped to OWASP LLM Top 10, MITRE ATLAS, and NIST AI RMF.

**Security Capabilities:**
- Vendor AI feature scanning and continuous monitoring
- Assessment of 26 risk vectors including indirect prompt injection
- Framework mappings (OWASP, MITRE ATLAS, NIST AI RMF)
- OAuth/SSO integration for enterprise access
- AI asset-to-data relationship mapping
- Actionable control recommendations per vendor

**Strengths:** Strong research contributions (published academic work on prompt injection defenses); comprehensive vendor risk assessment framework; useful for procurement and vendor management.

**Gaps (based on publicly available information):** Not a runtime agent firewall. Does not provide inline request inspection, behavioral analysis, kill chain detection, or real-time enforcement. Positioned as a risk assessment tool rather than a detection/prevention engine. No PII vault, SIEM integration, or human-in-the-loop approval workflows.

### 3.5 Lasso Security

**Overview:** Lasso Security is a comprehensive AI security platform covering employee AI usage monitoring, application security, and agentic AI protection. They released the first open-source MCP Security Gateway in April 2025 and introduced "Intent Deputy" in February 2026, which performs intent-level behavioral analysis.

**Security Capabilities:**
- Shadow AI discovery and continuous monitoring
- Open-source MCP Security Gateway
- Intent Deputy: behavioral-intent analysis that evaluates whether tool calls align with agent objectives
- Real-time detection and alerting with automated remediation
- Inter-tool data movement monitoring for exfiltration patterns
- Function-level tool usage policies with context-aware authorization
- Red/blue team continuous loop
- SIEM, SOAR, ticketing system, and messaging platform integration
- Autonomous adversarial testing

**Strengths:** Broad platform covering workforce AI governance through agentic security; Intent Deputy introduces meaningful behavioral analysis beyond content inspection; open-source MCP gateway; strong SIEM integration story; active research and thought leadership.

**Gaps (based on publicly available information):** Intent Deputy is newly launched (February 2026); maturity unclear. No public evidence of predefined kill chain state machines, per-agent behavioral baselines with rolling windows, or composite threat scoring. PII protection appears to be content-level detection rather than vault-integrated. Air-gapped deployment not documented.

### 3.6 Additional Players

**Pangea (AI Guard + Prompt Guard + AIDR):**
Pangea provides security guardrails as API services: AI Guard combines 13+ detectors for PII (50 types), malicious URLs, content filtering, and language detection. Prompt Guard achieves 99% accuracy (95.2 F1) for injection detection. Their 2025 AI Detection and Response (AIDR) platform adds Chrome browser integration and agentic framework SDKs. Partners with CrowdStrike and DomainTools for threat intelligence. Strong API-first approach but primarily content-inspection focused.

**NVIDIA NeMo Guardrails:**
Open-source toolkit with NIM microservices for content safety, topic control, and jailbreak detection (trained on 17,000+ known jailbreaks). Optimized for agentic AI with LangGraph integration. Adds approximately 500ms latency. Strength is ecosystem integration and GPU-accelerated inference. However, focused on LLM-level guardrails rather than tool-execution behavioral analysis.

**CalypsoAI (acquired by F5, September 2025, ~$180M):**
Runtime guardrails for prompt and output inspection, with red-teaming agents generating 10,000+ new attack patterns monthly. EU AI Act compliance scanner. Data masking and geo-location restrictions. F5 acquisition signals enterprise networking integration. Focus is primarily content safety and compliance rather than multi-step behavioral detection.

**Arthur AI:**
Model monitoring platform expanded to agentic AI in 2025, monitoring 1B+ tokens across deployments. Open-source Arthur Engine supports OpenInference specification. Guardrails for PII leakage, hallucination, prompt injection, and toxicity. Strength is model observability rather than agent-level behavioral analysis.

**NeuralTrust:**
Recognized as a Leader in 2025 KuppingerCole Leadership Compass for Generative AI Defense. Guardian Agents (November 2025) are autonomous security agents monitoring other agents in real time. Sub-10ms detection latency. 30+ injection technique coverage. Compliance automation for EU AI Act, NIST AI RMF, ISO 42001. Purpose-built for GenAI with strong governance capabilities, though detailed behavioral analysis features are not extensively documented publicly.

**Protect AI:**
Guardian scans 35+ model formats for deserialization attacks, backdoors, and runtime threats (1.5M+ Hugging Face models scanned). Layer provides API-level filtering. Recon orchestrates adversarial testing. Focus is model supply chain security rather than runtime agent behavioral analysis.

---

## 4. Feature Comparison Matrix

| Capability | Snapper | RunLayer | Lakera Guard | Invariant (Snyk) | Lasso | Pangea | NeMo Guardrails | CalypsoAI (F5) | NeuralTrust |
|---|---|---|---|---|---|---|---|---|---|
| **Prompt injection detection** | Via rule engine | Yes | Yes (99.2%) | Yes | Yes | Yes (99%) | Yes | Yes | Yes (30+ techniques) |
| **Multi-step kill chain detection** | Yes (7 chains) | Not documented | Not documented | Not documented | Partial (intent analysis) | Not documented | No | Not documented | Not documented |
| **Per-agent behavioral baselines** | Yes (7-day rolling) | Not documented | Not documented | Drift detection | Not documented | Not documented | No | Not documented | Not documented |
| **Composite threat scoring** | Yes (0-100) | Not documented | Not documented | Not documented | Not documented | Not documented | No | Not documented | Not documented |
| **Tool-level signal extraction** | Yes (13 types, <2ms) | MCP request analysis | No (prompt-level) | Static + runtime | Intent analysis | No (content-level) | No (LLM-level) | No (content-level) | Tool-use policy |
| **PII vault integration** | Yes (AES-256-GCM) | Not documented | DLP (mask/block) | PII detection | PII detection | Yes (50 types) | No | Data masking | Not documented |
| **PII-specific misuse detection** | Yes (5 signatures) | Not documented | Content inspection | Content inspection | Not documented | Content inspection | No | Content inspection | Not documented |
| **Data exfiltration detection** | Yes (7 signatures) | Not documented | Content-based DLP | Not documented | Inter-tool monitoring | Not documented | No | Not documented | Not documented |
| **Human-in-the-loop enforcement** | Yes (Telegram/Slack) | Not documented | No | Not documented | Not documented | No | No | No | Not documented |
| **SIEM integration (CEF/syslog)** | Yes (CEF 800-805) | Not documented | Not documented | Not documented | Yes | Secure Audit Log | No | Not documented | Not documented |
| **Air-gapped deployment** | Yes (full engine) | Not documented | Self-hosted option | Self-hosted option | Not documented | Not documented | Yes (open-source) | Not documented | Not documented |
| **AI-powered review layer** | Yes (opt-in Claude) | Not documented | Threat intel DB | Not documented | AI-native models | Not documented | NIM microservices | Red-team agents | Guardian Agents |
| **MCP protocol security** | Yes (traffic discovery) | Yes (core focus) | No | Yes (mcp-scan) | Yes (MCP gateway) | MCP proxy (AIDR) | No | Not documented | Not documented |
| **Behavioral anomaly detection** | Yes (Z-score, histograms) | Not documented | Not documented | Agent drift | Intent Deputy | Not documented | No | Not documented | Not documented |
| **Slow-drip exfil detection** | Yes (15-min periodic) | Not documented | Not documented | Not documented | Not documented | Not documented | No | Not documented | Not documented |
| **Encoding/steganography detection** | Yes (2 signal types) | Not documented | Not documented | Not documented | Not documented | Not documented | No | Not documented | Not documented |
| **Enterprise compliance** | CEF + audit trail | Enterprise IdP | SOC2/GDPR/NIST | Snyk platform | SOC2 | SOC2 | NVIDIA ecosystem | EU AI Act | EU AI Act/ISO 42001 |
| **Hot-path latency overhead** | <2.5ms | "No noticeable impact" | API call per request | Gateway proxy | Not documented | API call per request | ~500ms | Not documented | <10ms |

> **Note:** "Not documented" means the capability was not found in publicly available product documentation, blog posts, or press materials as of February 2026. It does not necessarily mean the feature is absent -- vendors may have undisclosed or in-development capabilities.

---

## 5. Snapper's Differentiators

### 5.1 Multi-Step Kill Chain Detection

Most competitors operate at the **single-request level** -- inspecting each prompt or tool call in isolation. Snapper's kill chain engine correlates signals **across requests over time**, detecting attack patterns that no single request would reveal. A `file_read` is benign. A `network_send` is benign. A `file_read` followed by `encoding_detected` followed by `network_send` within 90 seconds is a potential encoded exfiltration attempt scored at +50.

This temporal correlation is the fundamental gap in prompt-level security. An agent compromised via indirect prompt injection will use legitimate tools in a legitimate-looking sequence. The attack is visible only when the sequence is analyzed as a whole.

### 5.2 Per-Agent Behavioral Baselines

Snapper builds individualized behavioral profiles for each agent over 7-day rolling windows, including tool usage histograms, destination frequency maps, data volume averages, and time-of-day patterns. Anomalies are detected via Z-score deviation from the agent's own baseline -- not from generic thresholds.

This means an agent that normally reads 3 files per hour and sends data to 2 known endpoints will trigger alerts if it suddenly reads 50 files and contacts a new destination, even if those actions are within the general policy rules. The baseline makes detection adaptive to each agent's normal behavior.

### 5.3 Integrated PII Vault Awareness

Snapper's PII vault (AES-256-GCM encrypted storage with HKDF-derived keys) is not a separate product -- it is integrated into the detection engine. The `VAULT_TOKEN_PROBE` signal type and "Vault Token Extraction" kill chain specifically detect attempts to enumerate or extract vault tokens. The "PII accumulation" detector understands the difference between an agent legitimately resolving a single vault token and an agent systematically gathering PII from multiple sources.

No competitor in the current landscape offers this level of integration between PII storage and behavioral detection.

### 5.4 Air-Gapped Operation

The entire detection engine -- signal extraction, kill chain evaluation, behavioral baselines, anomaly scoring, and enforcement -- operates without external API calls. The AI review layer is opt-in and exits immediately without an API key. This makes Snapper deployable in classified, regulated, or network-isolated environments where cloud-dependent security tools cannot operate.

While Lakera and Invariant offer self-hosted options, their documentation does not confirm that all detection features work in fully air-gapped environments without any external connectivity.

### 5.5 Human-in-the-Loop Enforcement

Snapper's graduated enforcement model routes medium-severity threats (score 60-79) to human reviewers via Telegram or Slack for approval or denial. This is not simply an alert -- it is a blocking workflow where the request is held pending human decision. This bridges the gap between fully automated blocking (which risks false positives disrupting workflows) and alerting-only (which risks alerts being ignored).

### 5.6 Asynchronous Architecture with Minimal Hot-Path Impact

At <2.5ms total overhead on the hot path, Snapper's detection adds negligible latency compared to competitors. Lakera and Pangea require an API call per request. NVIDIA NeMo adds approximately 500ms. RunLayer claims "no noticeable impact" but does not publish latency figures. Snapper achieves this by performing only compiled-regex signal extraction synchronously, with all heavy analysis (baselines, kill chains, scoring) running asynchronously via Celery workers consuming from Redis Streams.

### 5.7 Enterprise SIEM Integration

Snapper produces CEF-formatted events (IDs 800-805) compatible with Splunk HEC, syslog, and webhook destinations. This is not an afterthought -- it is designed for SOC teams that need to correlate agent behavioral events with their existing security telemetry. While Lasso also documents SIEM integration, most competitors focus on their own dashboards rather than feeding into existing enterprise security stacks.

---

## 6. OWASP and MITRE Framework Alignment

### 6.1 OWASP Top 10 for Agentic Applications (2026)

The OWASP Top 10 for Agentic Applications was released in December 2025 after over a year of research by 100+ security researchers. The following table maps Snapper's detection capabilities to each risk category:

| OWASP Risk | ID | Snapper Coverage | Detection Mechanism |
|---|---|---|---|
| **Agent Goal Hijack** | ASI01 | Partial | Behavioral baseline detects deviation from normal tool usage patterns. Kill chain detection catches hijacked agents executing exfiltration sequences. AI review layer can identify subtle objective shifts. |
| **Tool Misuse & Exploitation** | ASI02 | Strong | `TOOL_ANOMALY` signal detects unusual tool invocations. Living-off-the-land kill chain catches legitimate tools chained for malicious purposes. Per-agent tool histograms flag new tool usage. |
| **Identity & Privilege Abuse** | ASI03 | Strong | `PRIVILEGE_ESCALATION` signal type. "Priv-Esc to Exfil" kill chain detects escalation followed by data access and exfiltration. Credential access monitoring. |
| **Agentic Supply Chain Vulnerabilities** | ASI04 | Partial | MCP traffic discovery scans for known and unknown servers. Smart defaults generate restrictive rules for new servers. Tool poisoning not directly addressed at detection layer (handled by rule engine). |
| **Unexpected Code Execution** | ASI05 | Partial | Rule engine blocks unauthorized commands. `TOOL_ANOMALY` can detect unexpected execution patterns. Not a primary detection focus. |
| **Memory & Context Poisoning** | ASI06 | Indirect | Behavioral baselines detect behavioral drift resulting from poisoned context. Kill chains catch the downstream effects (exfiltration, credential theft) even if the poisoning itself is not detected. |
| **Insecure Inter-Agent Communication** | ASI07 | Future (cross-agent pattern matching on roadmap) | Not currently addressed. Cross-agent detector is planned. |
| **Cascading Failures** | ASI08 | Partial | Rate limiting and adaptive trust scoring prevent cascade amplification. Volume spike detection catches cascade-induced anomalies. |
| **Human-Agent Trust Exploitation** | ASI09 | Strong | Human-in-the-loop enforcement at score >= 60 ensures human review of suspicious actions. Graduated enforcement prevents over-reliance on automated approval. |
| **Rogue Agents** | ASI10 | Strong | Core capability. Per-agent behavioral baselines detect drift. Kill chains detect rogue exfiltration/theft sequences. Composite scoring enables automatic quarantine. AI review catches subtle behavioral shifts. |

### 6.2 MITRE ATLAS Alignment

MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) expanded in October 2025 to include 14 agent-specific techniques (in collaboration with Zenity Labs), bringing the framework to 15 tactics, 66 techniques, and 46 sub-techniques. The following table maps Snapper's detections to relevant ATLAS techniques:

| ATLAS Technique | ID | Snapper Coverage | Detection Mechanism |
|---|---|---|---|
| **Exfiltration via AI Agent Tool Invocation** | AML.T0062 | Strong | Core detection target. Data Exfiltration kill chain, `NETWORK_SEND` + `FILE_READ` correlation, 7 exfiltration signatures, volume anomaly detection, slow-drip detection. |
| **AI Agent Context Poisoning** | AML.T0058 | Indirect | Behavioral baselines detect the downstream effects of poisoned context (changed tool patterns, new destinations). Not detected at the poisoning event itself. |
| **Memory Manipulation** | Related to AML.T0058 | Indirect | Same as context poisoning -- effects detected via behavioral drift. |
| **Modify AI Agent Configuration** | AML.T0059* | Partial | Rule change auditing. Behavioral baselines detect agents whose behavior changes after configuration modification. |
| **Thread Injection** | Related to AML.T0058 | Indirect | Kill chains detect malicious action sequences regardless of how the agent was compromised. |
| **Data Staging** | AML.T0025 | Strong | `FILE_READ` signal combined with `ENCODING_DETECTED` catches staging + encoding. PII accumulation detector catches data gathering from multiple sources. |
| **Reconnaissance** | TA0043 | Partial | `VAULT_TOKEN_PROBE` detects vault enumeration. `NEW_DESTINATION` detects scanning of new endpoints. Tool anomaly detects unusual exploratory tool usage. |
| **Credential Access** | TA0006 | Strong | `CREDENTIAL_ACCESS` signal type. "Credential Theft" kill chain (`credential_access` -> `network_send`). |
| **Collection** | TA0009 | Strong | `PII_ACCUMULATION` detector (3+ items from different sources in 5 minutes). `FILE_READ` volume tracking. Baseline deviation for data access patterns. |
| **Defense Evasion** | TA0005 | Strong | `ENCODING_DETECTED` catches encoding used for evasion. `STEGANOGRAPHIC_CONTENT` detects hidden data. Encoding stacking detector catches multiple layers. `HIGH_ENTROPY_PAYLOAD` flags encrypted content. |
| **Impact** | TA0040 | Partial | Volume spike and data flow reversal detectors catch destructive data movement. Auto-quarantine at score >= 80 limits blast radius. |

> *Technique IDs marked with asterisks are approximate mappings where exact ATLAS IDs were not confirmed in public documentation.

---

## 7. Summary

The AI agent security market is evolving rapidly, with significant investment flowing into prompt-level defenses, MCP protocol security, and compliance frameworks. This is necessary work -- prompt injection and tool poisoning are real and pressing threats.

However, the next generation of attacks against autonomous AI agents will not be prompt-level. They will be behavioral: multi-step sequences of individually benign actions that, in aggregate, constitute data exfiltration, credential theft, or privilege escalation. These attacks exploit the gap between what each request looks like in isolation and what the sequence of requests reveals about intent.

Snapper's Bad Actor Detection Engine is built specifically for this threat model. Its combination of hot-path signal extraction, temporal kill chain state machines, per-agent behavioral baselines, integrated PII vault awareness, and graduated human-in-the-loop enforcement addresses a gap that no other product in the current landscape fully covers -- and it does so with <2.5ms hot-path overhead, air-gapped compatibility, and enterprise SIEM integration.

---

*This document reflects publicly available information as of February 2026. Competitor capabilities may have changed since publication. "Not documented" indicates that a feature was not found in public materials and should not be interpreted as definitive absence.*
