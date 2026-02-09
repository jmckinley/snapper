# Terms of Service

**Effective Date:** February 7, 2026

## 1. Acceptance of Terms

By using Snapper ("the Software"), you agree to these Terms of Service. If you do not agree, do not use the Software.

## 2. Description of Service

Snapper is an Agent Application Firewall (AAF) that inspects and enforces security policy on AI agent traffic. It provides rule-based control, PII protection, approval workflows, and audit logging for AI agents including OpenClaw, Claude Code, Cursor, Windsurf, Cline, and custom agents.

## 3. License

Snapper is open-source software licensed under the MIT License. See [LICENSE](LICENSE) for the full license text.

## 4. Use at Your Own Risk

The Software is provided "as is" without warranty of any kind. You are solely responsible for:

- Configuring security rules appropriate for your environment
- Protecting your `SECRET_KEY` and API keys
- Securing your deployment (firewall, TLS, access controls)
- Backing up your data and encryption keys
- Evaluating whether the Software meets your security requirements

## 5. No Guarantee of Security

While Snapper is designed to enhance AI agent security, no software can guarantee complete protection. Snapper:

- Does not replace proper network security, access controls, or monitoring
- May not detect all malicious actions or PII patterns
- Depends on correct configuration to be effective
- Should be used as one layer in a defense-in-depth strategy

## 6. Data Handling

Snapper processes and stores:

- **Audit logs** of agent actions (commands, file access, network requests)
- **PII vault entries** encrypted with Fernet (AES-128-CBC) derived from your `SECRET_KEY`
- **Agent metadata** including API keys (stored as SHA-256 hashes)
- **Approval workflow state** in Redis (with configurable TTL)

All data is stored locally in your PostgreSQL and Redis instances. Snapper does not transmit data to external servers unless you configure external alerting (Telegram, Slack, email, webhooks).

## 7. PII Vault

The PII vault encrypts sensitive data using a key derived from your `SECRET_KEY` via HKDF. **Changing or losing your `SECRET_KEY` after storing vault entries will make them permanently unrecoverable.** You are responsible for securely backing up your `SECRET_KEY`.

## 8. Third-Party Integrations

Snapper integrates with third-party services (Telegram, Slack, PagerDuty, GitHub, NVD) when configured by you. These integrations are subject to the respective third-party terms of service. Snapper is not responsible for third-party service availability or data handling.

## 9. Limitation of Liability

To the maximum extent permitted by law, the authors and contributors of Snapper shall not be liable for any direct, indirect, incidental, special, consequential, or exemplary damages arising from the use or inability to use the Software, including but not limited to:

- Data loss or corruption
- Security breaches
- Unauthorized access to systems
- Loss of business or revenue
- Damages from AI agent actions that bypass security rules

## 10. Modifications

These terms may be updated from time to time. Continued use of the Software after changes constitutes acceptance of the modified terms. Check this document for the latest version.

## 11. Contact

For questions about these terms, open an issue at [github.com/jmckinley/snapper/issues](https://github.com/jmckinley/snapper/issues).
