# Terms of Service

**Effective Date:** February 7, 2026

## 1. Acceptance of Terms

By accessing, downloading, installing, or using Snapper ("the Software"), you acknowledge that you have read, understood, and agree to be bound by these Terms of Service ("Terms"). If you do not agree to all of these Terms, you must immediately cease all use of the Software and delete all copies in your possession.

These Terms constitute a legally binding agreement between you ("User," "you," or "your") and McKinley Labs LLC ("we," "us," or "our").

## 2. Eligibility

You must be at least 18 years of age and have the legal capacity to enter into a binding agreement in your jurisdiction to use the Software. If you are using the Software on behalf of an organization, you represent and warrant that you have the authority to bind that organization to these Terms. By using the Software, you represent that you meet these requirements.

## 3. Description of Service

Snapper is an Agent Application Firewall (AAF) that inspects and enforces security policy on AI agent traffic. It provides rule-based control, PII protection, approval workflows, and audit logging for AI agents including OpenClaw, Claude Code, Cursor, Windsurf, Cline, and custom agents.

**Snapper is a security tool, not a security guarantee.** The Software is designed to reduce risk, not eliminate it. You acknowledge that AI agent security is an evolving field and that no tool can provide absolute protection against all threats.

## 4. Beta Software

Snapper is currently in **beta**. By using the Software, you acknowledge and agree that:

- The Software is under active development and may contain bugs, errors, incomplete features, or unexpected behavior
- Features may be added, changed, or removed at any time without prior notice
- Data formats, APIs, database schemas, and configuration structures may change between versions, potentially requiring manual migration or causing data loss
- The Software has not undergone independent security auditing or formal verification
- Performance, reliability, and availability may not meet production-grade expectations
- We strongly recommend maintaining independent backups of any data stored by or processed through the Software
- The beta designation does not imply any timeline for a stable or general availability release

**Your use of the Software during the beta period is voluntary and at your own risk.** The limitations and disclaimers in these Terms apply with full force during the beta period and beyond.

## 5. License

Snapper is source-available software licensed under the [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0). See [LICENSE](LICENSE) for the full license text. The PolyForm Noncommercial License governs your right to use, copy, modify, and distribute the Software for noncommercial purposes. Commercial use requires a separate license from McKinley Labs LLC. These Terms govern additional conditions of use.

## 6. Assumption of Risk

**YOU EXPRESSLY ACKNOWLEDGE AND AGREE THAT USE OF THE SOFTWARE IS AT YOUR SOLE RISK.** By using Snapper, you assume full responsibility for:

- Selecting, configuring, testing, and maintaining security rules appropriate for your environment
- Protecting your `SECRET_KEY`, API keys, database credentials, and all other secrets
- Securing your deployment infrastructure (firewall, TLS, network access controls, operating system hardening)
- Backing up your data, encryption keys, and database contents regularly
- Evaluating whether the Software meets your security, compliance, and regulatory requirements
- Monitoring the Software's operation and responding to security events
- Keeping the Software and all dependencies up to date with security patches
- Testing the Software thoroughly in a non-production environment before deploying to production
- Understanding the security implications of every rule, configuration, and integration you enable
- Any and all consequences arising from AI agent actions, whether or not those actions were evaluated by Snapper

## 7. Acceptable Use

You agree to use the Software only for lawful purposes and in accordance with these Terms. You shall not use the Software to:

- Facilitate, enable, or conceal any activity that is illegal, fraudulent, or harmful
- Secure, monitor, or manage AI agents that are used to access systems, networks, or data without proper authorization
- Process, store, or transmit third-party personally identifiable information without the knowledge and consent of the individuals concerned
- Circumvent, disable, or interfere with security features of any system, including Snapper itself
- Develop, test, or deploy malware, ransomware, or other malicious software
- Conduct unauthorized penetration testing, vulnerability scanning, or security assessments against systems you do not own or have explicit written permission to test
- Misrepresent Snapper's capabilities to third parties or claim that use of Snapper satisfies specific compliance, regulatory, or contractual security obligations without independent verification

Violation of this section may result in termination of your right to use the Software and may expose you to civil or criminal liability.

## 8. No Guarantee of Security

**THE SOFTWARE DOES NOT AND CANNOT GUARANTEE SECURITY OF ANY KIND.** While Snapper is designed to enhance AI agent security, you expressly acknowledge and agree that:

- Snapper does not replace proper network security, access controls, intrusion detection, or security monitoring
- Snapper may fail to detect, block, or flag malicious, unauthorized, or unintended agent actions
- Snapper may fail to detect all PII, sensitive data, or confidential information in agent traffic
- Snapper depends entirely on correct configuration to be effective; misconfiguration may result in no protection or a false sense of security
- Snapper should be used as **one layer** in a defense-in-depth security strategy, never as the sole security measure
- New attack vectors, AI agent behaviors, or software vulnerabilities may emerge that Snapper does not address
- Rule evaluation, approval workflows, and blocking mechanisms may fail due to software bugs, infrastructure failures, race conditions, network issues, or other technical problems
- The absence of a blocked action in Snapper's logs does not mean the action was safe, authorized, or desirable
- Snapper's hook scripts depend on the correct functioning of third-party agent frameworks, and changes to those frameworks may break Snapper's protections without warning

## 9. Disclaimer of Warranties

**THE SOFTWARE IS PROVIDED "AS IS" AND "AS AVAILABLE" WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, ACCURACY, COMPLETENESS, RELIABILITY, SECURITY, OR AVAILABILITY.**

We do not warrant that:
- The Software will meet your requirements or expectations
- The Software will operate uninterrupted, error-free, or securely
- Any defects or vulnerabilities will be corrected
- The Software is free of viruses, malware, or other harmful components
- The results obtained from use of the Software will be accurate, complete, or reliable
- The encryption, hashing, or other security mechanisms in the Software are free from vulnerabilities

## 10. Data Handling and Privacy

Snapper processes and stores the following data locally in your infrastructure:

- **Audit logs** of agent actions (commands, file access, network requests)
- **PII vault entries** encrypted with AES-256-GCM derived from your `SECRET_KEY`
- **Agent metadata** including API keys (stored as SHA-256 hashes)
- **Approval workflow state** in Redis (with configurable TTL)

All data is stored in your own PostgreSQL and Redis instances. Snapper does not transmit data to external servers operated by us. However, if you configure external alerting (Telegram, Slack, email, webhooks, PagerDuty), data may be transmitted to those third-party services. **You are solely responsible for ensuring your use of Snapper complies with all applicable data protection laws and regulations**, including but not limited to GDPR, CCPA, HIPAA, and any other relevant privacy legislation.

We are not responsible for data breaches, data loss, or unauthorized access to data stored by Snapper, regardless of cause.

## 11. PII Vault and Encryption

The PII vault encrypts sensitive data using a key derived from your `SECRET_KEY` via HKDF.

**CRITICAL WARNING:** Changing, losing, or compromising your `SECRET_KEY` after storing vault entries will make all encrypted vault data **permanently and irreversibly unrecoverable**. No recovery mechanism exists. You are solely responsible for:

- Securely generating, storing, and backing up your `SECRET_KEY`
- Protecting your `SECRET_KEY` from unauthorized access
- Understanding that the encryption strength depends on the secrecy and strength of your `SECRET_KEY`
- Evaluating whether the encryption mechanisms meet your compliance and security requirements

We make no representations about the strength, adequacy, or suitability of the encryption algorithms used. Cryptographic standards evolve, and what is considered secure today may not be secure in the future.

## 12. Financial Transactions and Real-World Actions

Snapper enables AI agents to perform real-world actions on your behalf, including but not limited to filling out payment forms, submitting credentials to third-party websites, executing financial transactions, and interacting with external services. You expressly acknowledge and agree that:

- **You are solely responsible for any financial transaction** initiated, facilitated, or completed by an AI agent operating under your control, whether or not that transaction was approved through Snapper's approval workflow
- Snapper does not verify the correctness, legitimacy, or appropriateness of any transaction — it enforces rules you configure, nothing more
- Approval of an action via Telegram or any other notification channel constitutes your authorization of that action; you are responsible for reviewing the details before approving
- Accidental, rushed, or uninformed approvals are your responsibility — Snapper provides information to help you decide, but the decision is yours
- Snapper does not validate that amounts, recipients, account numbers, or other transaction details are correct
- We are not liable for unauthorized purchases, incorrect payments, overpayments, fraud, or any financial loss resulting from agent actions, regardless of whether those actions passed through Snapper's approval workflow

## 13. Mobile and Remote Approval Risks

Snapper's approval workflow may deliver approval requests to mobile devices via Telegram or other notification services. You acknowledge that:

- Mobile approval carries inherent risks including accidental approval (mis-taps), approval on compromised or shared devices, and notification fatigue leading to insufficient review of action details
- You are responsible for securing any device used to receive and respond to Snapper approval requests
- A compromised Telegram account or device could allow unauthorized approval of agent actions
- Network delays between the agent's request and your approval notification may result in stale context — the agent's environment may have changed between when the request was made and when you review it
- The "Allow Always" feature permanently authorizes a class of actions without future review; you should use this feature only when you fully understand its implications

## 14. Third-Party Integrations and Dependencies

Snapper integrates with third-party services and depends on third-party software. You acknowledge that:

- Third-party integrations (Telegram, Slack, PagerDuty, GitHub, NVD) are subject to their respective terms of service and privacy policies
- We are not responsible for the availability, reliability, accuracy, or security of any third-party service
- Third-party services may change their APIs, terms, or behavior at any time, which may break Snapper's integrations
- Snapper depends on third-party software libraries, and vulnerabilities in those dependencies may affect the security of the Software
- Agent hook scripts depend on the specific behavior of third-party AI agents (Cursor, Windsurf, Cline, Claude Code, OpenClaw), which may change without notice

## 15. Limitation of Liability

**TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL MCKINLEY LABS LLC, ITS OFFICERS, DIRECTORS, EMPLOYEES, CONTRIBUTORS, OR AGENTS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, PUNITIVE, OR EXEMPLARY DAMAGES WHATSOEVER, INCLUDING BUT NOT LIMITED TO:**

- Loss, theft, or corruption of data (including encrypted vault data)
- Security breaches, data breaches, or unauthorized access to systems or data
- Unauthorized, unintended, or malicious actions performed by AI agents
- AI agent actions that bypass, circumvent, or are not evaluated by Snapper's security rules
- Loss of business, revenue, profits, goodwill, or anticipated savings
- Business interruption or system downtime
- Cost of procurement of substitute goods or services
- Regulatory fines, penalties, or legal liability arising from data protection violations
- Damage to reputation arising from security incidents
- Any damages arising from the use or inability to use the Software
- Any damages arising from unauthorized access to or alteration of your data or transmissions

**THIS LIMITATION APPLIES WHETHER THE DAMAGES ARISE FROM USE OR MISUSE OF THE SOFTWARE, FROM INABILITY TO USE THE SOFTWARE, OR FROM THE INTERRUPTION, SUSPENSION, OR TERMINATION OF THE SOFTWARE, WHETHER MCKINLEY LABS LLC WAS ADVISED OF THE POSSIBILITY OF SUCH DAMAGES, AND REGARDLESS OF THE THEORY OF LIABILITY (CONTRACT, TORT, STRICT LIABILITY, OR OTHERWISE).**

**IN JURISDICTIONS THAT DO NOT ALLOW THE EXCLUSION OR LIMITATION OF INCIDENTAL OR CONSEQUENTIAL DAMAGES, OUR LIABILITY SHALL BE LIMITED TO THE MAXIMUM EXTENT PERMITTED BY LAW.**

## 16. Indemnification

You agree to indemnify, defend, and hold harmless McKinley Labs LLC, its officers, directors, employees, contributors, and agents from and against any and all claims, damages, losses, liabilities, costs, and expenses (including reasonable attorneys' fees and court costs) arising out of or relating to:

- Your use or misuse of the Software
- Your violation of these Terms
- Your violation of any applicable law, regulation, or third-party right
- Any security incident, data breach, or unauthorized access arising from your deployment of the Software
- Any claim by a third party related to actions performed by AI agents under your control, whether or not those actions were evaluated by Snapper
- Your failure to properly configure, maintain, or secure the Software
- Any data processed, stored, or transmitted through the Software

## 17. No Professional Advice

The Software does not constitute professional security, legal, compliance, or technical advice. You should consult qualified professionals regarding your specific security, compliance, and regulatory requirements. The presence of security features in the Software does not imply that those features are sufficient for your use case or that your use of the Software satisfies any legal or regulatory obligation.

## 18. Compliance and Regulatory

You are solely responsible for determining whether your use of the Software complies with all applicable laws, regulations, and industry standards. Snapper is not certified, audited, or approved by any regulatory body. The Software is not designed or intended to meet the requirements of any specific compliance framework (including but not limited to SOC 2, ISO 27001, PCI DSS, HIPAA, FedRAMP, or GDPR) unless explicitly stated in writing.

## 19. Export Controls

The Software includes cryptographic functionality (AES-256-GCM encryption) and may be subject to export control laws and regulations, including the U.S. Export Administration Regulations (EAR). You agree to comply with all applicable export and re-export control laws and regulations. You shall not download, use, or export the Software in violation of U.S. law or the laws of your jurisdiction, including to any country, entity, or person subject to U.S. sanctions or export restrictions. You represent and warrant that you are not located in, under the control of, or a national or resident of any country to which export of the Software would be prohibited.

## 20. Availability and Support

The Software is provided without any guarantee of availability, uptime, support, maintenance, or updates. We are under no obligation to:

- Provide technical support or assistance
- Fix bugs, vulnerabilities, or defects
- Release updates, patches, or new versions
- Maintain backward compatibility
- Respond to issues, feature requests, or security reports within any timeframe

## 21. Class Action Waiver

**YOU AND MCKINLEY LABS LLC AGREE THAT ANY DISPUTE ARISING OUT OF OR RELATING TO THESE TERMS OR THE SOFTWARE SHALL BE RESOLVED ON AN INDIVIDUAL BASIS ONLY.** You expressly waive any right to participate in a class action, collective action, or representative proceeding of any kind. You agree that:

- All claims must be brought in your individual capacity, not as a plaintiff or class member in any purported class, collective, or representative proceeding
- You waive any right to a jury trial
- Any dispute shall first be attempted to be resolved through good-faith negotiation for a period of 30 days before initiating legal proceedings
- Small claims court actions (within jurisdictional limits) are exempt from this provision

If any part of this class action waiver is found to be unenforceable, the remainder of this dispute resolution section shall still apply.

## 22. Governing Law and Dispute Resolution

These Terms shall be governed by and construed in accordance with the laws of the State of Texas, United States, without regard to its conflict of law provisions. Any dispute arising out of or relating to these Terms or the Software shall be resolved exclusively in the state or federal courts located in Dallas County, Texas, and you consent to the personal jurisdiction of such courts.

## 23. Severability

If any provision of these Terms is held to be invalid, illegal, or unenforceable by a court of competent jurisdiction, such provision shall be modified to the minimum extent necessary to make it valid and enforceable, or if modification is not possible, shall be severed from these Terms. The invalidity of any provision shall not affect the validity or enforceability of the remaining provisions, which shall continue in full force and effect.

## 24. Entire Agreement

These Terms, together with the PolyForm Noncommercial License 1.0.0, constitute the entire agreement between you and us regarding the Software and supersede all prior or contemporaneous agreements, representations, warranties, and understandings, whether written, oral, or implied.

## 25. Waiver

The failure of McKinley Labs LLC to enforce any right or provision of these Terms shall not constitute a waiver of such right or provision. Any waiver of any provision of these Terms will be effective only if in writing and signed by McKinley Labs LLC.

## 26. Modifications

We reserve the right to modify these Terms at any time without prior notice. Changes are effective immediately upon being posted in the repository. Your continued use of the Software after any modification constitutes your acceptance of the modified Terms. It is your responsibility to review these Terms periodically for changes.

## 27. Contact

For questions about these terms, open an issue at [github.com/jmckinley/snapper/issues](https://github.com/jmckinley/snapper/issues).
