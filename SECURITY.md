# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Snapper, please report it responsibly. **Do not open a public GitHub issue for security vulnerabilities.**

### How to Report

1. **Email:** security@greatfallsventures.com
2. **GitHub Security Advisories:** [Report a vulnerability](https://github.com/jmckinley/snapper/security/advisories/new) (preferred for tracked disclosure)

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact
- Suggested fix (if any)

### Response Timeline

| Stage | SLA |
|-------|-----|
| Acknowledgment | Within 72 hours |
| Initial assessment | Within 7 days |
| Fix development | Within 30 days for critical/high severity |
| Public disclosure | 90 days from initial report (coordinated) |

### Disclosure Policy

We follow a **90-day coordinated disclosure** timeline:

- We will work with you to understand and validate the issue.
- We will develop and test a fix before public disclosure.
- We will credit you in the advisory (unless you prefer anonymity).
- If we are unable to fix the issue within 90 days, we will coordinate with you on an appropriate disclosure timeline.

### Safe Harbor

We consider security research conducted in good faith to be authorized. We will not pursue legal action against researchers who:

- Make a good faith effort to avoid privacy violations, data destruction, and service disruption
- Only interact with accounts they own or with explicit permission from account holders
- Report vulnerabilities promptly and do not exploit them beyond what is necessary to demonstrate the issue
- Do not publicly disclose the vulnerability before the agreed-upon timeline

### Scope

The following are in scope for security reports:

- The Snapper application (`app/` directory)
- Hook scripts and agent integrations (`plugins/`, `scripts/`)
- Docker configuration and deployment scripts
- Authentication, authorization, and access control
- PII vault encryption and token handling
- Rule engine bypass or evasion
- Telegram bot command injection

The following are **out of scope**:

- Vulnerabilities in third-party dependencies (report these upstream; let us know if they affect Snapper)
- Social engineering attacks
- Denial of service via rate limiting exhaustion (this is expected behavior)
- Issues in development/testing configurations that do not affect production

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest `main` branch | Yes |
| Tagged releases | Yes |
| Older commits | Best effort |

## Security Documentation

For detailed information about Snapper's security architecture, see [docs/SECURITY.md](docs/SECURITY.md).
