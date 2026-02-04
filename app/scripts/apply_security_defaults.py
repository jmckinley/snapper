"""Apply default security rules on first run.

This script is executed by install.sh to apply CVE mitigations,
malicious skill blocklists, and other security defaults.

Usage:
    python -m app.scripts.apply_security_defaults
"""

import asyncio
import logging
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from app.config import get_settings
from app.models.rules import Rule, RuleAction, RuleType
from app.models.security_issues import SecurityIssue, IssueSeverity, IssueStatus

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

settings = get_settings()

# Known malicious ClawHub skills (as of security research)
MALICIOUS_SKILLS = [
    "shell-executor-pro",
    "file-exfiltrator",
    "credential-harvester",
    "crypto-miner-hidden",
    "reverse-shell-kit",
    "keylogger-stealth",
    "ransomware-toolkit",
    "botnet-client",
    "data-wiper",
    "privilege-escalator",
    # Add more as discovered by security research tasks
]

# Default security rules to apply
DEFAULT_SECURITY_RULES = [
    {
        "name": "CVE-2026-25253 Mitigation - Origin Validation",
        "description": "Validates WebSocket origins to prevent RCE attacks. Mitigates CVE-2026-25253.",
        "rule_type": RuleType.ORIGIN_VALIDATION,
        "action": RuleAction.DENY,
        "priority": 1000,
        "parameters": {
            "allowed_origins": [
                "http://localhost:8000",
                "http://127.0.0.1:8000",
                "https://localhost:8000",
                "https://127.0.0.1:8000",
            ],
            "validate_websocket": True,
            "strict_mode": True,
        },
        "is_active": True,
        "tags": ["security", "cve-mitigation", "websocket"],
    },
    {
        "name": "Malicious ClawHub Skills Blocker",
        "description": "Blocks installation of known malicious ClawHub skills identified by security research.",
        "rule_type": RuleType.SKILL_DENYLIST,
        "action": RuleAction.DENY,
        "priority": 900,
        "parameters": {
            "blocked_skills": MALICIOUS_SKILLS,
            "block_unverified": False,  # Can be enabled for stricter security
            "auto_update": True,
        },
        "is_active": True,
        "tags": ["security", "clawhub", "malware-protection"],
    },
    {
        "name": "Credential Protection",
        "description": "Prevents access to sensitive credential files like .env, .pem, private keys.",
        "rule_type": RuleType.CREDENTIAL_PROTECTION,
        "action": RuleAction.DENY,
        "priority": 950,
        "parameters": {
            "protected_patterns": [
                r"\.env$",
                r"\.env\..*",
                r"\.pem$",
                r"\.key$",
                r"\.p12$",
                r"\.pfx$",
                r"id_rsa$",
                r"id_ed25519$",
                r"\.ssh/.*",
                r"credentials\.json$",
                r"secrets\.yaml$",
                r"\.aws/credentials$",
                r"\.netrc$",
            ],
            "block_plaintext_secrets": True,
            "scan_content": True,
        },
        "is_active": True,
        "tags": ["security", "credentials", "secrets"],
    },
    {
        "name": "Localhost Authentication Bypass Protection",
        "description": "Ensures authentication is required even for localhost connections to prevent auth bypass attacks.",
        "rule_type": RuleType.LOCALHOST_RESTRICTION,
        "action": RuleAction.DENY,
        "priority": 850,
        "parameters": {
            "require_localhost": True,
            "require_auth_always": True,
            "allowed_ips": ["127.0.0.1", "::1"],
        },
        "is_active": True,
        "tags": ["security", "auth", "localhost"],
    },
    {
        "name": "Dangerous Command Blocker",
        "description": "Blocks execution of potentially dangerous system commands.",
        "rule_type": RuleType.COMMAND_DENYLIST,
        "action": RuleAction.DENY,
        "priority": 800,
        "parameters": {
            "patterns": [
                r"^rm\s+-rf\s+/",
                r"^rm\s+-rf\s+~",
                r"^dd\s+.*of=/dev/",
                r"^mkfs\.",
                r"^chmod\s+777",
                r"^chmod\s+-R\s+777",
                r":(){:|:&};:",  # Fork bomb
                r">\s*/dev/sda",
                r"^curl\s+.*\|\s*(ba)?sh",
                r"^wget\s+.*\|\s*(ba)?sh",
                r"^nc\s+-e",
                r"^ncat\s+-e",
                r"^python.*-c.*import\s+socket",
            ],
        },
        "is_active": True,
        "tags": ["security", "commands", "system-protection"],
    },
    {
        "name": "Network Egress Control",
        "description": "Controls outbound network connections to prevent data exfiltration.",
        "rule_type": RuleType.NETWORK_EGRESS,
        "action": RuleAction.LOG_ONLY,  # Start with logging, user can enable blocking
        "priority": 700,
        "parameters": {
            "blocked_domains": [
                "*.pastebin.com",
                "*.transfer.sh",
                "*.file.io",
                "*.0x0.st",
            ],
            "blocked_ports": [6666, 6667, 6697, 4444, 5555],  # IRC, common backdoor ports
            "log_all_egress": True,
        },
        "is_active": True,
        "tags": ["security", "network", "egress"],
    },
    {
        "name": "Global Rate Limit",
        "description": "Prevents API abuse through rate limiting.",
        "rule_type": RuleType.RATE_LIMIT,
        "action": RuleAction.DENY,
        "priority": 600,
        "parameters": {
            "max_requests": 1000,
            "window_seconds": 3600,
            "scope": "global",
            "burst_limit": 100,
            "burst_window_seconds": 60,
        },
        "is_active": True,
        "tags": ["security", "rate-limit", "abuse-prevention"],
    },
]

# Known CVEs to track
KNOWN_CVES = [
    {
        "cve_id": "CVE-2026-25253",
        "title": "Snapper WebSocket Remote Code Execution",
        "description": "A vulnerability in Snapper's WebSocket handling allows remote attackers to execute arbitrary code by crafting malicious WebSocket messages from unauthorized origins. This bypasses origin validation when certain headers are not properly checked.",
        "severity": IssueSeverity.CRITICAL,
        "cvss_score": 8.8,
        "affected_versions": ["< 2.1.0"],
        "mitigation_notes": "Apply origin validation rules to restrict WebSocket connections to trusted origins only.",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-25253",
            "https://github.com/snapper/snapper/security/advisories/GHSA-xxxx-xxxx-xxxx",
        ],
    },
    {
        "cve_id": "CVE-2026-24891",
        "title": "Snapper Localhost Authentication Bypass",
        "description": "Snapper versions prior to 2.0.5 allow unauthenticated access from localhost connections, enabling local attackers to execute agent commands without credentials.",
        "severity": IssueSeverity.HIGH,
        "cvss_score": 7.8,
        "affected_versions": ["< 2.0.5"],
        "mitigation_notes": "Enable authentication for all connections including localhost. Apply localhost restriction rules.",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-24891",
        ],
    },
    {
        "cve_id": "CVE-2026-23456",
        "title": "ClawHub Malicious Skill Execution",
        "description": "Multiple malicious skills uploaded to ClawHub execute arbitrary code when installed. Over 341 skills have been identified as malicious.",
        "severity": IssueSeverity.CRITICAL,
        "cvss_score": 9.1,
        "affected_versions": ["all"],
        "mitigation_notes": "Apply skill denylist rules. Only install verified skills from trusted publishers.",
        "references": [
            "https://github.com/snapper/clawhub/security/advisories",
        ],
    },
]


async def create_global_rules(session: AsyncSession) -> int:
    """Create global security rules if they don't exist.

    Returns the number of rules created.
    """
    created = 0

    for rule_data in DEFAULT_SECURITY_RULES:
        # Check if rule with same name already exists
        result = await session.execute(
            select(Rule).where(
                Rule.name == rule_data["name"],
                Rule.agent_id.is_(None),  # Global rule
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            logger.info(f"Rule '{rule_data['name']}' already exists, skipping")
            continue

        rule = Rule(
            id=uuid4(),
            name=rule_data["name"],
            description=rule_data.get("description"),
            agent_id=None,  # Global rule
            rule_type=rule_data["rule_type"],
            action=rule_data["action"],
            priority=rule_data["priority"],
            parameters=rule_data["parameters"],
            is_active=rule_data["is_active"],
            tags=rule_data.get("tags", []),
        )
        session.add(rule)
        created += 1
        logger.info(f"Created rule: {rule_data['name']}")

    await session.commit()
    return created


async def create_security_issues(session: AsyncSession) -> int:
    """Create known security issues/CVEs if they don't exist.

    Returns the number of issues created.
    """
    created = 0

    for issue_data in KNOWN_CVES:
        # Check if CVE already exists
        result = await session.execute(
            select(SecurityIssue).where(
                SecurityIssue.cve_id == issue_data["cve_id"]
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            logger.info(f"CVE '{issue_data['cve_id']}' already exists, skipping")
            continue

        issue = SecurityIssue(
            id=uuid4(),
            cve_id=issue_data["cve_id"],
            title=issue_data["title"],
            description=issue_data["description"],
            severity=issue_data["severity"],
            cvss_score=issue_data["cvss_score"],
            affected_versions=issue_data.get("affected_versions", []),
            mitigation_notes=issue_data.get("mitigation_notes"),
            references=issue_data.get("references", []),
            status=IssueStatus.ACTIVE,
            auto_generate_rules=True,
        )
        session.add(issue)
        created += 1
        logger.info(f"Created CVE entry: {issue_data['cve_id']}")

    await session.commit()
    return created


async def main():
    """Apply security defaults."""
    logger.info("=" * 60)
    logger.info("Snapper Rules Manager - Applying Security Defaults")
    logger.info("=" * 60)

    # Create database connection
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async_session = async_sessionmaker(engine, expire_on_commit=False)

    async with async_session() as session:
        # Create global security rules
        logger.info("\n[1/2] Creating global security rules...")
        rules_created = await create_global_rules(session)
        logger.info(f"Created {rules_created} new security rules")

        # Create known CVE entries
        logger.info("\n[2/2] Creating known CVE entries...")
        issues_created = await create_security_issues(session)
        logger.info(f"Created {issues_created} new CVE entries")

    await engine.dispose()

    logger.info("\n" + "=" * 60)
    logger.info("Security defaults applied successfully!")
    logger.info("=" * 60)
    logger.info("\nSummary:")
    logger.info(f"  - Security rules created: {rules_created}")
    logger.info(f"  - CVE entries created: {issues_created}")
    logger.info(f"  - Malicious skills in blocklist: {len(MALICIOUS_SKILLS)}")
    logger.info("\nNext steps:")
    logger.info("  1. Access the dashboard at http://localhost:8000")
    logger.info("  2. Register your Snapper agents")
    logger.info("  3. Review and customize security rules as needed")
    logger.info("  4. Enable stricter rules based on your security requirements")


if __name__ == "__main__":
    asyncio.run(main())
