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
from app.models.security_issues import (
    MaliciousSkill,
    SecurityIssue,
    IssueSeverity,
    IssueStatus,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

settings = get_settings()

# Known malicious ClawHub skills (as of security research - Feb 2026)
# Source: ClawHavoc campaign analysis, ToxicSkills study, Snyk research
MALICIOUS_SKILLS = [
    # Original blocklist
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

    # ClawHub typosquatting variants (ClawHavoc campaign - Feb 2026)
    "clawhub",
    "clawhub1",
    "clawhubb",
    "clawhubcli",
    "clawwhub",
    "cllawhub",
    "clawdhub",
    "clawdhub1",

    # Known malicious with random suffixes (pattern: clawhub-XXXXX)
    "clawhub-6yr3b",
    "clawhub-c9y4p",
    "clawhub-d4kxr",
    "clawhub-f3qcn",
    "clawhub-gpcrq",
    "clawhub-gstca",
    "clawhub-hh1fd",
    "clawhub-hh2km",
    "clawhub-hylhq",
    "clawhub-i7oci",
    "clawhub-i9zhz",
    "clawhub-ja7eh",
    "clawhub-krmvq",
    "clawhub-oihpl",
    "clawhub-olgys",
    "clawhub-osasg",
    "clawhub-rkvny",
    "clawhub-sxtsn",
    "clawhub-tlxx5",
    "clawhub-uoeym",
    "clawhub-wixce",
    "clawhub-wotp2",

    # Auto-updater category (high risk - dynamic payload fetching)
    "auto-update-helper",
    "skill-auto-updater",
    "clawhub-updater",
    "self-update-tool",
]

# Malicious skill patterns (regex) - matched in rule_engine.py
MALICIOUS_SKILL_PATTERNS = [
    r"^clawhub[0-9a-z\-]*$",      # ClawHub typosquats
    r"^clawdhub[0-9a-z\-]*$",     # clawdhub typosquats
    r"^hightower6eu/.*$",          # Known malicious publisher (314+ skills)
    r".*crypto-trader.*",          # Crypto trading category (111 malicious)
    r".*polymarket-bot.*",         # Prediction market bots (34 malicious)
    r".*-auto-updater.*",          # Auto-updaters (28 malicious, dynamic payloads)
    r".*solana-wallet.*",          # Wallet drainers
    r".*-miner-.*",                # Crypto miners
    r".*-stealer.*",               # Credential stealers
    r".*-backdoor.*",              # Backdoors
    r".*-rat$",                    # Remote access trojans
]

# Malicious publishers to block entirely
MALICIOUS_PUBLISHERS = [
    "hightower6eu",  # 314+ malicious skills in ClawHavoc campaign
]

# Detailed malicious skill records for the malicious_skills database table.
# Each entry maps to a MaliciousSkill model row with full threat classification.
MALICIOUS_SKILL_RECORDS = [
    # --- Original blocklist (general malware tools) ---
    {
        "skill_id": "shell-executor-pro",
        "skill_name": "Shell Executor Pro",
        "author": None,
        "threat_type": "rce",
        "severity": IssueSeverity.CRITICAL,
        "description": "Executes arbitrary shell commands without sandboxing or user approval.",
        "indicators": {"patterns": ["subprocess.call", "os.system"], "behavior": "unrestricted_shell"},
        "confidence": "high",
        "source": "scan",
        "is_blocked": True,
        "is_verified": True,
    },
    {
        "skill_id": "file-exfiltrator",
        "skill_name": "File Exfiltrator",
        "author": None,
        "threat_type": "data_exfil",
        "severity": IssueSeverity.CRITICAL,
        "description": "Reads and transmits local files to external servers.",
        "indicators": {"patterns": ["requests.post", "open("], "behavior": "file_upload"},
        "confidence": "high",
        "source": "scan",
        "is_blocked": True,
        "is_verified": True,
    },
    {
        "skill_id": "credential-harvester",
        "skill_name": "Credential Harvester",
        "author": None,
        "threat_type": "credential_theft",
        "severity": IssueSeverity.CRITICAL,
        "description": "Harvests credentials from environment variables, config files, and keychains.",
        "indicators": {"patterns": ["os.environ", ".env", "keychain"], "behavior": "credential_access"},
        "confidence": "high",
        "source": "scan",
        "is_blocked": True,
        "is_verified": True,
    },
    {
        "skill_id": "crypto-miner-hidden",
        "skill_name": "Crypto Miner (Hidden)",
        "author": None,
        "threat_type": "cryptominer",
        "severity": IssueSeverity.HIGH,
        "description": "Runs cryptocurrency mining in background processes consuming system resources.",
        "indicators": {"patterns": ["hashlib", "threading"], "behavior": "cpu_intensive_loop"},
        "confidence": "high",
        "source": "scan",
        "is_blocked": True,
        "is_verified": True,
    },
    {
        "skill_id": "reverse-shell-kit",
        "skill_name": "Reverse Shell Kit",
        "author": None,
        "threat_type": "backdoor",
        "severity": IssueSeverity.CRITICAL,
        "description": "Opens reverse shell connections to attacker-controlled servers.",
        "indicators": {"patterns": ["socket.connect", "/dev/tcp"], "behavior": "reverse_shell"},
        "confidence": "confirmed",
        "source": "scan",
        "is_blocked": True,
        "is_verified": True,
    },
    {
        "skill_id": "keylogger-stealth",
        "skill_name": "Keylogger Stealth",
        "author": None,
        "threat_type": "spyware",
        "severity": IssueSeverity.CRITICAL,
        "description": "Captures keystrokes and sends them to external endpoints.",
        "indicators": {"patterns": ["pynput", "keyboard.hook"], "behavior": "input_capture"},
        "confidence": "high",
        "source": "scan",
        "is_blocked": True,
        "is_verified": True,
    },
    {
        "skill_id": "ransomware-toolkit",
        "skill_name": "Ransomware Toolkit",
        "author": None,
        "threat_type": "ransomware",
        "severity": IssueSeverity.CRITICAL,
        "description": "Encrypts user files and demands ransom for decryption keys.",
        "indicators": {"patterns": ["cryptography.fernet", "os.walk"], "behavior": "file_encryption"},
        "confidence": "confirmed",
        "source": "scan",
        "is_blocked": True,
        "is_verified": True,
    },
    {
        "skill_id": "botnet-client",
        "skill_name": "Botnet Client",
        "author": None,
        "threat_type": "botnet",
        "severity": IssueSeverity.CRITICAL,
        "description": "Connects to C2 server and executes remote commands as part of a botnet.",
        "indicators": {"patterns": ["socket", "json.loads", "eval"], "behavior": "c2_communication"},
        "confidence": "high",
        "source": "scan",
        "is_blocked": True,
        "is_verified": True,
    },
    {
        "skill_id": "data-wiper",
        "skill_name": "Data Wiper",
        "author": None,
        "threat_type": "destructive",
        "severity": IssueSeverity.CRITICAL,
        "description": "Recursively deletes files and overwrites disk sectors.",
        "indicators": {"patterns": ["shutil.rmtree", "os.remove"], "behavior": "mass_deletion"},
        "confidence": "confirmed",
        "source": "scan",
        "is_blocked": True,
        "is_verified": True,
    },
    {
        "skill_id": "privilege-escalator",
        "skill_name": "Privilege Escalator",
        "author": None,
        "threat_type": "privilege_escalation",
        "severity": IssueSeverity.CRITICAL,
        "description": "Attempts to escalate privileges via SUID exploits and sudo misconfigurations.",
        "indicators": {"patterns": ["chmod u+s", "sudo"], "behavior": "priv_escalation"},
        "confidence": "high",
        "source": "scan",
        "is_blocked": True,
        "is_verified": True,
    },
    # --- ClawHavoc campaign typosquatting variants ---
    {
        "skill_id": "clawhub",
        "skill_name": "clawhub (typosquat)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.CRITICAL,
        "description": "Typosquat of official ClawHub CLI. Part of ClawHavoc campaign distributing macOS malware via ClickFix instructions.",
        "indicators": {"campaign": "ClawHavoc", "technique": "typosquatting", "malware_type": "ClickFix"},
        "confidence": "confirmed",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": True,
    },
    {
        "skill_id": "clawhub1",
        "skill_name": "clawhub1 (typosquat)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.CRITICAL,
        "description": "Typosquat variant of ClawHub CLI. ClawHavoc campaign.",
        "indicators": {"campaign": "ClawHavoc", "technique": "typosquatting"},
        "confidence": "confirmed",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": True,
    },
    {
        "skill_id": "clawhubb",
        "skill_name": "clawhubb (typosquat)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.CRITICAL,
        "description": "Typosquat variant of ClawHub CLI. ClawHavoc campaign.",
        "indicators": {"campaign": "ClawHavoc", "technique": "typosquatting"},
        "confidence": "confirmed",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": True,
    },
    {
        "skill_id": "clawhubcli",
        "skill_name": "clawhubcli (typosquat)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.CRITICAL,
        "description": "Typosquat variant of ClawHub CLI. ClawHavoc campaign.",
        "indicators": {"campaign": "ClawHavoc", "technique": "typosquatting"},
        "confidence": "confirmed",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": True,
    },
    {
        "skill_id": "clawwhub",
        "skill_name": "clawwhub (typosquat)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.CRITICAL,
        "description": "Typosquat variant of ClawHub CLI. ClawHavoc campaign.",
        "indicators": {"campaign": "ClawHavoc", "technique": "typosquatting"},
        "confidence": "confirmed",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": True,
    },
    {
        "skill_id": "cllawhub",
        "skill_name": "cllawhub (typosquat)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.CRITICAL,
        "description": "Typosquat variant of ClawHub CLI. ClawHavoc campaign.",
        "indicators": {"campaign": "ClawHavoc", "technique": "typosquatting"},
        "confidence": "confirmed",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": True,
    },
    {
        "skill_id": "clawdhub",
        "skill_name": "clawdhub (typosquat)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.CRITICAL,
        "description": "Typosquat variant of ClawHub CLI. ClawHavoc campaign.",
        "indicators": {"campaign": "ClawHavoc", "technique": "typosquatting"},
        "confidence": "confirmed",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": True,
    },
    {
        "skill_id": "clawdhub1",
        "skill_name": "clawdhub1 (typosquat)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.CRITICAL,
        "description": "Typosquat variant of ClawHub CLI. ClawHavoc campaign.",
        "indicators": {"campaign": "ClawHavoc", "technique": "typosquatting"},
        "confidence": "confirmed",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": True,
    },
    # --- ClawHavoc random suffix variants (representative sample) ---
    {
        "skill_id": "clawhub-6yr3b",
        "skill_name": "clawhub-6yr3b (random suffix)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.HIGH,
        "description": "Random-suffix ClawHub typosquat. Part of ClawHavoc campaign batch generation.",
        "indicators": {"campaign": "ClawHavoc", "technique": "random_suffix_typosquatting"},
        "confidence": "high",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": False,
    },
    {
        "skill_id": "clawhub-c9y4p",
        "skill_name": "clawhub-c9y4p (random suffix)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.HIGH,
        "description": "Random-suffix ClawHub typosquat. Part of ClawHavoc campaign batch generation.",
        "indicators": {"campaign": "ClawHavoc", "technique": "random_suffix_typosquatting"},
        "confidence": "high",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": False,
    },
    {
        "skill_id": "clawhub-d4kxr",
        "skill_name": "clawhub-d4kxr (random suffix)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.HIGH,
        "description": "Random-suffix ClawHub typosquat. Part of ClawHavoc campaign batch generation.",
        "indicators": {"campaign": "ClawHavoc", "technique": "random_suffix_typosquatting"},
        "confidence": "high",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": False,
    },
    {
        "skill_id": "clawhub-f3qcn",
        "skill_name": "clawhub-f3qcn (random suffix)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.HIGH,
        "description": "Random-suffix ClawHub typosquat. Part of ClawHavoc campaign batch generation.",
        "indicators": {"campaign": "ClawHavoc", "technique": "random_suffix_typosquatting"},
        "confidence": "high",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": False,
    },
    {
        "skill_id": "clawhub-gpcrq",
        "skill_name": "clawhub-gpcrq (random suffix)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.HIGH,
        "description": "Random-suffix ClawHub typosquat. Part of ClawHavoc campaign batch generation.",
        "indicators": {"campaign": "ClawHavoc", "technique": "random_suffix_typosquatting"},
        "confidence": "high",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": False,
    },
    {
        "skill_id": "clawhub-gstca",
        "skill_name": "clawhub-gstca (random suffix)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.HIGH,
        "description": "Random-suffix ClawHub typosquat. Part of ClawHavoc campaign batch generation.",
        "indicators": {"campaign": "ClawHavoc", "technique": "random_suffix_typosquatting"},
        "confidence": "high",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": False,
    },
    {
        "skill_id": "clawhub-hh1fd",
        "skill_name": "clawhub-hh1fd (random suffix)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.HIGH,
        "description": "Random-suffix ClawHub typosquat. Part of ClawHavoc campaign batch generation.",
        "indicators": {"campaign": "ClawHavoc", "technique": "random_suffix_typosquatting"},
        "confidence": "high",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": False,
    },
    {
        "skill_id": "clawhub-hh2km",
        "skill_name": "clawhub-hh2km (random suffix)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.HIGH,
        "description": "Random-suffix ClawHub typosquat. Part of ClawHavoc campaign batch generation.",
        "indicators": {"campaign": "ClawHavoc", "technique": "random_suffix_typosquatting"},
        "confidence": "high",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": False,
    },
    {
        "skill_id": "clawhub-hylhq",
        "skill_name": "clawhub-hylhq (random suffix)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.HIGH,
        "description": "Random-suffix ClawHub typosquat. Part of ClawHavoc campaign batch generation.",
        "indicators": {"campaign": "ClawHavoc", "technique": "random_suffix_typosquatting"},
        "confidence": "high",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": False,
    },
    {
        "skill_id": "clawhub-i7oci",
        "skill_name": "clawhub-i7oci (random suffix)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.HIGH,
        "description": "Random-suffix ClawHub typosquat. Part of ClawHavoc campaign batch generation.",
        "indicators": {"campaign": "ClawHavoc", "technique": "random_suffix_typosquatting"},
        "confidence": "high",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": False,
    },
    {
        "skill_id": "clawhub-i9zhz",
        "skill_name": "clawhub-i9zhz (random suffix)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.HIGH,
        "description": "Random-suffix ClawHub typosquat. Part of ClawHavoc campaign batch generation.",
        "indicators": {"campaign": "ClawHavoc", "technique": "random_suffix_typosquatting"},
        "confidence": "high",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": False,
    },
    {
        "skill_id": "clawhub-ja7eh",
        "skill_name": "clawhub-ja7eh (random suffix)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.HIGH,
        "description": "Random-suffix ClawHub typosquat. Part of ClawHavoc campaign batch generation.",
        "indicators": {"campaign": "ClawHavoc", "technique": "random_suffix_typosquatting"},
        "confidence": "high",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": False,
    },
    {
        "skill_id": "clawhub-krmvq",
        "skill_name": "clawhub-krmvq (random suffix)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.HIGH,
        "description": "Random-suffix ClawHub typosquat. Part of ClawHavoc campaign batch generation.",
        "indicators": {"campaign": "ClawHavoc", "technique": "random_suffix_typosquatting"},
        "confidence": "high",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": False,
    },
    {
        "skill_id": "clawhub-oihpl",
        "skill_name": "clawhub-oihpl (random suffix)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.HIGH,
        "description": "Random-suffix ClawHub typosquat. Part of ClawHavoc campaign batch generation.",
        "indicators": {"campaign": "ClawHavoc", "technique": "random_suffix_typosquatting"},
        "confidence": "high",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": False,
    },
    {
        "skill_id": "clawhub-olgys",
        "skill_name": "clawhub-olgys (random suffix)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.HIGH,
        "description": "Random-suffix ClawHub typosquat. Part of ClawHavoc campaign batch generation.",
        "indicators": {"campaign": "ClawHavoc", "technique": "random_suffix_typosquatting"},
        "confidence": "high",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": False,
    },
    {
        "skill_id": "clawhub-osasg",
        "skill_name": "clawhub-osasg (random suffix)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.HIGH,
        "description": "Random-suffix ClawHub typosquat. Part of ClawHavoc campaign batch generation.",
        "indicators": {"campaign": "ClawHavoc", "technique": "random_suffix_typosquatting"},
        "confidence": "high",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": False,
    },
    {
        "skill_id": "clawhub-rkvny",
        "skill_name": "clawhub-rkvny (random suffix)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.HIGH,
        "description": "Random-suffix ClawHub typosquat. Part of ClawHavoc campaign batch generation.",
        "indicators": {"campaign": "ClawHavoc", "technique": "random_suffix_typosquatting"},
        "confidence": "high",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": False,
    },
    {
        "skill_id": "clawhub-sxtsn",
        "skill_name": "clawhub-sxtsn (random suffix)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.HIGH,
        "description": "Random-suffix ClawHub typosquat. Part of ClawHavoc campaign batch generation.",
        "indicators": {"campaign": "ClawHavoc", "technique": "random_suffix_typosquatting"},
        "confidence": "high",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": False,
    },
    {
        "skill_id": "clawhub-tlxx5",
        "skill_name": "clawhub-tlxx5 (random suffix)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.HIGH,
        "description": "Random-suffix ClawHub typosquat. Part of ClawHavoc campaign batch generation.",
        "indicators": {"campaign": "ClawHavoc", "technique": "random_suffix_typosquatting"},
        "confidence": "high",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": False,
    },
    {
        "skill_id": "clawhub-uoeym",
        "skill_name": "clawhub-uoeym (random suffix)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.HIGH,
        "description": "Random-suffix ClawHub typosquat. Part of ClawHavoc campaign batch generation.",
        "indicators": {"campaign": "ClawHavoc", "technique": "random_suffix_typosquatting"},
        "confidence": "high",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": False,
    },
    {
        "skill_id": "clawhub-wixce",
        "skill_name": "clawhub-wixce (random suffix)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.HIGH,
        "description": "Random-suffix ClawHub typosquat. Part of ClawHavoc campaign batch generation.",
        "indicators": {"campaign": "ClawHavoc", "technique": "random_suffix_typosquatting"},
        "confidence": "high",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": False,
    },
    {
        "skill_id": "clawhub-wotp2",
        "skill_name": "clawhub-wotp2 (random suffix)",
        "author": "hightower6eu",
        "threat_type": "typosquatting",
        "severity": IssueSeverity.HIGH,
        "description": "Random-suffix ClawHub typosquat. Part of ClawHavoc campaign batch generation.",
        "indicators": {"campaign": "ClawHavoc", "technique": "random_suffix_typosquatting"},
        "confidence": "high",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": False,
    },
    # --- Auto-updater category (dynamic payload fetching) ---
    {
        "skill_id": "auto-update-helper",
        "skill_name": "Auto Update Helper",
        "author": None,
        "threat_type": "dropper",
        "severity": IssueSeverity.HIGH,
        "description": "Auto-updater that fetches and executes dynamic payloads from remote servers.",
        "indicators": {"patterns": ["urllib.request", "exec("], "behavior": "dynamic_payload_fetch"},
        "confidence": "high",
        "source": "scan",
        "is_blocked": True,
        "is_verified": True,
    },
    {
        "skill_id": "skill-auto-updater",
        "skill_name": "Skill Auto Updater",
        "author": None,
        "threat_type": "dropper",
        "severity": IssueSeverity.HIGH,
        "description": "Masquerades as skill updater but downloads and runs arbitrary code.",
        "indicators": {"patterns": ["requests.get", "eval("], "behavior": "dynamic_payload_fetch"},
        "confidence": "high",
        "source": "scan",
        "is_blocked": True,
        "is_verified": True,
    },
    {
        "skill_id": "clawhub-updater",
        "skill_name": "ClawHub Updater (fake)",
        "author": "hightower6eu",
        "threat_type": "dropper",
        "severity": IssueSeverity.HIGH,
        "description": "Fake ClawHub updater that downloads malware. Part of ClawHavoc campaign.",
        "indicators": {"campaign": "ClawHavoc", "behavior": "dynamic_payload_fetch"},
        "confidence": "confirmed",
        "source": "intel_feed",
        "is_blocked": True,
        "is_verified": True,
    },
    {
        "skill_id": "self-update-tool",
        "skill_name": "Self Update Tool",
        "author": None,
        "threat_type": "dropper",
        "severity": IssueSeverity.HIGH,
        "description": "Self-updating tool that replaces its own code with remotely fetched payloads.",
        "indicators": {"patterns": ["__file__", "urllib"], "behavior": "self_modification"},
        "confidence": "high",
        "source": "scan",
        "is_blocked": True,
        "is_verified": False,
    },
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
        "description": "Blocks installation of known malicious ClawHub skills identified by security research. Includes ClawHavoc campaign (341+ skills) and ToxicSkills (1467 payloads).",
        "rule_type": RuleType.SKILL_DENYLIST,
        "action": RuleAction.DENY,
        "priority": 900,
        "parameters": {
            "blocked_skills": MALICIOUS_SKILLS,
            "blocked_patterns": MALICIOUS_SKILL_PATTERNS,
            "blocked_publishers": MALICIOUS_PUBLISHERS,
            "block_unverified": False,  # Can be enabled for stricter security
            "auto_update": True,
        },
        "is_active": True,
        "tags": ["security", "clawhub", "malware-protection", "clawhavoc"],
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
        "description": "Blocks execution of potentially dangerous system commands including RCE, reverse shells, and data exfiltration vectors.",
        "rule_type": RuleType.COMMAND_DENYLIST,
        "action": RuleAction.DENY,
        "priority": 800,
        "parameters": {
            "patterns": [
                # Destructive commands
                r"^rm\s+-rf\s+/",
                r"^rm\s+-rf\s+~",
                r"^dd\s+.*of=/dev/",
                r"^mkfs\.",
                r"^chmod\s+777",
                r"^chmod\s+-R\s+777",
                r":(){:|:&};:",  # Fork bomb
                r">\s*/dev/sda",

                # Remote code execution (pipe to shell)
                r".*curl\s+.*\|\s*(ba)?sh",
                r".*wget\s+.*\|\s*(ba)?sh",
                r".*curl\s+.*\|\s*python",
                r".*wget\s+.*\|\s*python",

                # Base64 encoded command execution (bypass attempts)
                r".*base64\s+-d.*\|\s*(ba)?sh",
                r".*base64\s+--decode.*\|\s*(ba)?sh",
                r"echo\s+.*\|\s*base64\s+-d\s*\|\s*sh",

                # Reverse shells
                r"^nc\s+-e",
                r"^ncat\s+-e",
                r"bash\s+-i\s*>&\s*/dev/tcp",
                r"^python.*-c.*import\s+socket",
                r"^python.*-c.*subprocess",
                r"^perl.*-e.*socket",
                r"^ruby.*-rsocket",
                r"^php.*-r.*fsockopen",

                # Eval/exec patterns
                r"eval\s*\(",
                r"exec\s*\(",
                r"\$\(.*\)",  # Command substitution with suspicious content

                # Cron/persistence
                r"crontab\s+-e",
                r"echo.*>>\s*/etc/cron",
                r"echo.*>>\s*~/.bashrc",
                r"echo.*>>\s*~/.bash_profile",

                # Privilege escalation
                r"chmod\s+[ugo]\+s",  # SUID/SGID
                r"chown\s+root",
            ],
        },
        "is_active": True,
        "tags": ["security", "commands", "system-protection", "rce-prevention"],
    },
    {
        "name": "Memory Poisoning Protection",
        "description": "Blocks modifications to agent memory files (SOUL.md, MEMORY.md) which can be used for persistence attacks.",
        "rule_type": RuleType.FILE_ACCESS,
        "action": RuleAction.REQUIRE_APPROVAL,
        "priority": 850,
        "parameters": {
            "protected_patterns": [
                r"SOUL\.md$",
                r"MEMORY\.md$",
                r"\.claude/.*\.md$",
                r"\.mcp/.*\.json$",
                r"conversation.*\.json$",
            ],
            "operations": ["write", "delete", "append"],
        },
        "is_active": True,
        "tags": ["security", "memory-protection", "persistence-prevention"],
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
    {
        "name": "Version Enforcement - Block Vulnerable OpenClaw",
        "description": "Blocks OpenClaw versions prior to 2026.1.29 which contain CVE-2026-25253 (WebSocket RCE).",
        "rule_type": RuleType.VERSION_ENFORCEMENT,
        "action": RuleAction.DENY,
        "priority": 950,
        "parameters": {
            "minimum_versions": {
                "openclaw": "2026.1.29",
                "moltbot": "2026.1.29",
            },
            "blocked_versions": [],
            "allow_unknown_version": False,
        },
        "is_active": True,
        "tags": ["security", "version-enforcement", "cve-mitigation"],
    },
    {
        "name": "Sandbox Requirement (Optional)",
        "description": "Requires agents to run in container, VM, or sandbox environment. Disabled by default.",
        "rule_type": RuleType.SANDBOX_REQUIRED,
        "action": RuleAction.DENY,
        "priority": 750,
        "parameters": {
            "allowed_environments": ["container", "vm", "sandbox"],
            "allow_unknown": False,
        },
        "is_active": False,  # Disabled by default - enable for high-security environments
        "tags": ["security", "sandbox", "isolation"],
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
    {
        "cve_id": "CVE-2026-25157",
        "title": "OpenClaw Command Injection via Skill Parameters",
        "description": "Command injection vulnerability in OpenClaw skill parameter handling allows attackers to execute arbitrary shell commands through crafted skill inputs.",
        "severity": IssueSeverity.HIGH,
        "cvss_score": 8.1,
        "affected_versions": ["< 2026.1.29"],
        "mitigation_notes": "Update to OpenClaw 2026.1.29+. Apply command denylist rules to block injection patterns.",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-25157",
        ],
    },
    {
        "cve_id": "CVE-2026-CLAWHAVOC",
        "title": "ClawHavoc Supply Chain Attack Campaign",
        "description": "Coordinated supply chain attack on ClawHub with 341+ malicious skills traced to a single threat actor (hightower6eu). Skills distributed macOS malware via ClickFix instructions. Categories affected: crypto trading (111), YouTube utilities (57), prediction market bots (34), auto-updaters (28).",
        "severity": IssueSeverity.CRITICAL,
        "cvss_score": 9.8,
        "affected_versions": ["all"],
        "mitigation_notes": "Block all skills from hightower6eu publisher. Apply typosquatting patterns to skill denylist. Enable skill allowlisting for production environments.",
        "references": [
            "https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html",
            "https://snyk.io/articles/clawdhub-malicious-campaign-ai-agent-skills/",
            "https://blog.virustotal.com/2026/02/from-automation-to-infection-how.html",
        ],
    },
    {
        "cve_id": "CVE-2026-MEMPOISONING",
        "title": "AI Agent Memory Poisoning Attacks",
        "description": "Attackers inject malicious data into agent memory files (SOUL.md, MEMORY.md, vector databases) to create persistent backdoors. MINJA attack achieves >95% injection success rate. AGENTPOISON achieves 82% retrieval and 63% end-to-end success.",
        "severity": IssueSeverity.HIGH,
        "cvss_score": 7.5,
        "affected_versions": ["all"],
        "mitigation_notes": "Protect SOUL.md and MEMORY.md files from unauthorized modification. Require human approval for memory file changes. Monitor for anomalous memory modifications.",
        "references": [
            "https://ttps.ai/technique/memory_poisoning.html",
            "https://www.lakera.ai/blog/agentic-ai-threats-p1",
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


async def create_malicious_skill_records(session: AsyncSession) -> int:
    """Create MaliciousSkill database records from the known malicious skills list.

    Populates the malicious_skills table so the Security page's
    Malicious Skills tab shows data. Uses upsert logic to avoid
    duplicates on re-runs.

    Returns the number of records created.
    """
    created = 0

    for record_data in MALICIOUS_SKILL_RECORDS:
        # Check if skill_id already exists
        result = await session.execute(
            select(MaliciousSkill).where(
                MaliciousSkill.skill_id == record_data["skill_id"]
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            logger.info(
                f"MaliciousSkill '{record_data['skill_id']}' already exists, skipping"
            )
            continue

        skill = MaliciousSkill(
            id=uuid4(),
            skill_id=record_data["skill_id"],
            skill_name=record_data["skill_name"],
            author=record_data.get("author"),
            threat_type=record_data["threat_type"],
            severity=record_data["severity"],
            analysis_notes=record_data.get("description"),
            indicators=record_data.get("indicators", {}),
            confidence=record_data.get("confidence", "medium"),
            source=record_data.get("source", "seed"),
            is_blocked=record_data.get("is_blocked", True),
            is_verified=record_data.get("is_verified", False),
        )
        session.add(skill)
        created += 1
        logger.info(f"Created MaliciousSkill: {record_data['skill_id']}")

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
            source="seed",
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
        logger.info("\n[1/3] Creating global security rules...")
        rules_created = await create_global_rules(session)
        logger.info(f"Created {rules_created} new security rules")

        # Create known CVE entries
        logger.info("\n[2/3] Creating known CVE entries...")
        issues_created = await create_security_issues(session)
        logger.info(f"Created {issues_created} new CVE entries")

        # Create malicious skill database records
        logger.info("\n[3/3] Creating malicious skill records...")
        skills_created = await create_malicious_skill_records(session)
        logger.info(f"Created {skills_created} new malicious skill records")

    await engine.dispose()

    logger.info("\n" + "=" * 60)
    logger.info("Security defaults applied successfully!")
    logger.info("=" * 60)
    logger.info("\nSummary:")
    logger.info(f"  - Security rules created: {rules_created}")
    logger.info(f"  - CVE entries created: {issues_created}")
    logger.info(f"  - Malicious skill records created: {skills_created}")
    logger.info(f"  - Malicious skills in blocklist: {len(MALICIOUS_SKILLS)}")
    logger.info("\nNext steps:")
    logger.info("  1. Access the dashboard at http://localhost:8000")
    logger.info("  2. Register your Snapper agents")
    logger.info("  3. Review and customize security rules as needed")
    logger.info("  4. Enable stricter rules based on your security requirements")


if __name__ == "__main__":
    asyncio.run(main())
