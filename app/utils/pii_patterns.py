"""PII detection patterns for data redaction.

Supports US, UK, Canada, and Australia formats.
"""

# PII patterns organized by category and region
PII_PATTERNS = {
    # === Government IDs ===

    # US Social Security Number: 123-45-6789
    "us_ssn": r"\b\d{3}-\d{2}-\d{4}\b",

    # UK National Insurance Number: AB123456C
    "uk_nin": r"\b[A-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-Z]\b",

    # Canada Social Insurance Number: 123-456-789
    "ca_sin": r"\b\d{3}-\d{3}-\d{3}\b",

    # Australia Tax File Number: 123 456 789 (9 digits)
    "au_tfn": r"\b\d{3}\s?\d{3}\s?\d{3}\b",

    # UK NHS Number: 123 456 7890 (10 digits, 3-3-4)
    "uk_nhs": r"\b\d{3}\s\d{3}\s\d{4}\b",

    # Australia Medicare: 1234 56789 0 (10-11 digits)
    "au_medicare": r"\b\d{4}\s?\d{5}\s?\d{1,2}\b",

    # Passport numbers (generic alphanumeric, 6-9 chars)
    "passport": r"\b[A-Z]{1,2}\d{6,8}\b",

    # Driver's license (generic, state-specific patterns vary)
    "drivers_license": r"\b[A-Z]{1,2}\d{4,8}\b",

    # === Financial ===

    # Credit/Debit cards (Visa, MC, Amex, Discover)
    "credit_card": r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",

    # IBAN (International Bank Account Number)
    "iban": r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b",

    # US Bank routing number (9 digits)
    "us_routing": r"\b[0-9]{9}\b",

    # === Contact Info ===

    # Email addresses
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",

    # US/Canada phone: (123) 456-7890 or 123-456-7890 or 123.456.7890
    "phone_us_ca": r"\b(?:\+?1[- ]?)?(?:\([0-9]{3}\)|[0-9]{3})[- .]?[0-9]{3}[- .]?[0-9]{4}\b",

    # UK phone: +44 7xxx xxxxxx or 07xxx xxxxxx
    "phone_uk": r"\b(?:\+44\s?|0)(?:7\d{3}|\d{4})\s?\d{3}\s?\d{3}\b",

    # Australia phone: +61 4xx xxx xxx or 04xx xxx xxx
    "phone_au": r"\b(?:\+61\s?|0)4\d{2}\s?\d{3}\s?\d{3}\b",

    # === Addresses ===

    # Street address (number + street name + type)
    "street_address": r"\b\d+\s+[\w\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct|Place|Pl|Circle|Cir)\b",

    # US ZIP code: 12345 or 12345-6789
    "us_zip": r"\b\d{5}(?:-\d{4})?\b",

    # UK Postcode: SW1A 1AA
    "uk_postcode": r"\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b",

    # Canada Postal Code: A1A 1A1
    "ca_postal": r"\b[A-Z]\d[A-Z]\s?\d[A-Z]\d\b",

    # Australia Postcode: 4 digits
    "au_postcode": r"\b(?:0[289]\d{2}|[1-9]\d{3})\b",

    # === Dates (potential DOB) ===

    # Date formats: MM/DD/YYYY, DD/MM/YYYY, YYYY-MM-DD
    "date_mdy": r"\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2}\b",
    "date_dmy": r"\b(?:0[1-9]|[12]\d|3[01])[/-](?:0[1-9]|1[0-2])[/-](?:19|20)\d{2}\b",
    "date_iso": r"\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b",

    # === Network ===

    # IPv4 address
    "ipv4": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",

    # === API Keys & Secrets ===

    # OpenAI API key: sk-... (51+ chars) or sk-proj-... (variable)
    "api_key_openai": r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b",

    # Anthropic API key: sk-ant-... (40+ chars)
    "api_key_anthropic": r"\bsk-ant-[A-Za-z0-9_-]{20,}\b",

    # AWS Access Key ID: AKIA... (20 chars)
    "api_key_aws": r"\bAKIA[0-9A-Z]{16}\b",

    # AWS Secret Access Key (40 chars base64-ish, after known prefixes)
    "api_key_aws_secret": r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|SecretAccessKey)[\"'=:>\s]+[A-Za-z0-9/+=]{40}\b",

    # GitHub personal access token: ghp_, gho_, ghu_, ghs_, ghr_ (40+ chars)
    "api_key_github": r"\bg(?:hp|ho|hu|hs|hr)_[A-Za-z0-9_]{36,}\b",

    # Google API key
    "api_key_google": r"\bAIza[0-9A-Za-z_-]{35}\b",

    # Stripe API key: sk_live_ or sk_test_ or pk_live_ or pk_test_
    "api_key_stripe": r"\b[sp]k_(?:live|test)_[A-Za-z0-9]{24,}\b",

    # Slack Bot/User/Webhook tokens
    "api_key_slack": r"\bxox[bpras]-[A-Za-z0-9-]{10,}\b",

    # Twilio API key: SK... (32 hex)
    "api_key_twilio": r"\bSK[0-9a-fA-F]{32}\b",

    # SendGrid API key: SG. prefix
    "api_key_sendgrid": r"\bSG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{20,}\b",

    # Generic Bearer token in JSON/headers
    "bearer_token": r"(?:Bearer|bearer|Authorization|authorization)[\"':\s]+Bearer\s+[A-Za-z0-9._~+/=-]{20,}\b",

    # Generic high-entropy secret (key=... or token=... with 32+ hex/base64 chars)
    "generic_secret": r"(?:api_key|apikey|api_secret|secret_key|access_token|auth_token|private_key)[\"'=:>\s]+[A-Za-z0-9/+=_-]{32,}\b",

    # === Names (aggressive - may have false positives) ===

    # Full name with title: Mr. John Smith, Dr. Jane Doe
    "name_with_title": r"\b(?:Mr|Mrs|Ms|Miss|Dr|Prof|Sir|Dame)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b",
}

# API key pattern names for easy referencing
API_KEY_PATTERNS = {
    k: PII_PATTERNS[k] for k in PII_PATTERNS if k.startswith("api_key_")
}

# Shorter list for quick/default redaction (most reliable patterns)
PII_PATTERNS_DEFAULT = {
    "us_ssn": PII_PATTERNS["us_ssn"],
    "uk_nin": PII_PATTERNS["uk_nin"],
    "ca_sin": PII_PATTERNS["ca_sin"],
    "au_tfn": PII_PATTERNS["au_tfn"],
    "credit_card": PII_PATTERNS["credit_card"],
    "email": PII_PATTERNS["email"],
    "phone_us_ca": PII_PATTERNS["phone_us_ca"],
    "phone_uk": PII_PATTERNS["phone_uk"],
    "phone_au": PII_PATTERNS["phone_au"],
    # API keys — high-signal, low false-positive
    "api_key_openai": PII_PATTERNS["api_key_openai"],
    "api_key_anthropic": PII_PATTERNS["api_key_anthropic"],
    "api_key_aws": PII_PATTERNS["api_key_aws"],
    "api_key_github": PII_PATTERNS["api_key_github"],
    "api_key_google": PII_PATTERNS["api_key_google"],
    "api_key_stripe": PII_PATTERNS["api_key_stripe"],
    "api_key_slack": PII_PATTERNS["api_key_slack"],
    "generic_secret": PII_PATTERNS["generic_secret"],
}

# Full list for thorough redaction
PII_PATTERNS_FULL = PII_PATTERNS


def redact_pii(text: str, patterns: dict = None, replacement_format: str = "[REDACTED-{type}]") -> tuple[str, int]:
    """
    Redact PII from text using specified patterns.

    Args:
        text: The text to redact
        patterns: Dict of pattern_name -> regex. Defaults to PII_PATTERNS_DEFAULT
        replacement_format: Format string for replacement. {type} will be replaced with pattern name.

    Returns:
        Tuple of (redacted_text, count_of_redactions)
    """
    import re

    if patterns is None:
        patterns = PII_PATTERNS_DEFAULT

    redaction_count = 0
    result = text

    for pii_type, pattern in patterns.items():
        matches = re.findall(pattern, result, re.IGNORECASE)
        if matches:
            redaction_count += len(matches)
            replacement = replacement_format.format(type=pii_type.upper())
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)

    return result, redaction_count


def detect_pii(text: str, patterns: dict = None) -> list[dict]:
    """
    Detect PII in text without redacting.

    Args:
        text: The text to scan
        patterns: Dict of pattern_name -> regex. Defaults to PII_PATTERNS_DEFAULT

    Returns:
        List of dicts with 'type', 'match', 'start', 'end' for each PII found
    """
    import re

    if patterns is None:
        patterns = PII_PATTERNS_DEFAULT

    findings = []

    for pii_type, pattern in patterns.items():
        for match in re.finditer(pattern, text, re.IGNORECASE):
            findings.append({
                "type": pii_type,
                "match": match.group(),
                "start": match.start(),
                "end": match.end(),
            })

    return sorted(findings, key=lambda x: x["start"])
