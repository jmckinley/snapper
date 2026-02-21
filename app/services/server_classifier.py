"""Server security classifier — assigns security categories to MCP servers.

Three-tier hybrid classification:
  Tier 1: Name pattern matching (high confidence, <1ms)
  Tier 2: Description keyword scoring (medium confidence, <1ms)
  Tier 3: BGE embedding similarity (high accuracy, ~5ms/server) — see bge_classifier.py

Tiers 1+2 run synchronously during catalog sync. Tier 3 runs as a Celery
background task for servers still classified as 'general'.
"""

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Security Categories (13)
# ---------------------------------------------------------------------------
SECURITY_CATEGORIES = {
    "data_store": "Strict — deny bulk export, deny drop/truncate, approve writes",
    "code_repository": "Moderate — allow reads, approve commits/merges, deny force-push/delete-branch",
    "filesystem": "Strict — allow reads, approve writes, deny deletion, block sensitive paths",
    "shell_exec": "Very strict — allowlist safe reads, deny rm/sudo/pipes",
    "browser_automation": "Strict — allow navigate/screenshot, approve form fills, PII gate",
    "network_http": "Moderate — allow GET/search, approve POST, deny internal IPs",
    "communication": "Moderate — allow reads, approve sends, deny admin/delete",
    "cloud_infra": "Strict — allow describe/list, approve create, deny terminate/delete",
    "identity_auth": "Very strict — deny most, approve reads only",
    "payment_finance": "Maximum — require approval for ALL, deny refunds/reversals",
    "ai_model": "Moderate — allow queries, approve training, deny model deletion",
    "monitoring": "Low — allow reads, approve config changes, deny data deletion",
    "general": "Default — allow reads, approve writes, deny destructive (fallback)",
}

# ---------------------------------------------------------------------------
# Tier 1: Name pattern matching
# ---------------------------------------------------------------------------
CATEGORY_NAME_PATTERNS: dict[str, re.Pattern] = {
    "data_store": re.compile(
        r"postgres|mysql|sqlite|mongo|redis|supabase|dynamo|firestore|qdrant|pinecone|"
        r"weaviate|chroma|milvus|turso|neon|cockroach|mariadb|cassandra|couchdb|"
        r"drizzle|prisma|knex|sequelize|typeorm|airtable|fauna|planetscale|"
        r"elastic(?:search)?|opensearch|clickhouse|timescale|influx|neo4j|dgraph|"
        r"surrealdb|duckdb|snowflake|bigquery|databricks|lake(?:house|formation)",
        re.I,
    ),
    "code_repository": re.compile(
        r"github|gitlab|bitbucket|gitea|sourcegraph|gitpod|codeberg|azure[-_]?devops|"
        r"codecommit|gitkraken|linear|jira|shortcut|asana(?:[-_]project)?",
        re.I,
    ),
    "filesystem": re.compile(
        r"filesystem|fs[-_]access|local[-_]files|file[-_]manager|file[-_]system|"
        r"s3[-_]?bucket|minio|google[-_]?drive|gdrive|onedrive|dropbox|box[-_]?api",
        re.I,
    ),
    "shell_exec": re.compile(
        r"\bshell\b|\bbash\b|terminal|command[-_]line|\bssh\b|\bexec\b|"
        r"powershell|zsh|subprocess|run[-_]?command",
        re.I,
    ),
    "browser_automation": re.compile(
        r"puppeteer|playwright|selenium|browser(?:base|less)|cypress|webdriver|"
        r"crawl(?:ee|er|4ai)|scraping|screen[-_]?shot|headless",
        re.I,
    ),
    "network_http": re.compile(
        r"\bfetch\b|brave[-_]search|\bexa\b|tavily|firecrawl|serp|"
        r"\bcurl\b|http[-_]?client|web[-_]?search|bing[-_]?search|"
        r"google[-_]?search|duckduckgo|searx|perplexity|"
        r"scrape|proxy|webhook|rest[-_]?api",
        re.I,
    ),
    "communication": re.compile(
        r"slack|discord|telegram|gmail|email|twilio|notion|teams|"
        r"whatsapp|sendgrid|mailgun|postmark|resend|intercom|"
        r"hubspot|zendesk|freshdesk|crisp|drift",
        re.I,
    ),
    "cloud_infra": re.compile(
        r"\baws\b|\bgcp\b|azure|docker|kubernetes|cloudflare|terraform|vercel|"
        r"netlify|heroku|railway|fly\.io|render|pulumi|ansible|"
        r"vagrant|helm|istio|consul|vault(?:[-_]hashi)?|"
        r"digitalocean|linode|vultr|hetzner|lambda|fargate|ecs\b|eks\b",
        re.I,
    ),
    "identity_auth": re.compile(
        r"oauth|auth0|okta|keycloak|\biam\b|\bsso\b|cognito|firebase[-_]?auth|"
        r"ldap|active[-_]?directory|saml|clerk|supertokens|lucia|"
        r"passport(?:js)?|nextauth|authelia",
        re.I,
    ),
    "payment_finance": re.compile(
        r"stripe|paypal|plaid|braintree|coinbase|billing|"
        r"square|adyen|mollie|razorpay|paddle|lemonsqueezy|"
        r"wise|mercury|quickbooks|xero|invoice",
        re.I,
    ),
    "ai_model": re.compile(
        r"openai|anthropic|huggingface|ollama|replicate|together[-_]ai|groq|"
        r"mistral|cohere|anyscale|fireworks[-_]?ai|deepseek|"
        r"llamafile|vllm|text[-_]?generation|embedding|langchain|"
        r"llama(?:index)?|autogen|crewai|dspy",
        re.I,
    ),
    "monitoring": re.compile(
        r"sentry|datadog|grafana|prometheus|pagerduty|newrelic|splunk|"
        r"logstash|kibana|fluentd|loki|jaeger|zipkin|tempo|"
        r"uptime[-_]?robot|statuspage|opsgenie|victorops|honeycomb",
        re.I,
    ),
}

# ---------------------------------------------------------------------------
# Tier 2: Description keyword scoring
# ---------------------------------------------------------------------------

# High-confidence keywords (3 points each)
_HIGH_KEYWORDS: dict[str, list[str]] = {
    "data_store": [
        "database", "sql query", "table schema", "data warehouse",
        "vector store", "key-value", "document store", "graph database",
        "olap", "oltp", "data lake",
    ],
    "code_repository": [
        "pull request", "merge request", "git repository", "code review",
        "commit history", "branch management", "issue tracker", "ci/cd pipeline",
    ],
    "filesystem": [
        "file operations", "directory listing", "read files", "write files",
        "file management", "file upload", "file download", "storage bucket",
    ],
    "shell_exec": [
        "execute command", "run shell", "command execution", "terminal access",
        "subprocess", "system command", "shell script",
    ],
    "browser_automation": [
        "browser automation", "web scraping", "page screenshot", "dom manipulation",
        "headless browser", "web crawling", "form automation",
    ],
    "network_http": [
        "http request", "web search", "api call", "rest endpoint",
        "search engine", "web fetch", "url fetch",
    ],
    "communication": [
        "send message", "chat message", "email send", "notification",
        "messaging platform", "channel management", "direct message",
    ],
    "cloud_infra": [
        "cloud deployment", "container orchestration", "infrastructure as code",
        "serverless function", "cloud resource", "virtual machine",
        "auto-scaling", "load balancer",
    ],
    "identity_auth": [
        "authentication", "authorization", "identity provider", "access token",
        "user session", "single sign-on", "multi-factor",
    ],
    "payment_finance": [
        "payment processing", "financial transaction", "billing system",
        "subscription management", "invoice generation", "payment gateway",
    ],
    "ai_model": [
        "language model", "ai inference", "model training", "text generation",
        "embedding generation", "prompt engineering", "model fine-tuning",
    ],
    "monitoring": [
        "log aggregation", "metrics collection", "error tracking",
        "performance monitoring", "alerting system", "observability",
        "distributed tracing",
    ],
}

# Medium-confidence keywords (1 point each)
_MEDIUM_KEYWORDS: dict[str, list[str]] = {
    "data_store": [
        "query", "schema", "migration", "index", "collection",
        "record", "row", "column", "crud", "orm",
    ],
    "code_repository": [
        "repository", "branch", "merge", "commit", "diff",
        "release", "tag", "fork", "clone",
    ],
    "filesystem": [
        "file", "directory", "folder", "path", "storage",
        "upload", "download", "rename",
    ],
    "shell_exec": [
        "command", "process", "script", "executable", "pipe",
    ],
    "browser_automation": [
        "browser", "page", "navigate", "click", "screenshot",
        "dom", "element", "crawl",
    ],
    "network_http": [
        "fetch", "request", "response", "url", "endpoint",
        "search", "scrape",
    ],
    "communication": [
        "message", "channel", "chat", "email", "inbox",
        "thread", "reply", "conversation",
    ],
    "cloud_infra": [
        "deploy", "container", "cluster", "instance", "region",
        "service", "resource", "infrastructure",
    ],
    "identity_auth": [
        "token", "credential", "permission", "role", "session",
        "login", "user",
    ],
    "payment_finance": [
        "payment", "charge", "refund", "subscription", "plan",
        "invoice", "customer", "price",
    ],
    "ai_model": [
        "model", "inference", "prompt", "completion", "embedding",
        "token", "generate",
    ],
    "monitoring": [
        "log", "metric", "alert", "trace", "dashboard",
        "error", "incident",
    ],
}

# Minimum score to classify via description (avoids false positives)
_MIN_DESCRIPTION_SCORE = 3


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify_server(name: str, description: Optional[str] = None) -> str:
    """Classify an MCP server into a security category (tiers 1+2).

    Fast synchronous path (<1ms). Returns a category string.
    Falls back to 'general' if no confident match.
    """
    if not name:
        return "general"

    # Tier 1: Name pattern matching
    category = _classify_by_name(name)
    if category:
        return category

    # Tier 2: Description keyword scoring
    if description:
        category = _classify_by_description(description)
        if category:
            return category

    return "general"


def classify_server_with_method(
    name: str, description: Optional[str] = None
) -> tuple[str, str]:
    """Like classify_server but also returns the classification method.

    Returns (category, method) where method is 'name_pattern',
    'description_keywords', or 'default'.
    """
    if not name:
        return "general", "default"

    category = _classify_by_name(name)
    if category:
        return category, "name_pattern"

    if description:
        category = _classify_by_description(description)
        if category:
            return category, "description_keywords"

    return "general", "default"


def batch_classify(
    servers: list[tuple[str, Optional[str]]],
) -> list[tuple[str, str]]:
    """Classify a batch of servers. Returns list of (category, method) tuples."""
    return [classify_server_with_method(name, desc) for name, desc in servers]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _classify_by_name(name: str) -> Optional[str]:
    """Tier 1: match server name against category patterns."""
    for category, pattern in CATEGORY_NAME_PATTERNS.items():
        if pattern.search(name):
            return category
    return None


def _classify_by_description(description: str) -> Optional[str]:
    """Tier 2: score description against keyword lists."""
    if not description or len(description) < 10:
        return None

    desc_lower = description.lower()
    scores: dict[str, int] = {}

    # Score high-confidence keywords (3 points each)
    for category, keywords in _HIGH_KEYWORDS.items():
        for kw in keywords:
            if kw in desc_lower:
                scores[category] = scores.get(category, 0) + 3

    # Score medium-confidence keywords (1 point each)
    for category, keywords in _MEDIUM_KEYWORDS.items():
        for kw in keywords:
            if kw in desc_lower:
                scores[category] = scores.get(category, 0) + 1

    if not scores:
        return None

    # Find best category above threshold
    best_category = max(scores, key=scores.get)  # type: ignore[arg-type]
    best_score = scores[best_category]

    if best_score < _MIN_DESCRIPTION_SCORE:
        return None

    # Require some margin over second-best to avoid ambiguous classifications
    sorted_scores = sorted(scores.values(), reverse=True)
    if len(sorted_scores) > 1 and sorted_scores[0] - sorted_scores[1] < 2:
        # Too close to call — only classify if score is strong enough
        if best_score < 5:
            return None

    return best_category
