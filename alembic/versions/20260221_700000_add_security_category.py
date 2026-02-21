"""Add security_category column to mcp_server_catalog.

Adds a String(30) column with server_default 'general' and an index.
Includes a data migration that classifies existing servers using
name pattern matching (tier 1).

Revision ID: 20260221_700000
Revises: 20260221_600000
Create Date: 2026-02-21
"""

from alembic import op
import sqlalchemy as sa

revision = "20260221_700000"
down_revision = "20260221_600000"
branch_labels = None
depends_on = None

# Simplified name patterns for PostgreSQL POSIX regex (~*).
# These are intentionally less precise than server_classifier.py's Python regex
# (no \b word boundaries, simplified alternation). The runtime classifier will
# refine classifications on the next catalog sync.
_CATEGORY_PATTERNS = {
    "data_store": (
        r"postgres|mysql|sqlite|mongo|redis|supabase|dynamo|firestore|qdrant|pinecone|"
        r"weaviate|chroma|milvus|turso|neon|cockroach|mariadb|cassandra|couchdb|"
        r"drizzle|prisma|knex|sequelize|typeorm|airtable|fauna|planetscale|"
        r"elastic|opensearch|clickhouse|timescale|influx|neo4j|dgraph|"
        r"surrealdb|duckdb|snowflake|bigquery|databricks|lake"
    ),
    "code_repository": (
        r"github|gitlab|bitbucket|gitea|sourcegraph|gitpod|codeberg|azure.devops|"
        r"codecommit|linear|jira|shortcut"
    ),
    "filesystem": (
        r"filesystem|fs.access|local.files|file.manager|file.system|"
        r"s3.bucket|minio|google.drive|gdrive|onedrive|dropbox|box.api"
    ),
    "shell_exec": r"shell|bash|terminal|command.line|ssh|powershell|zsh|subprocess",
    "browser_automation": (
        r"puppeteer|playwright|selenium|browserbase|browserless|cypress|webdriver|"
        r"crawl|scraping|screen.shot|headless"
    ),
    "network_http": (
        r"fetch|brave.search|exa|tavily|firecrawl|serp|curl|http.client|"
        r"web.search|bing.search|google.search|duckduckgo|searx|perplexity"
    ),
    "communication": (
        r"slack|discord|telegram|gmail|email|twilio|notion|teams|"
        r"whatsapp|sendgrid|mailgun|postmark|resend|intercom|hubspot|zendesk"
    ),
    "cloud_infra": (
        r"aws|gcp|azure|docker|kubernetes|cloudflare|terraform|vercel|"
        r"netlify|heroku|railway|render|pulumi|ansible|helm|"
        r"digitalocean|linode|vultr|hetzner|lambda|fargate"
    ),
    "identity_auth": (
        r"oauth|auth0|okta|keycloak|iam|sso|cognito|firebase.auth|"
        r"ldap|active.directory|saml|clerk|supertokens|nextauth"
    ),
    "payment_finance": (
        r"stripe|paypal|plaid|braintree|coinbase|billing|"
        r"square|adyen|mollie|razorpay|paddle|lemonsqueezy|quickbooks|xero"
    ),
    "ai_model": (
        r"openai|anthropic|huggingface|ollama|replicate|together.ai|groq|"
        r"mistral|cohere|fireworks.ai|deepseek|vllm|langchain|llama"
    ),
    "monitoring": (
        r"sentry|datadog|grafana|prometheus|pagerduty|newrelic|splunk|"
        r"logstash|kibana|fluentd|loki|jaeger|zipkin|honeycomb"
    ),
}


def upgrade() -> None:
    # Add the column with default
    op.add_column(
        "mcp_server_catalog",
        sa.Column(
            "security_category",
            sa.String(30),
            server_default="general",
            nullable=False,
        ),
    )

    # Create index
    op.create_index(
        "ix_mcp_catalog_security_category",
        "mcp_server_catalog",
        ["security_category"],
    )

    # Data migration: classify existing servers using SQL CASE WHEN
    # Build a big CASE expression from name patterns
    cases = []
    for category, pattern in _CATEGORY_PATTERNS.items():
        cases.append(
            f"WHEN lower(name) ~* '{pattern}' "
            f"OR lower(normalized_name) ~* '{pattern}' "
            f"THEN '{category}'"
        )

    case_sql = " ".join(cases)
    op.execute(
        f"UPDATE mcp_server_catalog SET security_category = "
        f"CASE {case_sql} ELSE 'general' END"
    )


def downgrade() -> None:
    op.drop_index("ix_mcp_catalog_security_category", table_name="mcp_server_catalog")
    op.drop_column("mcp_server_catalog", "security_category")
