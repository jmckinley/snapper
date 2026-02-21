"""Tests for MCP server security classifier (tiers 1+2)."""

import pytest

from app.services.server_classifier import (
    SECURITY_CATEGORIES,
    classify_server,
    classify_server_with_method,
    batch_classify,
    _classify_by_name,
    _classify_by_description,
)


class TestTier1NamePatternMatching:
    """Test name-based classification (tier 1)."""

    @pytest.mark.parametrize("name,expected", [
        # data_store
        ("postgres-mcp", "data_store"),
        ("my-mysql-server", "data_store"),
        ("sqlite-reader", "data_store"),
        ("mongodb-mcp", "data_store"),
        ("redis-cache", "data_store"),
        ("supabase-db", "data_store"),
        ("qdrant-vector", "data_store"),
        ("pinecone-mcp", "data_store"),
        ("elasticsearch-tools", "data_store"),
        ("neo4j-graph", "data_store"),
        ("snowflake-warehouse", "data_store"),
        ("bigquery-analytics", "data_store"),
        ("duckdb-local", "data_store"),
        # code_repository
        ("github-mcp", "code_repository"),
        ("gitlab-server", "code_repository"),
        ("bitbucket-tools", "code_repository"),
        ("sourcegraph-search", "code_repository"),
        ("linear-project", "code_repository"),
        ("jira-tickets", "code_repository"),
        # filesystem
        ("filesystem-mcp", "filesystem"),
        ("s3-bucket-access", "filesystem"),
        ("google-drive-mcp", "filesystem"),
        ("dropbox-sync", "filesystem"),
        # shell_exec
        ("shell-executor", "shell_exec"),
        ("bash-runner", "shell_exec"),
        ("ssh-connect", "shell_exec"),
        ("terminal-access", "shell_exec"),
        # browser_automation
        ("puppeteer-browser", "browser_automation"),
        ("playwright-mcp", "browser_automation"),
        ("selenium-test", "browser_automation"),
        ("browserbase-cloud", "browser_automation"),
        # network_http
        ("brave-search-api", "network_http"),
        ("tavily-search", "network_http"),
        ("firecrawl-scraper", "network_http"),
        ("exa-search", "network_http"),
        # communication
        ("slack-bot", "communication"),
        ("discord-server", "communication"),
        ("telegram-notifier", "communication"),
        ("gmail-reader", "communication"),
        ("sendgrid-email", "communication"),
        ("hubspot-crm", "communication"),
        # cloud_infra
        ("aws-tools", "cloud_infra"),
        ("docker-manager", "cloud_infra"),
        ("kubernetes-deploy", "cloud_infra"),
        ("terraform-plan", "cloud_infra"),
        ("cloudflare-dns", "cloud_infra"),
        ("vercel-deploy", "cloud_infra"),
        # identity_auth
        ("auth0-mcp", "identity_auth"),
        ("okta-sso", "identity_auth"),
        ("keycloak-idp", "identity_auth"),
        ("cognito-auth", "identity_auth"),
        # payment_finance
        ("stripe-payments", "payment_finance"),
        ("paypal-checkout", "payment_finance"),
        ("plaid-banking", "payment_finance"),
        ("quickbooks-mcp", "payment_finance"),
        # ai_model
        ("openai-gpt", "ai_model"),
        ("anthropic-claude", "ai_model"),
        ("huggingface-models", "ai_model"),
        ("ollama-local", "ai_model"),
        ("groq-inference", "ai_model"),
        ("langchain-tools", "ai_model"),
        # monitoring
        ("sentry-errors", "monitoring"),
        ("datadog-metrics", "monitoring"),
        ("grafana-dashboards", "monitoring"),
        ("prometheus-exporter", "monitoring"),
        ("pagerduty-alerts", "monitoring"),
    ])
    def test_name_classification(self, name, expected):
        result = classify_server(name)
        assert result == expected, f"{name} classified as {result}, expected {expected}"

    def test_unknown_name_returns_general(self):
        assert classify_server("my-custom-tool") == "general"
        assert classify_server("foobar-service") == "general"

    def test_empty_name_returns_general(self):
        assert classify_server("") == "general"

    def test_case_insensitive(self):
        assert classify_server("PostgreSQL-MCP") == "data_store"
        assert classify_server("GITHUB-Tools") == "code_repository"
        assert classify_server("AWS-Lambda") == "cloud_infra"


class TestTier2DescriptionKeywords:
    """Test description-based classification (tier 2)."""

    def test_database_description(self):
        desc = "A SQL query engine for managing database tables and running migrations"
        result = _classify_by_description(desc)
        assert result == "data_store"

    def test_messaging_description(self):
        desc = "Send messages to channels and manage direct message conversations on your messaging platform"
        result = _classify_by_description(desc)
        assert result == "communication"

    def test_cloud_description(self):
        desc = "Deploy containers and manage cloud infrastructure with serverless function support"
        result = _classify_by_description(desc)
        assert result == "cloud_infra"

    def test_payment_description(self):
        desc = "Payment processing gateway for subscription management and invoice generation"
        result = _classify_by_description(desc)
        assert result == "payment_finance"

    def test_monitoring_description(self):
        desc = "Log aggregation and metrics collection with error tracking and distributed tracing"
        result = _classify_by_description(desc)
        assert result == "monitoring"

    def test_vague_description_returns_none(self):
        desc = "A useful tool for various tasks"
        result = _classify_by_description(desc)
        assert result is None

    def test_short_description_returns_none(self):
        result = _classify_by_description("hi")
        assert result is None

    def test_empty_description_returns_none(self):
        result = _classify_by_description("")
        assert result is None

    def test_none_description_returns_none(self):
        result = _classify_by_description(None)
        assert result is None


class TestClassifyServerCombined:
    """Test the combined classify_server function."""

    def test_name_takes_priority(self):
        # Even if description mentions monitoring, name pattern wins
        result = classify_server("postgres-mcp", "A monitoring tool for databases")
        assert result == "data_store"

    def test_falls_through_to_description(self):
        # Unknown name, but description matches
        result = classify_server(
            "my-data-tool",
            "A SQL query engine for database tables and managing schema migrations"
        )
        assert result == "data_store"

    def test_both_unknown_returns_general(self):
        result = classify_server("my-random-tool", "Does something interesting")
        assert result == "general"


class TestClassifyServerWithMethod:
    """Test classification with method tracking."""

    def test_name_pattern_method(self):
        cat, method = classify_server_with_method("github-tools")
        assert cat == "code_repository"
        assert method == "name_pattern"

    def test_description_method(self):
        cat, method = classify_server_with_method(
            "my-tool",
            "A SQL query engine for database tables and schema"
        )
        assert cat == "data_store"
        assert method == "description_keywords"

    def test_default_method(self):
        cat, method = classify_server_with_method("random-thing")
        assert cat == "general"
        assert method == "default"


class TestBatchClassify:
    """Test batch classification."""

    def test_batch_classification(self):
        servers = [
            ("postgres-mcp", "Database server"),
            ("github-tools", None),
            ("random-tool", "Does stuff"),
        ]
        results = batch_classify(servers)
        assert len(results) == 3
        assert results[0] == ("data_store", "name_pattern")
        assert results[1] == ("code_repository", "name_pattern")
        assert results[2] == ("general", "default")

    def test_empty_batch(self):
        results = batch_classify([])
        assert results == []


class TestSecurityCategories:
    """Test category definitions."""

    def test_all_13_categories_defined(self):
        assert len(SECURITY_CATEGORIES) == 13

    def test_general_category_exists(self):
        assert "general" in SECURITY_CATEGORIES

    def test_all_categories_have_descriptions(self):
        for cat, desc in SECURITY_CATEGORIES.items():
            assert desc, f"Category {cat} has no description"
