"""Tests for BGE embedding classifier (tier 3).

These tests verify the BGE classifier interface and behavior.
The actual model loading is tested only if sentence-transformers is installed.
"""

import pytest

try:
    import numpy  # noqa
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

from app.services.bge_classifier import (
    CATEGORY_ANCHORS,
    embed_and_classify,
    batch_embed_and_classify,
    is_available,
)


class TestBGEClassifierInterface:
    """Test BGE classifier interface without requiring model."""

    def test_category_anchors_complete(self):
        """All 12 non-general categories should have anchors."""
        expected_categories = {
            "data_store", "code_repository", "filesystem", "shell_exec",
            "browser_automation", "network_http", "communication",
            "cloud_infra", "identity_auth", "payment_finance",
            "ai_model", "monitoring",
        }
        assert set(CATEGORY_ANCHORS.keys()) == expected_categories

    def test_each_category_has_anchors(self):
        for cat, anchors in CATEGORY_ANCHORS.items():
            assert len(anchors) >= 3, f"{cat} has fewer than 3 anchors"
            for anchor in anchors:
                assert len(anchor) > 10, f"{cat} has too-short anchor: {anchor}"

    def test_empty_text_returns_general(self):
        result, confidence = embed_and_classify("")
        assert result == "general"
        assert confidence == 0.0

    def test_batch_empty_returns_general(self):
        results = batch_embed_and_classify([])
        assert results == []


class TestBGEClassifierWithModel:
    """Tests that require the actual BGE model.

    Skipped if sentence-transformers is not installed.
    """

    @pytest.fixture(autouse=True)
    def check_model_available(self):
        try:
            import sentence_transformers  # noqa
        except ImportError:
            pytest.skip("sentence-transformers not installed")

        if not is_available():
            pytest.skip("BGE model not available")

    def test_database_classification(self):
        cat, conf = embed_and_classify(
            "postgres: A PostgreSQL database management tool for running SQL queries"
        )
        assert cat == "data_store"
        assert conf > 0.5

    def test_communication_classification(self):
        cat, conf = embed_and_classify(
            "slack-bot: Send and receive messages in Slack channels"
        )
        assert cat == "communication"
        assert conf > 0.5

    def test_batch_classification(self):
        texts = [
            "postgres: SQL database query engine",
            "github: Code repository and pull request management",
            "random-thing: Does miscellaneous stuff",
        ]
        results = batch_embed_and_classify(texts)
        assert len(results) == 3
        assert results[0][0] == "data_store"
        assert results[1][0] == "code_repository"
        # Third one might be general or something else
