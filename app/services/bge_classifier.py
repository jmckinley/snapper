"""BGE embedding classifier — Tier 3 classification for MCP servers.

Uses BAAI/bge-small-en-v1.5 (~130MB, runs on CPU) to classify servers
that Tiers 1+2 couldn't confidently categorize. Computes cosine similarity
between server text and pre-defined category anchor descriptions.

Model is lazily loaded on first call and cached in module-level variable.
"""

import logging
from typing import Any, Optional

try:
    import numpy as np
    _HAS_NUMPY = True
except ImportError:
    np = None  # type: ignore[assignment]
    _HAS_NUMPY = False

logger = logging.getLogger(__name__)

# Module-level model cache
_model = None
_reference_embeddings: Optional[dict[str, Any]] = None

# Confidence thresholds
_MIN_SIMILARITY = 0.5       # Top match must exceed this
_MIN_MARGIN = 0.1           # Must beat runner-up by this much

# Anchor descriptions per category — used to build reference embeddings
CATEGORY_ANCHORS: dict[str, list[str]] = {
    "data_store": [
        "database management system for storing and querying structured data",
        "SQL query engine for relational databases",
        "key-value storage and caching system",
        "vector database for semantic search and embeddings",
        "document store for NoSQL data management",
    ],
    "code_repository": [
        "source code repository for version control and collaboration",
        "git hosting platform for pull requests and code review",
        "project management and issue tracking for software development",
        "continuous integration and deployment pipeline",
    ],
    "filesystem": [
        "local filesystem access for reading and writing files",
        "file manager for directory operations and file manipulation",
        "cloud storage bucket for file uploads and downloads",
        "file system operations including create, read, update, delete",
    ],
    "shell_exec": [
        "command line shell for executing system commands",
        "terminal access for running bash scripts and programs",
        "remote SSH connection for server management",
        "subprocess execution for automation tasks",
    ],
    "browser_automation": [
        "browser automation for web scraping and testing",
        "headless browser for capturing screenshots and DOM interaction",
        "web crawler for extracting data from websites",
        "automated form filling and page navigation",
    ],
    "network_http": [
        "HTTP client for making web requests and API calls",
        "web search engine for finding information online",
        "URL fetching and content extraction from web pages",
        "REST API proxy for external service integration",
    ],
    "communication": [
        "messaging platform for sending and receiving chat messages",
        "email service for sending notifications and managing inbox",
        "team collaboration tool for channels and threads",
        "SMS and voice communication service",
    ],
    "cloud_infra": [
        "cloud infrastructure management for deploying and scaling services",
        "container orchestration with Docker and Kubernetes",
        "infrastructure as code for provisioning cloud resources",
        "serverless function deployment and management",
    ],
    "identity_auth": [
        "authentication and authorization service for user identity",
        "OAuth and SSO provider for secure login",
        "identity and access management for permissions and roles",
        "credential management and token generation",
    ],
    "payment_finance": [
        "payment processing gateway for handling financial transactions",
        "subscription billing and invoice management",
        "financial data aggregation and banking API",
        "e-commerce checkout and payment integration",
    ],
    "ai_model": [
        "large language model API for text generation and chat",
        "AI inference service for running machine learning models",
        "embedding generation for semantic search and retrieval",
        "model training and fine-tuning platform",
    ],
    "monitoring": [
        "application monitoring and error tracking service",
        "log aggregation and metrics collection platform",
        "alerting and incident management system",
        "distributed tracing and performance observability",
    ],
}


def _load_model():
    """Lazily load the BGE model and compute reference embeddings."""
    global _model, _reference_embeddings

    if _model is not None:
        return

    if not _HAS_NUMPY:
        logger.warning("numpy not installed — BGE classifier unavailable")
        _model = False
        return

    try:
        from sentence_transformers import SentenceTransformer

        logger.info("Loading BGE model (bge-small-en-v1.5)...")
        _model = SentenceTransformer("BAAI/bge-small-en-v1.5")
        logger.info("BGE model loaded successfully")

        # Pre-compute reference embeddings (mean of anchors per category)
        _reference_embeddings = {}
        for category, anchors in CATEGORY_ANCHORS.items():
            embeddings = _model.encode(anchors, normalize_embeddings=True)
            _reference_embeddings[category] = np.mean(embeddings, axis=0)
            # Re-normalize after averaging
            norm = np.linalg.norm(_reference_embeddings[category])
            if norm > 0:
                _reference_embeddings[category] /= norm

        logger.info(f"Reference embeddings computed for {len(_reference_embeddings)} categories")

    except ImportError:
        logger.warning(
            "sentence-transformers not installed — BGE classifier unavailable. "
            "Install with: pip install sentence-transformers"
        )
        _model = False  # Mark as failed so we don't retry
    except Exception as e:
        logger.error(f"Failed to load BGE model: {e}")
        _model = False


def is_available() -> bool:
    """Check if the BGE classifier is available (model loaded or loadable)."""
    if _model is None:
        _load_model()
    return _model is not None and _model is not False


def embed_and_classify(text: str) -> tuple[str, float]:
    """Classify a single text using BGE embeddings.

    Returns (category, confidence) where confidence is cosine similarity.
    Falls back to ('general', 0.0) if model unavailable.
    """
    if not is_available() or not text:
        return "general", 0.0

    try:
        embedding = _model.encode([text], normalize_embeddings=True)[0]

        # Compute cosine similarity against each category
        similarities = {}
        for category, ref_emb in _reference_embeddings.items():
            similarities[category] = float(np.dot(embedding, ref_emb))

        # Find best match
        sorted_cats = sorted(similarities.items(), key=lambda x: x[1], reverse=True)
        best_cat, best_sim = sorted_cats[0]
        runner_up_sim = sorted_cats[1][1] if len(sorted_cats) > 1 else 0.0

        # Apply confidence thresholds
        if best_sim < _MIN_SIMILARITY:
            return "general", best_sim

        if best_sim - runner_up_sim < _MIN_MARGIN:
            return "general", best_sim

        return best_cat, best_sim

    except Exception as e:
        logger.error(f"BGE classification failed: {e}")
        return "general", 0.0


def batch_embed_and_classify(
    texts: list[str],
) -> list[tuple[str, float]]:
    """Classify a batch of texts using BGE embeddings.

    More efficient than calling embed_and_classify() in a loop because
    it encodes all texts in a single batch.
    """
    if not is_available() or not texts:
        return [("general", 0.0)] * len(texts)

    try:
        embeddings = _model.encode(texts, normalize_embeddings=True, batch_size=64)

        results = []
        for embedding in embeddings:
            similarities = {}
            for category, ref_emb in _reference_embeddings.items():
                similarities[category] = float(np.dot(embedding, ref_emb))

            sorted_cats = sorted(similarities.items(), key=lambda x: x[1], reverse=True)
            best_cat, best_sim = sorted_cats[0]
            runner_up_sim = sorted_cats[1][1] if len(sorted_cats) > 1 else 0.0

            if best_sim < _MIN_SIMILARITY or best_sim - runner_up_sim < _MIN_MARGIN:
                results.append(("general", best_sim))
            else:
                results.append((best_cat, best_sim))

        return results

    except Exception as e:
        logger.error(f"BGE batch classification failed: {e}")
        return [("general", 0.0)] * len(texts)
