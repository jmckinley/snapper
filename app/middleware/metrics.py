"""Prometheus metrics middleware for Snapper.

Exposes /metrics endpoint with application-level counters and histograms.
Uses the prometheus_client library directly (no heavy framework wrappers).
"""

import logging
import time
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)

try:
    from prometheus_client import (
        CollectorRegistry,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
    )

    REGISTRY = CollectorRegistry()

    # HTTP request metrics
    REQUEST_COUNT = Counter(
        "snapper_requests_total",
        "Total HTTP requests",
        ["method", "path", "status"],
        registry=REGISTRY,
    )
    REQUEST_LATENCY = Histogram(
        "snapper_request_duration_seconds",
        "HTTP request latency",
        ["method", "path"],
        buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
        registry=REGISTRY,
    )

    # Rule evaluation metrics
    RULE_EVALUATIONS = Counter(
        "snapper_rule_evaluations_total",
        "Total rule evaluations",
        ["rule_type", "decision"],
        registry=REGISTRY,
    )
    RULE_EVALUATION_LATENCY = Histogram(
        "snapper_rule_evaluation_duration_seconds",
        "Rule evaluation latency",
        buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5],
        registry=REGISTRY,
    )

    # PII Vault metrics
    PII_VAULT_OPS = Counter(
        "snapper_pii_vault_operations_total",
        "PII vault operations",
        ["operation"],  # create, read, delete, resolve
        registry=REGISTRY,
    )

    # Agent metrics
    ACTIVE_AGENTS = Gauge(
        "snapper_active_agents",
        "Number of active agents",
        registry=REGISTRY,
    )

    # Approval metrics
    APPROVAL_LATENCY = Histogram(
        "snapper_approval_latency_seconds",
        "Time from approval request to decision",
        buckets=[1, 5, 10, 30, 60, 120, 300, 600],
        registry=REGISTRY,
    )
    APPROVAL_DECISIONS = Counter(
        "snapper_approval_decisions_total",
        "Approval workflow decisions",
        ["decision"],  # approved, denied, timeout
        registry=REGISTRY,
    )

    # SIEM event metrics
    SIEM_EVENTS = Counter(
        "snapper_siem_events_total",
        "SIEM events published",
        ["output", "status"],  # syslog/webhook, success/failure
        registry=REGISTRY,
    )

    # Webhook delivery metrics
    WEBHOOK_DELIVERIES = Counter(
        "snapper_webhook_deliveries_total",
        "Webhook delivery attempts",
        ["status"],  # success, failure
        registry=REGISTRY,
    )

    PROMETHEUS_AVAILABLE = True

except ImportError:
    PROMETHEUS_AVAILABLE = False
    logger.info("prometheus_client not installed, metrics disabled")


def _normalize_path(path: str) -> str:
    """Normalize URL path for metric labels to avoid cardinality explosion.

    Groups UUID-like path segments into {id} placeholders.
    """
    import re

    # Replace UUID segments
    path = re.sub(
        r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "/{id}",
        path,
    )
    # Replace numeric IDs
    path = re.sub(r"/\d+(?=/|$)", "/{id}", path)
    return path


class MetricsMiddleware(BaseHTTPMiddleware):
    """Middleware that records Prometheus metrics for every request."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not PROMETHEUS_AVAILABLE:
            return await call_next(request)

        # Skip metrics endpoint itself
        if request.url.path == "/metrics":
            return await call_next(request)

        method = request.method
        path = _normalize_path(request.url.path)
        start = time.perf_counter()

        response = await call_next(request)

        elapsed = time.perf_counter() - start
        status = str(response.status_code)

        REQUEST_COUNT.labels(method=method, path=path, status=status).inc()
        REQUEST_LATENCY.labels(method=method, path=path).observe(elapsed)

        return response


def get_metrics_response() -> Response:
    """Generate Prometheus metrics response."""
    if not PROMETHEUS_AVAILABLE:
        from starlette.responses import PlainTextResponse

        return PlainTextResponse(
            "# prometheus_client not installed\n", status_code=501
        )

    from starlette.responses import Response as StarletteResponse

    body = generate_latest(REGISTRY)
    return StarletteResponse(
        content=body,
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


# --- Convenience functions for recording metrics from application code ---

def record_rule_evaluation(rule_type: str, decision: str, duration_ms: float) -> None:
    """Record a rule evaluation metric."""
    if not PROMETHEUS_AVAILABLE:
        return
    RULE_EVALUATIONS.labels(rule_type=rule_type, decision=decision).inc()
    RULE_EVALUATION_LATENCY.observe(duration_ms / 1000.0)


def record_pii_operation(operation: str) -> None:
    """Record a PII vault operation."""
    if not PROMETHEUS_AVAILABLE:
        return
    PII_VAULT_OPS.labels(operation=operation).inc()


def set_active_agents(count: int) -> None:
    """Set the active agent gauge."""
    if not PROMETHEUS_AVAILABLE:
        return
    ACTIVE_AGENTS.set(count)


def record_approval_decision(decision: str, latency_seconds: float = 0) -> None:
    """Record an approval decision with optional latency."""
    if not PROMETHEUS_AVAILABLE:
        return
    APPROVAL_DECISIONS.labels(decision=decision).inc()
    if latency_seconds > 0:
        APPROVAL_LATENCY.observe(latency_seconds)


def record_siem_event(output: str, success: bool) -> None:
    """Record a SIEM event publish attempt."""
    if not PROMETHEUS_AVAILABLE:
        return
    SIEM_EVENTS.labels(output=output, status="success" if success else "failure").inc()


def record_webhook_delivery(success: bool) -> None:
    """Record a webhook delivery attempt."""
    if not PROMETHEUS_AVAILABLE:
        return
    WEBHOOK_DELIVERIES.labels(status="success" if success else "failure").inc()
