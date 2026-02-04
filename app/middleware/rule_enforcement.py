"""Rule enforcement middleware for API requests."""

import logging
from typing import Callable, Optional
from uuid import UUID

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.config import get_settings
from app.database import async_session_factory
from app.redis_client import redis_client
from app.services.rule_engine import (
    EvaluationContext,
    EvaluationDecision,
    RuleEngine,
)

logger = logging.getLogger(__name__)
settings = get_settings()


class RuleEnforcementMiddleware(BaseHTTPMiddleware):
    """
    Middleware for enforcing security rules on API requests.

    Builds evaluation context from requests and runs them through
    the rule engine. Returns appropriate responses for denied or
    pending-approval requests.
    """

    # Paths exempt from rule enforcement
    EXEMPT_PATHS = {
        "/health",
        "/health/ready",
        "/api/docs",
        "/api/redoc",
        "/api/openapi.json",
        "/",  # Dashboard
        "/wizard",  # Setup wizard
    }

    # Path prefixes exempt from enforcement
    EXEMPT_PREFIXES = [
        "/static/",
        "/api/v1/security/",  # Security endpoints need to work
        "/api/v1/audit/",  # Audit endpoints need to work
        "/api/v1/agents/",  # Agent management needs to work
        "/api/v1/rules/",  # Rule management needs to work
        "/api/v1/integrations/",  # Integration management needs to work
    ]

    async def dispatch(
        self, request: Request, call_next: Callable
    ) -> Response:
        """Process request through rule enforcement."""
        # Check if path is exempt
        if self._is_exempt_path(request.url.path):
            return await call_next(request)

        # Try to extract agent ID from request
        agent_id = self._extract_agent_id(request)

        # If no agent ID, allow request (internal requests)
        if not agent_id:
            return await call_next(request)

        # Build evaluation context
        context = self._build_context(request, agent_id)

        # Evaluate rules
        try:
            async with async_session_factory() as db:
                engine = RuleEngine(db, redis_client)
                result = await engine.evaluate(context)

            if result.decision == EvaluationDecision.DENY:
                logger.warning(
                    f"Request denied by rule engine: {result.reason}",
                    extra={
                        "agent_id": str(agent_id),
                        "request_id": context.request_id,
                        "path": request.url.path,
                        "blocking_rule": str(result.blocking_rule) if result.blocking_rule else None,
                    },
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "detail": result.reason,
                        "decision": result.decision.value,
                        "blocking_rule": str(result.blocking_rule) if result.blocking_rule else None,
                    },
                    headers={
                        "X-Request-ID": context.request_id or "",
                        "X-Rule-Decision": result.decision.value,
                    },
                )

            if result.decision == EvaluationDecision.REQUIRE_APPROVAL:
                logger.info(
                    f"Request requires approval: {result.reason}",
                    extra={
                        "agent_id": str(agent_id),
                        "request_id": context.request_id,
                        "path": request.url.path,
                    },
                )
                return JSONResponse(
                    status_code=202,
                    content={
                        "detail": result.reason,
                        "decision": result.decision.value,
                        "approval_required": True,
                        "blocking_rule": str(result.blocking_rule) if result.blocking_rule else None,
                    },
                    headers={
                        "X-Request-ID": context.request_id or "",
                        "X-Rule-Decision": result.decision.value,
                    },
                )

            # Add evaluation info to request state for logging
            request.state.rule_evaluation = result

        except Exception as e:
            logger.exception(f"Rule evaluation error: {e}")
            # Fail-safe: deny on error if configured
            if settings.DENY_BY_DEFAULT:
                return JSONResponse(
                    status_code=500,
                    content={
                        "detail": "Rule evaluation failed - request denied for safety",
                    },
                )

        # Request allowed, continue
        return await call_next(request)

    def _is_exempt_path(self, path: str) -> bool:
        """Check if path is exempt from rule enforcement."""
        # Exact match
        if path in self.EXEMPT_PATHS:
            return True

        # Prefix match
        for prefix in self.EXEMPT_PREFIXES:
            if path.startswith(prefix):
                return True

        return False

    def _extract_agent_id(self, request: Request) -> Optional[UUID]:
        """Extract agent ID from request."""
        # Try header first
        agent_id_str = request.headers.get("X-Agent-ID")
        if agent_id_str:
            try:
                return UUID(agent_id_str)
            except ValueError:
                pass

        # Try query parameter
        agent_id_str = request.query_params.get("agent_id")
        if agent_id_str:
            try:
                return UUID(agent_id_str)
            except ValueError:
                pass

        # Try path parameter (for /agents/{id}/... routes)
        path_parts = request.url.path.split("/")
        if "agents" in path_parts:
            try:
                idx = path_parts.index("agents")
                if idx + 1 < len(path_parts):
                    return UUID(path_parts[idx + 1])
            except (ValueError, IndexError):
                pass

        return None

    def _build_context(self, request: Request, agent_id: UUID) -> EvaluationContext:
        """Build evaluation context from request."""
        request_id = getattr(request.state, "request_id", None)

        # Determine request type based on path and method
        request_type = self._determine_request_type(request)

        context = EvaluationContext(
            agent_id=agent_id,
            request_type=request_type,
            origin=request.headers.get("origin"),
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            request_id=request_id,
            metadata={
                "method": request.method,
                "path": request.url.path,
                "query": str(request.query_params),
            },
        )

        # Extract additional context based on request type
        if request_type == "skill":
            # Try to extract skill ID from path or body
            path_parts = request.url.path.split("/")
            if "skills" in path_parts:
                try:
                    idx = path_parts.index("skills")
                    if idx + 1 < len(path_parts):
                        context.skill_id = path_parts[idx + 1]
                except (ValueError, IndexError):
                    pass

        return context

    def _determine_request_type(self, request: Request) -> str:
        """Determine the type of request for rule evaluation."""
        path = request.url.path.lower()

        if "/skills/" in path or "/clawhub/" in path:
            return "skill"
        if "/network/" in path or "/egress/" in path:
            return "network"
        if "/files/" in path or "/filesystem/" in path:
            return "file_access"
        if "/commands/" in path or "/execute/" in path:
            return "command"
        if "/credentials/" in path or "/secrets/" in path:
            return "credential"

        return "api"  # Generic API request
