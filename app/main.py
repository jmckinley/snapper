"""FastAPI application entry point with lifespan management.

@module main
@description Core application setup including routes, middleware, lifespan, and template rendering.
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import get_settings
from app.database import check_db_health, close_db, init_db
from app.redis_client import redis_client

# Import routers
from app.routers import agents, approvals, audit, integrations, rules, security, setup, slack, telegram, vault
from app.routers import auth as auth_router
from app.routers import organizations as org_router
from app.routers import billing as billing_router
from app.routers import saml as saml_router
from app.routers import oidc as oidc_router
from app.routers import scim as scim_router
from app.routers import webhooks as webhooks_router
from app.routers import approval_policies as approval_policies_router
from app.routers import suggestions as suggestions_router
from app.routers import threats as threats_router

settings = get_settings()

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager for startup and shutdown."""
    # Startup
    logger.info("Starting Snapper...")

    # Initialize Redis
    logger.info("Connecting to Redis...")
    await redis_client.connect()

    # Verify database connectivity (migrations handled by Alembic)
    logger.info("Verifying database connection...")
    await init_db()

    # Register Telegram bot commands for autocomplete menu
    if settings.TELEGRAM_BOT_TOKEN:
        logger.info("Registering Telegram bot commands...")
        from app.routers.telegram import register_bot_commands
        await register_bot_commands()

    # Start Slack bot (Socket Mode)
    if settings.SLACK_BOT_TOKEN and settings.SLACK_APP_TOKEN:
        logger.info("Starting Slack bot (Socket Mode)...")
        from app.routers.slack import start_slack_bot
        await start_slack_bot()

    # Set initial active agents gauge
    try:
        from app.middleware.metrics import set_active_agents
        from app.database import get_db_context
        from app.models.agents import Agent, AgentStatus
        from sqlalchemy import select, func
        async with get_db_context() as db:
            count_result = await db.execute(
                select(func.count(Agent.id)).where(Agent.deleted_at.is_(None), Agent.status == AgentStatus.ACTIVE)
            )
            set_active_agents(count_result.scalar() or 0)
        logger.info("Active agents gauge initialized")
    except Exception as e:
        logger.warning(f"Could not initialize active agents gauge: {e}")

    logger.info("Snapper started successfully")

    yield

    # Shutdown
    logger.info("Shutting down Snapper...")

    # Stop Slack bot
    if settings.SLACK_BOT_TOKEN and settings.SLACK_APP_TOKEN:
        from app.routers.slack import stop_slack_bot
        await stop_slack_bot()

    # Close Redis
    await redis_client.close()

    # Close database
    await close_db()

    logger.info("Snapper shut down successfully")


# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Security-focused rule management for AI agents",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
    openapi_tags=[
        # Public API tags (listed first)
        {"name": "Core", "description": "Evaluate requests and check approval status — the primary hook integration points."},
        {"name": "Agents", "description": "Agent lifecycle management: create, update, suspend, trust scoring."},
        {"name": "Rules", "description": "Policy-as-code: CRUD, import/export, validate, templates."},
        {"name": "Vault", "description": "PII vault: encrypted storage with tokenized references."},
        {"name": "Audit", "description": "Audit logs, stats, violations, and alerts."},
        {"name": "Webhooks", "description": "Webhook configuration for event notifications."},
        {"name": "Integrations", "description": "Traffic discovery, MCP server detection, and rule pack management."},
        # Internal tags
        {"name": "Auth", "description": "Internal: User authentication and session management."},
        {"name": "Organizations", "description": "Internal: Organization and team management."},
        {"name": "Billing", "description": "Internal: Subscription and usage billing."},
        {"name": "Telegram", "description": "Internal: Telegram bot webhook and commands."},
        {"name": "Slack", "description": "Internal: Slack bot Socket Mode integration."},
        {"name": "SSO", "description": "Internal: SAML, OIDC, and SCIM provisioning."},
        {"name": "Security Research", "description": "Internal: Security vulnerability research and threat feeds."},
        {"name": "Setup", "description": "Internal: First-run wizard and agent auto-discovery."},
    ],
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-API-Version", "X-RateLimit-Limit", "X-RateLimit-Remaining", "Retry-After"],
)


# Import and add middleware
from app.middleware.security import SecurityMiddleware
from app.middleware.rule_enforcement import RuleEnforcementMiddleware
from app.middleware.onboarding import OnboardingMiddleware
from app.middleware.auth import AuthMiddleware
from app.middleware.metrics import MetricsMiddleware
from app.middleware.api_version import APIVersionMiddleware

app.add_middleware(SecurityMiddleware)
app.add_middleware(AuthMiddleware)
app.add_middleware(RuleEnforcementMiddleware)
app.add_middleware(OnboardingMiddleware)
app.add_middleware(APIVersionMiddleware)
if settings.METRICS_ENABLED:
    app.add_middleware(MetricsMiddleware)


# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Setup templates
templates = Jinja2Templates(directory="app/templates")


# Include API routers
app.include_router(agents.router, prefix=settings.API_V1_PREFIX, tags=["Agents"])
app.include_router(rules.router, prefix=settings.API_V1_PREFIX, tags=["Rules"])
app.include_router(integrations.router, prefix=settings.API_V1_PREFIX, tags=["Integrations"])
app.include_router(security.router, prefix=settings.API_V1_PREFIX, tags=["Security Research"])
app.include_router(audit.router, prefix=settings.API_V1_PREFIX, tags=["Audit"])
app.include_router(setup.router, tags=["Setup"])
app.include_router(telegram.router, prefix=settings.API_V1_PREFIX, tags=["Telegram"])
app.include_router(slack.router, prefix=settings.API_V1_PREFIX, tags=["Slack"])
app.include_router(approvals.router, prefix=settings.API_V1_PREFIX, tags=["Core"])
app.include_router(vault.router, prefix=settings.API_V1_PREFIX, tags=["Vault"])
app.include_router(auth_router.router, prefix=settings.API_V1_PREFIX, tags=["Auth"])
app.include_router(org_router.router, prefix=settings.API_V1_PREFIX, tags=["Organizations"])
app.include_router(billing_router.router, prefix=settings.API_V1_PREFIX, tags=["Billing"])
app.include_router(saml_router.router, tags=["SSO"])
app.include_router(oidc_router.router, tags=["SSO"])
app.include_router(scim_router.router, tags=["SSO"])
app.include_router(webhooks_router.router, prefix=settings.API_V1_PREFIX, tags=["Webhooks"])
app.include_router(approval_policies_router.router, prefix=settings.API_V1_PREFIX, tags=["Core"])
app.include_router(suggestions_router.router, prefix=settings.API_V1_PREFIX, tags=["Core"])
app.include_router(threats_router.router, prefix=settings.API_V1_PREFIX, tags=["Threats"])


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle uncaught exceptions."""
    logger.exception(f"Unhandled exception: {exc}")

    if settings.DEBUG:
        return JSONResponse(
            status_code=500,
            content={"detail": str(exc), "type": type(exc).__name__},
        )

    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


# Health check endpoints
@app.get("/health", tags=["health"])
async def health_check():
    """Basic health check endpoint."""
    return {"status": "healthy", "version": settings.APP_VERSION}


@app.get("/metrics", tags=["monitoring"])
async def metrics_endpoint():
    """Prometheus metrics scrape target."""
    from app.middleware.metrics import get_metrics_response
    return get_metrics_response()


@app.get("/health/ready", tags=["health"])
async def readiness_check():
    """Readiness check - verifies all dependencies."""
    db_healthy = await check_db_health()
    redis_healthy = await redis_client.check_health()

    if db_healthy and redis_healthy:
        return {
            "status": "ready",
            "database": "connected",
            "redis": "connected",
        }

    return JSONResponse(
        status_code=503,
        content={
            "status": "not ready",
            "database": "connected" if db_healthy else "disconnected",
            "redis": "connected" if redis_healthy else "disconnected",
        },
    )


# Dashboard routes
@app.get("/", tags=["dashboard"])
async def dashboard(request: Request):
    """Main dashboard page."""
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "settings": settings},
    )


@app.get("/agents", tags=["dashboard"])
async def agents_page(request: Request):
    """Agents management page."""
    return templates.TemplateResponse(
        "agents/index.html",
        {"request": request, "settings": settings},
    )


@app.get("/rules", tags=["dashboard"])
async def rules_page(request: Request):
    """Rules management page."""
    return templates.TemplateResponse(
        "rules/index.html",
        {"request": request, "settings": settings},
    )


@app.get("/rules/create", tags=["dashboard"])
async def rules_create_page(request: Request):
    """Create rule page."""
    return templates.TemplateResponse(
        "rules/create.html",
        {"request": request, "settings": settings},
    )


@app.get("/rules/edit/{rule_id}", tags=["dashboard"])
async def rules_edit_page(request: Request, rule_id: str):
    """Edit rule page."""
    return templates.TemplateResponse(
        "rules/edit.html",
        {"request": request, "settings": settings, "rule_id": rule_id},
    )


@app.get("/approvals", tags=["dashboard"])
async def approvals_page(request: Request):
    """Approval automation management page."""
    return templates.TemplateResponse(
        "approvals/index.html",
        {"request": request, "settings": settings},
    )


@app.get("/security", tags=["dashboard"])
async def security_page(request: Request):
    """Security intelligence page."""
    return templates.TemplateResponse(
        "security/index.html",
        {"request": request, "settings": settings},
    )


@app.get("/audit", tags=["dashboard"])
async def audit_page(request: Request):
    """Audit logs page."""
    return templates.TemplateResponse(
        "audit/index.html",
        {"request": request, "settings": settings},
    )


@app.get("/integrations", tags=["dashboard"])
async def integrations_page(request: Request):
    """Integrations management page."""
    return templates.TemplateResponse(
        "integrations/index.html",
        {"request": request, "settings": settings},
    )


@app.get("/wizard", tags=["dashboard"])
async def wizard_page(request: Request):
    """First-run security wizard."""
    return templates.TemplateResponse(
        "wizard/index.html",
        {"request": request, "settings": settings},
    )


@app.get("/settings", tags=["dashboard"])
async def settings_page(request: Request):
    """Settings page."""
    return templates.TemplateResponse(
        "settings/index.html",
        {"request": request, "settings": settings},
    )


@app.get("/help", tags=["dashboard"])
async def help_page(request: Request):
    """Help and FAQ page."""
    return templates.TemplateResponse(
        "help/index.html",
        {"request": request, "settings": settings},
    )


@app.get("/terms", tags=["dashboard"])
async def terms_page(request: Request):
    """Terms of service page."""
    return templates.TemplateResponse(
        "terms.html",
        {"request": request, "settings": settings},
    )


@app.get("/docs", tags=["dashboard"])
async def docs_page(request: Request):
    """API documentation page."""
    return templates.TemplateResponse(
        "docs/index.html",
        {"request": request, "settings": settings},
    )


# Auth pages (standalone, no nav auth required)
@app.get("/login", tags=["auth"])
async def login_page(request: Request):
    """Login page."""
    return templates.TemplateResponse(
        "auth/login.html",
        {"request": request, "settings": settings},
    )


@app.get("/register", tags=["auth"])
async def register_page(request: Request):
    """Registration page."""
    return templates.TemplateResponse(
        "auth/register.html",
        {"request": request, "settings": settings},
    )


@app.get("/forgot-password", tags=["auth"])
async def forgot_password_page(request: Request):
    """Forgot password page."""
    return templates.TemplateResponse(
        "auth/forgot_password.html",
        {"request": request, "settings": settings},
    )


@app.get("/reset-password", tags=["auth"])
async def reset_password_page(request: Request):
    """Password reset page."""
    return templates.TemplateResponse(
        "auth/reset_password.html",
        {"request": request, "settings": settings},
    )


# Org management pages
@app.get("/org/settings", tags=["dashboard"])
async def org_settings_page(request: Request):
    """Organization settings page."""
    return templates.TemplateResponse(
        "org/settings.html",
        {"request": request, "settings": settings},
    )


@app.get("/org/members", tags=["dashboard"])
async def org_members_page(request: Request):
    """Organization members page."""
    return templates.TemplateResponse(
        "org/members.html",
        {"request": request, "settings": settings},
    )


@app.get("/billing", tags=["dashboard"])
async def billing_page(request: Request):
    """Billing page."""
    return templates.TemplateResponse(
        "org/billing.html",
        {"request": request, "settings": settings},
    )
