"""FastAPI application entry point with lifespan management."""

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
from app.routers import agents, approvals, audit, integrations, rules, security, setup, telegram

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

    # Initialize database
    logger.info("Initializing database...")
    await init_db()

    logger.info("Snapper started successfully")

    yield

    # Shutdown
    logger.info("Shutting down Snapper...")

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
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-RateLimit-Remaining", "Retry-After"],
)


# Import and add middleware
from app.middleware.security import SecurityMiddleware
from app.middleware.rule_enforcement import RuleEnforcementMiddleware
from app.middleware.onboarding import OnboardingMiddleware

app.add_middleware(SecurityMiddleware)
app.add_middleware(RuleEnforcementMiddleware)
app.add_middleware(OnboardingMiddleware)


# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Setup templates
templates = Jinja2Templates(directory="app/templates")


# Include API routers
app.include_router(agents.router, prefix=settings.API_V1_PREFIX, tags=["agents"])
app.include_router(rules.router, prefix=settings.API_V1_PREFIX, tags=["rules"])
app.include_router(integrations.router, prefix=settings.API_V1_PREFIX, tags=["integrations"])
app.include_router(security.router, prefix=settings.API_V1_PREFIX, tags=["security"])
app.include_router(audit.router, prefix=settings.API_V1_PREFIX, tags=["audit"])
app.include_router(setup.router, tags=["setup"])
app.include_router(telegram.router, prefix=settings.API_V1_PREFIX, tags=["telegram"])
app.include_router(approvals.router, prefix=settings.API_V1_PREFIX, tags=["approvals"])


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
