"""
NGINX Manager API

A comprehensive API for managing NGINX configurations, SSL certificates,
and reverse proxy setups. Designed for AI agent integration with detailed
OpenAPI specifications and robust validation.

This API follows REST principles and provides safe, validated operations
for NGINX server management in containerized environments.
"""

import logging
from contextlib import asynccontextmanager
from datetime import datetime

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from fastapi.staticfiles import StaticFiles

from config import ensure_directories, settings
from core.rate_limiter import limiter
from core.request_logger import RequestLoggerMiddleware
from endpoints import auth, certificates, events, gpt, nginx, sessions, sites, totp, transactions, users, workflows

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger.info("NGINX Manager API starting up...")

    # Ensure required directories exist
    ensure_directories()

    # Initialize database
    from core.database import initialize_database

    await initialize_database()
    logger.info("Database initialized")

    # Start certificate renewal scheduler
    from core.cert_scheduler import get_cert_scheduler

    cert_scheduler = get_cert_scheduler()
    try:
        await cert_scheduler.start()
        logger.info("Certificate renewal scheduler started")
    except Exception as e:
        logger.warning(f"Failed to start certificate scheduler: {e}")

    yield

    # Stop certificate scheduler
    try:
        await cert_scheduler.stop()
        logger.info("Certificate renewal scheduler stopped")
    except Exception as e:
        logger.warning(f"Error stopping certificate scheduler: {e}")

    logger.info("NGINX Manager API shutting down...")


# FastAPI application with comprehensive metadata for OpenAPI
app = FastAPI(
    title="NGINX Manager API",
    description="""
    ## 🎯 Purpose

    A modular, AI-agent-first API for managing NGINX configurations, SSL certificates,
    and reverse proxy setups on VPS environments.

    ## 🤖 AI Agent Integration

    This API is specifically designed for AI agents (Custom GPTs, Claude MCP) with:
    - **Detailed OpenAPI schemas** for automatic tool discovery
    - **Comprehensive error responses** with actionable messages
    - **Safe operations** with validation and rollback capabilities
    - **Descriptive endpoints** with clear input/output specifications

    ## 🛡️ Safety Features

    - Configuration validation before deployment
    - Automatic backups before changes
    - Rollback capabilities for failed deployments
    - Health checks and monitoring
    """,
    version="0.1.0",
    contact={
        "name": "NGINX Manager API",
        "email": "admin@example.com",
    },
    license_info={
        "name": "MIT",
    },
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Rate limiting
app.state.limiter = limiter


def _rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """Custom 429 handler with Retry-After and AI-friendly error."""
    retry_after = getattr(exc, "retry_after", 60)
    return JSONResponse(
        status_code=429,
        content={
            "detail": "Rate limit exceeded. Please wait before making more requests.",
            "retry_after_seconds": retry_after,
            "suggestion": "Reduce request frequency or contact an admin for a rate limit override.",
        },
        headers={"Retry-After": str(retry_after)},
    )


app.add_exception_handler(RateLimitExceeded, _rate_limit_handler)

# Include API routers
app.include_router(sites.router)
app.include_router(nginx.router)
app.include_router(events.router)
app.include_router(transactions.router)
app.include_router(certificates.router)
app.include_router(workflows.router)
app.include_router(gpt.router)
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(totp.router)
app.include_router(sessions.router)

# Dashboard (Phase 7)
if settings.dashboard_enabled:
    from dashboard import STATIC_DIR, create_dashboard_router

    app.include_router(create_dashboard_router())
    app.mount("/dashboard/static", StaticFiles(directory=str(STATIC_DIR)), name="dashboard-static")


# Security headers middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        path = request.url.path
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Dashboard pages use SAMEORIGIN for HTMX fragment loading
        if path.startswith("/dashboard/"):
            response.headers["X-Frame-Options"] = "SAMEORIGIN"
        else:
            response.headers["X-Frame-Options"] = "DENY"

        # Static assets can be cached; API and dashboard pages should not
        if path.startswith("/dashboard/static/"):
            response.headers["Cache-Control"] = "public, max-age=86400"
        else:
            response.headers["Cache-Control"] = "no-store"

        return response


app.add_middleware(SecurityHeadersMiddleware)

# Request logging middleware
app.add_middleware(RequestLoggerMiddleware)

# CORS middleware — restrict origins in production
_cors_origins = (
    [o.strip() for o in settings.cors_allowed_origins.split(",") if o.strip()]
    if settings.cors_allowed_origins
    else ["*"]
    if settings.api_debug
    else []
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get(
    "/",
    summary="API Health Check",
    description="Basic health check endpoint to verify the API is running.",
    response_description="API status and basic information",
    tags=["Health"],
)
async def root():
    """
    Welcome endpoint providing API status and basic information.

    Returns:
        dict: API status, version, and available endpoints information
    """
    return {
        "message": "🎯 NGINX Manager API is running",
        "version": "0.1.0",
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "docs_url": "/docs",
        "openapi_url": "/openapi.json",
        "features": ["Configuration Management", "SSL Certificate Lifecycle", "Reverse Proxy Setup"],
    }


@app.get(
    "/health",
    summary="Detailed Health Check",
    description="Comprehensive health check including system status and dependencies.",
    response_description="Detailed health status of API and connected services",
    tags=["Health"],
)
async def health_check():
    """
    Detailed health check endpoint for monitoring and AI agent verification.

    This endpoint provides comprehensive status information about:
    - API service health
    - NGINX container status
    - Site configuration summary
    - Configuration validation capabilities
    - SSL certificate management status

    Returns:
        dict: Detailed health status and system information
    """
    from config import get_nginx_conf_path
    from core.context_helpers import get_system_state_summary
    from core.docker_service import DockerServiceError, docker_service

    # Check NGINX container status
    nginx_status = {"status": "unknown", "message": "Unable to determine NGINX status"}
    nginx_running = False
    nginx_healthy = False

    try:
        container_status = await docker_service.get_container_status()
        if container_status.get("running"):
            nginx_running = True
            nginx_healthy = container_status.get("health_status") == "healthy"
            nginx_status = {
                "status": "running",
                "container_id": container_status.get("container_id"),
                "uptime_seconds": container_status.get("uptime_seconds"),
                "health_status": container_status.get("health_status", "unknown"),
            }
        else:
            nginx_status = {
                "status": container_status.get("status", "stopped"),
                "message": "NGINX container is not running",
            }
    except DockerServiceError as e:
        nginx_status = {"status": "error", "message": e.message, "suggestion": e.suggestion}

    # Count sites
    conf_dir = get_nginx_conf_path()
    enabled_sites = 0
    disabled_sites = 0
    try:
        enabled_sites = len(list(conf_dir.glob("*.conf")))
        disabled_sites = len(list(conf_dir.glob("*.conf.disabled")))
    except Exception:
        pass  # Directory may not exist in some test environments

    total_sites = enabled_sites + disabled_sites

    # Build system state summary
    system_state = get_system_state_summary(
        nginx_running=nginx_running,
        nginx_healthy=nginx_healthy,
        total_sites=total_sites,
        enabled_sites=enabled_sites,
        disabled_sites=disabled_sites,
    )

    # Generate suggestions based on state
    suggestions = []
    if not nginx_running:
        suggestions.append(
            {"action": "Start the NGINX container", "reason": "NGINX is not running", "priority": "high"}
        )
    if enabled_sites == 0 and total_sites == 0:
        suggestions.append(
            {
                "action": "Create your first site",
                "reason": "No sites are configured yet",
                "endpoint": "POST /sites/",
                "priority": "medium",
            }
        )
    if disabled_sites > 0:
        suggestions.append(
            {
                "action": f"Review {disabled_sites} disabled site(s)",
                "reason": "Some sites are disabled and not serving traffic",
                "endpoint": "GET /sites/",
                "priority": "low",
            }
        )

    # Get SSL certificate status
    ssl_status = {"status": "unknown", "total": 0, "valid": 0, "expiring_soon": 0, "expired": 0}
    try:
        from core.cert_manager import get_cert_manager
        from models.certificate import CertificateStatus

        cert_manager = get_cert_manager()
        certs = await cert_manager.list_certificates()
        ssl_status["total"] = len(certs)
        ssl_status["valid"] = len([c for c in certs if c.status == CertificateStatus.VALID])
        ssl_status["expiring_soon"] = len([c for c in certs if c.status == CertificateStatus.EXPIRING_SOON])
        ssl_status["expired"] = len([c for c in certs if c.status == CertificateStatus.EXPIRED])
        ssl_status["status"] = "healthy" if ssl_status["expired"] == 0 else "warning"

        # Add SSL suggestions
        if ssl_status["expiring_soon"] > 0:
            suggestions.append(
                {
                    "action": f"Renew {ssl_status['expiring_soon']} certificate(s) expiring soon",
                    "reason": "Certificates should be renewed before they expire",
                    "endpoint": "GET /certificates/",
                    "priority": "high",
                }
            )
        if ssl_status["expired"] > 0:
            suggestions.append(
                {
                    "action": f"Address {ssl_status['expired']} expired certificate(s)",
                    "reason": "Expired certificates will cause browser warnings",
                    "endpoint": "GET /certificates/",
                    "priority": "critical",
                }
            )
    except Exception as e:
        logger.warning(f"Failed to get SSL status: {e}")
        ssl_status["status"] = "error"
        ssl_status["message"] = str(e)

    # Security warnings
    security_warnings = []
    try:
        from core.context_helpers import get_security_warnings

        security_warnings = get_security_warnings()
    except Exception as e:
        logger.warning(f"Failed to get security warnings: {e}")

    return {
        "status": "healthy" if nginx_healthy else ("degraded" if nginx_running else "unhealthy"),
        "timestamp": datetime.now().isoformat(),
        "api": {"status": "running", "version": "0.2.0"},
        "nginx": nginx_status,
        "sites": {"total": total_sites, "enabled": enabled_sites, "disabled": disabled_sites},
        "system_state": system_state,
        "suggestions": suggestions,
        "ssl": ssl_status,
        "security_warnings": security_warnings,
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True, log_level="info")
