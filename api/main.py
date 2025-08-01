"""
NGINX Manager API

A comprehensive API for managing NGINX configurations, SSL certificates,
and reverse proxy setups. Designed for AI agent integration with detailed
OpenAPI specifications and robust validation.

This API follows REST principles and provides safe, validated operations
for NGINX server management in containerized environments.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uvicorn
import logging
from datetime import datetime

from endpoints import sites
from config import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger.info("🚀 NGINX Manager API starting up...")
    yield
    logger.info("🛑 NGINX Manager API shutting down...")


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
    openapi_url="/openapi.json"
)

# Include API routers
app.include_router(sites.router)

# CORS middleware for web interface compatibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get(
    "/",
    summary="API Health Check",
    description="Basic health check endpoint to verify the API is running.",
    response_description="API status and basic information",
    tags=["Health"]
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
        "features": [
            "Configuration Management",
            "SSL Certificate Lifecycle", 
            "Reverse Proxy Setup"
        ]
    }


@app.get(
    "/health",
    summary="Detailed Health Check",
    description="Comprehensive health check including system status and dependencies.",
    response_description="Detailed health status of API and connected services",
    tags=["Health"]
)
async def health_check():
    """
    Detailed health check endpoint for monitoring and AI agent verification.
    
    This endpoint provides comprehensive status information about:
    - API service health
    - NGINX container status (when implemented)
    - Configuration validation capabilities
    - SSL certificate management status
    
    Returns:
        dict: Detailed health status and system information
    """
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "api": {
            "status": "running",
            "version": "0.1.0"
        },
        "nginx": {
            "status": "not_connected",  # Will be implemented
            "message": "NGINX management not yet implemented"
        },
        "ssl": {
            "status": "not_configured",  # Will be implemented
            "message": "SSL management not yet implemented"
        }
    }


if __name__ == "__main__":
    uvicorn.run(
        "main:app", 
        host="0.0.0.0", 
        port=8000, 
        reload=True,
        log_level="info"
    )
