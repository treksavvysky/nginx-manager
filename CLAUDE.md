# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NGINX Manager is an AI-agent-first REST API for managing NGINX configurations, SSL certificates, and reverse proxy setups. Built with FastAPI (Python 3.12), designed for integration with AI systems (Custom GPTs, Claude MCP). Features crossplane-based config parsing and Docker-based NGINX container control.

## Commands

### Development
```bash
./scripts/dev-deploy.sh                           # Start dev environment (hot reload)
docker compose -f docker/compose/dev.yml logs -f  # View logs
docker compose -f docker/compose/dev.yml down     # Stop services
```

### Production
```bash
./scripts/prod-deploy.sh             # Deploy to production
curl http://localhost:8000/health    # Check API health
```

### API Documentation
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
- OpenAPI schema: http://localhost:8000/openapi.json

### Testing
```bash
pytest                              # Run all tests
pytest tests/unit/ -v               # Run unit tests with verbose output
docker run --rm -v "$(pwd)/tests:/app/tests" -v "$(pwd)/api:/app/api" \
  -w /app compose-nginx-manager-api pytest tests/  # Run in Docker
```

## Architecture

```
Client (AI Agents / REST API)
         │
    FastAPI App (api/main.py)
         │
    Endpoints (api/endpoints/)
         │
    Core Logic (api/core/)
         │
    NGINX Container + Docker Compose
```

**Key modules:**
- `api/main.py` - FastAPI app setup, lifespan manager, root/health endpoints
- `api/endpoints/sites.py` - Site configuration endpoints (GET /sites/, GET /sites/{site_name})
- `api/endpoints/nginx.py` - NGINX control endpoints (reload, restart, status, test)
- `api/endpoints/transactions.py` - Transaction history and rollback endpoints
- `api/endpoints/events.py` - Event audit log endpoints
- `api/core/config_manager/crossplane_parser.py` - Crossplane-based NGINX parser (full directive support)
- `api/core/config_manager/adapter.py` - Converts parsed config to API response format
- `api/core/docker_service.py` - Docker SDK wrapper for NGINX container management
- `api/core/health_checker.py` - HTTP health verification with retries
- `api/core/transaction_manager.py` - Transaction lifecycle management with snapshots
- `api/core/event_store.py` - Event persistence and querying
- `api/core/snapshot_service.py` - Configuration state capture and restoration
- `api/core/database.py` - SQLite async database management
- `api/models/nginx.py` - Rich data models: ServerBlock, LocationBlock, UpstreamBlock, SSLConfig, NginxOperationResult
- `api/models/transaction.py` - Transaction, TransactionDetail, RollbackResult models
- `api/models/event.py` - Event, EventFilters models
- `api/models/config.py` - Pydantic models: SiteConfig, SiteConfigResponse, ConfigValidationResult
- `api/config.py` - Pydantic BaseSettings for environment configuration

**Docker setup:**
- `docker/compose/dev.yml` - Development with hot reload, volumes mounted
- `docker/compose/prod.yml` - Production hardened, localhost-only API, non-root user
- `docker/api/Dockerfile` - Python 3.12-slim base
- `docker/nginx/Dockerfile` - nginx:alpine base

## Configuration

Environment variables managed via Pydantic BaseSettings in `api/config.py`:
- `NGINX_CONF_DIR`, `BACKUP_DIR`, `SSL_CERT_DIR` - Path configurations
- `API_DEBUG` - Enable debug mode and verbose logging
- `VALIDATE_BEFORE_DEPLOY`, `AUTO_BACKUP` - Safety flags
- `NGINX_CONTAINER_NAME` - Docker container name for NGINX (default: nginx-manager-nginx)
- `NGINX_HEALTH_ENDPOINT` - HTTP endpoint to verify NGINX health
- `NGINX_OPERATION_TIMEOUT`, `NGINX_HEALTH_CHECK_RETRIES`, `NGINX_HEALTH_CHECK_INTERVAL` - Operation settings
- `TRANSACTION_DB_PATH` - SQLite database for transaction/event metadata
- `SNAPSHOT_DIR` - Directory for configuration snapshots
- `SNAPSHOT_RETENTION_DAYS`, `EVENT_RETENTION_DAYS` - Retention policies
- `AUTO_ROLLBACK_ON_FAILURE` - Automatic rollback on operation failure

## Current Limitations

- Site CRUD operations not yet implemented (read-only for sites)
- No authentication/authorization
- No SSL certificate automation
