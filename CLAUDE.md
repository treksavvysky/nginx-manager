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
- `api/endpoints/sites.py` - Site CRUD endpoints (list, get, create, update, delete, enable, disable)
- `api/endpoints/nginx.py` - NGINX control endpoints (reload, restart, status, test)
- `api/endpoints/certificates.py` - SSL certificate endpoints (request, list, get, delete, renew, upload, diagnose)
- `api/endpoints/transactions.py` - Transaction history and rollback endpoints
- `api/endpoints/events.py` - Event audit log endpoints
- `api/core/config_manager/crossplane_parser.py` - Crossplane-based NGINX parser (full directive support: server, location, upstream, map, geo, include resolution)
- `api/core/config_manager/adapter.py` - Converts parsed config to API response format
- `api/core/config_generator/generator.py` - Jinja2-based NGINX config generator
- `api/core/config_generator/templates/` - NGINX config templates (static_site, reverse_proxy, ssl_static_site, ssl_reverse_proxy)
- `api/core/docker_service.py` - Docker SDK wrapper for NGINX container management
- `api/core/health_checker.py` - HTTP health verification with retries
- `api/core/acme_service.py` - ACME protocol client for Let's Encrypt certificate automation
- `api/core/cert_manager.py` - Certificate lifecycle management (request, renew, revoke, upload)
- `api/core/cert_scheduler.py` - Background scheduler for auto-renewal and expiry warnings
- `api/core/transaction_manager.py` - Transaction lifecycle management with snapshots
- `api/core/event_store.py` - Event persistence and querying
- `api/core/snapshot_service.py` - Configuration state capture and restoration
- `api/core/context_helpers.py` - Generates suggestions and warnings for AI-friendly responses
- `api/core/database.py` - SQLite async database management (transactions, events, certificates, acme_accounts)
- `api/models/nginx.py` - Rich data models: ServerBlock, LocationBlock, UpstreamBlock, MapBlock, GeoBlock, SSLConfig, NginxOperationResult, ParsedNginxConfig
- `api/models/certificate.py` - SSL certificate models: Certificate, CertificateStatus, CertificateRequestCreate, CertificateUploadRequest, CertificateMutationResponse
- `api/models/transaction.py` - Transaction, TransactionDetail, RollbackResult models
- `api/models/event.py` - Event, EventFilters models
- `api/models/config.py` - Pydantic models: SiteConfig, SiteConfigResponse, ConfigValidationResult
- `api/models/site_requests.py` - Site CRUD request/response models: SiteCreateRequest, SiteUpdateRequest, SiteMutationResponse, DryRunResult, DryRunDiff
- `api/config.py` - Pydantic BaseSettings for environment configuration

**Docker setup:**
- `docker/compose/dev.yml` - Development with hot reload, volumes mounted
- `docker/compose/prod.yml` - Production hardened, localhost-only API, non-root user
- `docker/api/Dockerfile` - Python 3.12-slim base
- `docker/nginx/Dockerfile` - nginx:alpine base

**Directory structure (persistent storage):**
```
├── test-configs/          → /etc/nginx/conf.d    (NGINX site configs)
├── www/                   → /var/www             (Website content)
└── data/
    ├── ssl/               → /etc/ssl             (SSL certificates & private keys)
    ├── acme-challenge/    → /var/www/.well-known/acme-challenge (ACME HTTP-01 challenges)
    ├── nginx-logs/        → /var/log/nginx       (NGINX access/error logs)
    ├── api-logs/          → /var/log/nginx-manager (API logs)
    └── api-backups/       → /var/backups/nginx   (Database & config snapshots)
```

## Data Persistence & Security

**Persistent Data**: The `data/` directory contains all persistent state and survives container restarts. Even in development mode, data is stored on the host filesystem, not inside containers. Back up this directory to preserve:
- SSL certificates and private keys
- Transaction history and certificate metadata (SQLite database)
- Configuration snapshots for rollback

**Sensitive Data - DO NOT COMMIT**: The following contain secrets and must never be pushed to git:
- `data/ssl/` - SSL private keys
- `data/api-backups/*.db` - May contain ACME account keys
- `.env` files - API keys and credentials

These paths are excluded in `.gitignore`. Before committing, verify with:
```bash
git status --ignored
```

**Development vs Production**: Both environments use the same persistent storage pattern. The difference is that dev mounts source code for hot-reload while prod uses built images. Your certificates and database persist regardless of which mode you use.

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
- `ACME_DIRECTORY_URL` - Let's Encrypt ACME directory (production by default)
- `ACME_STAGING_URL` - Let's Encrypt staging directory for testing
- `ACME_USE_STAGING` - Use staging environment to avoid rate limits during development
- `ACME_ACCOUNT_EMAIL` - Email for Let's Encrypt account registration
- `ACME_CHALLENGE_DIR` - Directory for HTTP-01 challenge files
- `CERT_RENEWAL_DAYS` - Days before expiry to trigger auto-renewal (default: 30)
- `CERT_EXPIRY_WARNING_DAYS` - Days before expiry to generate warnings (default: 14)

## API Usage Examples

### Create a static site
```bash
curl -X POST http://localhost:8000/sites/ \
  -H "Content-Type: application/json" \
  -d '{"name": "example.com", "server_names": ["example.com"], "site_type": "static", "root_path": "/var/www/example", "auto_reload": true}'
```

### Create a reverse proxy site
```bash
curl -X POST http://localhost:8000/sites/ \
  -H "Content-Type: application/json" \
  -d '{"name": "api.example.com", "server_names": ["api.example.com"], "site_type": "reverse_proxy", "proxy_pass": "http://localhost:3000", "auto_reload": true}'
```

### List all sites
```bash
curl http://localhost:8000/sites/
```

### Test a site (requires Host header for virtual hosts)
```bash
curl -H "Host: example.com" http://localhost/
```

### Request Let's Encrypt SSL certificate
```bash
curl -X POST http://localhost:8000/certificates/ \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "alt_names": ["www.example.com"], "auto_renew": true}'
```

### Check SSL readiness (dry-run)
```bash
curl -X POST "http://localhost:8000/certificates/?dry_run=true" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

### List all certificates
```bash
curl http://localhost:8000/certificates/
```

### Run SSL diagnostic for a domain
```bash
curl http://localhost:8000/certificates/example.com/check
```

### Upload custom SSL certificate
```bash
curl -X POST http://localhost:8000/certificates/upload \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "certificate_pem": "-----BEGIN CERTIFICATE-----\n...", "private_key_pem": "-----BEGIN PRIVATE KEY-----\n..."}'
```

## Key Features

- **Rich Context Responses**: All responses include `suggestions` and `warnings` fields for AI guidance
- **Dry-Run Mode**: All mutation endpoints support `?dry_run=true` to preview changes without applying them
- **Transaction System**: All changes create transactions with snapshots for rollback capability
- **Auto-Rollback**: If health check fails after NGINX reload, configuration automatically rolls back
- **Config Validation**: All config changes validated with `nginx -t` before deployment
- **System State Summary**: Health endpoint provides comprehensive system state for AI situational awareness
- **SSL Certificate Automation**: Let's Encrypt integration with HTTP-01 challenge, auto-renewal scheduler, custom certificate upload, and SSL diagnostics

## Current Limitations

- No authentication/authorization
- No web dashboard (API only)
