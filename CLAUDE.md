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

### Testing & CI
```bash
make ci                             # Run full CI check (lint + test with coverage)
make lint                           # Ruff check + format verification
make format                         # Auto-fix lint issues and format code
make test                           # Run unit tests with verbose output
make test-cov                       # Run tests with coverage report (45% threshold)
pytest tests/unit/ -v               # Run unit tests directly
```

### Linting
```bash
uv run ruff check api/ tests/       # Check lint rules
uv run ruff check --fix api/ tests/  # Auto-fix lint issues
uv run ruff format api/ tests/       # Format code
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
- `api/endpoints/workflows.py` - Compound workflow endpoints (setup-site, migrate-site) with SSE streaming
- `api/endpoints/gpt.py` - GPT integration endpoints (openapi.json schema, instructions)
- `api/endpoints/auth.py` - Authentication endpoints (bootstrap, API key CRUD, token exchange/refresh)
- `api/endpoints/users.py` - User management endpoints (login, user CRUD, password change)
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
- `api/core/context_helpers.py` - Generates suggestions, warnings, and security warnings for AI-friendly responses
- `api/core/auth_service.py` - API key + JWT token management (creation, validation, hashing)
- `api/core/auth_dependency.py` - FastAPI Depends() for authentication and role-based access control
- `api/core/user_service.py` - User account management (bcrypt hashing, login with lockout, CRUD)
- `api/core/encryption_service.py` - Fernet encryption for private key storage at rest
- `api/core/rate_limiter.py` - slowapi rate limiting configuration
- `api/core/request_logger.py` - HTTP request logging middleware
- `api/core/database.py` - SQLite async database management (transactions, events, certificates, acme_accounts, api_keys, users)
- `api/core/workflow_engine.py` - Generic workflow execution engine with checkpoint-based rollback and progress callbacks
- `api/core/workflow_definitions.py` - Concrete step implementations for setup-site and migrate-site workflows
- `api/core/gpt_schema.py` - Transforms FastAPI OpenAPI schema for Custom GPT Actions compatibility (tag filtering, description truncation, operationId enforcement)
- `api/models/nginx.py` - Rich data models: ServerBlock, LocationBlock, UpstreamBlock, MapBlock, GeoBlock, SSLConfig, NginxOperationResult, ParsedNginxConfig
- `api/models/certificate.py` - SSL certificate models: Certificate, CertificateStatus, CertificateRequestCreate, CertificateUploadRequest, CertificateMutationResponse
- `api/models/transaction.py` - Transaction, TransactionDetail, RollbackResult models
- `api/models/event.py` - Event, EventFilters models (with audit fields: client_ip, user_id, api_key_id)
- `api/models/auth.py` - Auth models: Role, AuthContext, APIKey, User, LoginRequest/Response, TokenRequest/Response
- `api/models/config.py` - Pydantic models: SiteConfig, SiteConfigResponse, ConfigValidationResult
- `api/models/site_requests.py` - Site CRUD request/response models: SiteCreateRequest, SiteUpdateRequest, SiteMutationResponse, DryRunResult, DryRunDiff
- `api/models/workflow.py` - Workflow models: SetupSiteRequest, MigrateSiteRequest, WorkflowResponse, WorkflowDryRunResponse, WorkflowProgressEvent
- `api/config.py` - Pydantic BaseSettings for environment configuration
- `api/gpt/instructions.md` - System prompt template for Custom GPT builder
- `api/gpt/example_config.json` - Example Custom GPT configuration
- `api/mcp_server/` - MCP (Model Context Protocol) server for AI agent integration
  - `api/mcp_server/server.py` - Main MCP server with stdio and HTTP transport support
  - `api/mcp_server/resources.py` - Read-only resources (sites, certificates, health, events, transactions)
  - `api/mcp_server/tools.py` - Executable tools (site CRUD, NGINX control, SSL management, rollback, workflows)
  - `api/mcp_server/prompts.py` - Workflow templates (setup site, add SSL, diagnose connectivity)

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
- `WORKFLOW_STEP_TIMEOUT` - Timeout in seconds for individual workflow steps (default: 120)
- `WORKFLOW_AUTO_ROLLBACK` - Automatically rollback checkpoint steps on workflow failure (default: true)
- `AUTH_ENABLED` - Enable API key/JWT authentication (default: false for backward compatibility)
- `AUTH_MASTER_KEY` - Master key for bootstrapping the first admin API key
- `JWT_SECRET_KEY` - Secret key for signing JWT tokens (required when AUTH_ENABLED=true)
- `JWT_ALGORITHM` - Algorithm for JWT signing (default: HS256)
- `JWT_EXPIRY_MINUTES` - JWT token expiration time in minutes (default: 60)
- `MCP_API_KEY` - API key for MCP server authentication (stdio transport)
- `MCP_REQUIRE_AUTH` - Require authentication for MCP connections (default: true)
- `CORS_ALLOWED_ORIGINS` - Comma-separated list of allowed CORS origins (empty = wildcard in debug mode only)
- `ENCRYPT_PRIVATE_KEYS` - Encrypt SSL private keys at rest using Fernet (default: false)
- `PRIVATE_KEY_ENCRYPTION_KEY` - Passphrase for private key encryption (min 16 chars recommended)

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

### Setup a complete site with SSL (workflow)
```bash
curl -X POST http://localhost:8000/workflows/setup-site \
  -H "Content-Type: application/json" \
  -d '{"name": "example.com", "server_names": ["example.com"], "site_type": "static", "root_path": "/var/www/example", "request_ssl": true}'
```

### Migrate a site with auto-rollback on failure (workflow)
```bash
curl -X POST http://localhost:8000/workflows/migrate-site \
  -H "Content-Type: application/json" \
  -d '{"name": "example.com", "proxy_pass": "http://localhost:4000"}'
```

### Preview a workflow (dry-run)
```bash
curl -X POST "http://localhost:8000/workflows/setup-site?dry_run=true" \
  -H "Content-Type: application/json" \
  -d '{"name": "example.com", "server_names": ["example.com"], "site_type": "static", "root_path": "/var/www/example", "request_ssl": false}'
```

### Stream workflow progress (SSE)
```bash
curl -N -X POST "http://localhost:8000/workflows/setup-site?stream=true" \
  -H "Content-Type: application/json" \
  -d '{"name": "example.com", "server_names": ["example.com"], "site_type": "static", "root_path": "/var/www/example"}'
```

### Get GPT-compatible OpenAPI schema
```bash
curl "http://localhost:8000/gpt/openapi.json?server_url=https://your-domain.com"
```

## Key Features

- **Rich Context Responses**: All responses include `suggestions` and `warnings` fields for AI guidance
- **Dry-Run Mode**: All mutation endpoints support `?dry_run=true` to preview changes without applying them
- **Transaction System**: All changes create transactions with snapshots for rollback capability
- **Auto-Rollback**: If health check fails after NGINX reload, configuration automatically rolls back
- **Config Validation**: All config changes validated with `nginx -t` before deployment
- **System State Summary**: Health endpoint provides comprehensive system state for AI situational awareness
- **SSL Certificate Automation**: Let's Encrypt integration with HTTP-01 challenge, auto-renewal scheduler, custom certificate upload, and SSL diagnostics
- **MCP Server**: Native Model Context Protocol support for Claude and other AI agents
- **Agent Workflows**: Compound operations (setup-site, migrate-site) with checkpoint-based rollback and SSE progress streaming
- **Custom GPT Integration**: GPT-compatible OpenAPI schema generator with description truncation, tag filtering, and system instruction templates

## MCP Server

The MCP server provides an AI-native interface for NGINX Manager, exposing all functionality through the Model Context Protocol.

### Running the MCP Server
```bash
# Stdio transport (for Claude Desktop/Claude Code)
cd api && python3 mcp_server/server.py

# HTTP transport (for remote access)
cd api && python3 mcp_server/server.py --transport streamable-http --port 8080

# Add to Claude Code (from project directory)
claude mcp add nginx-manager --transport stdio -e PYTHONPATH=/path/to/api -- python3 /path/to/api/mcp_server/server.py
```

### MCP Resources (Read-Only)
- `nginx://sites` - List all site configurations
- `nginx://sites/{name}` - Get specific site details
- `nginx://certificates` - List all SSL certificates
- `nginx://health` - System health summary
- `nginx://events` - Recent system events
- `nginx://transactions` - Transaction history

### MCP Tools (Actions)
- `create_site`, `update_site`, `delete_site`, `enable_site`, `disable_site`
- `nginx_reload`, `nginx_restart`, `nginx_test`
- `request_certificate`, `upload_certificate`, `renew_certificate`, `revoke_certificate`, `diagnose_ssl`
- `rollback_transaction`
- `setup_site_workflow`, `migrate_site_workflow`

### MCP Prompts (Workflow Templates)
- `setup_new_site` - Guide for creating sites with optional SSL
- `add_ssl_to_site` - Guide for adding SSL certificates
- `check_expiring_certs` - Guide for certificate renewal
- `diagnose_connectivity` - Guide for troubleshooting
- `rollback_changes` - Guide for safe rollback

See `docs/MCP_DESIGN.md` for full schema definitions and `docs/MCP_DEPLOYMENT.md` for deployment guide.

## Custom GPT Integration

The API can power an OpenAI Custom GPT for managing NGINX via natural language.

### Setup
1. Fetch the GPT-compatible schema: `GET /gpt/openapi.json?server_url=https://your-domain.com`
2. Fetch the system instructions: `GET /gpt/instructions`
3. In the GPT builder, import the schema and paste the instructions
4. Set authentication to API Key with header `X-API-Key`

### Schema Features
- Filters endpoints by tag (Site Configuration, NGINX Control, SSL Certificates, Agent Workflows)
- Truncates descriptions to 300 characters (GPT's enforced limit)
- Ensures all operations have unique `operationId` values
- Respects `X-Forwarded-Proto` and `X-Forwarded-Host` headers for correct server URL detection behind reverse proxies

See `docs/GPT_INTEGRATION.md` for the full setup guide.

## Agent Workflows

Compound operations that orchestrate multiple API calls with checkpoint-based rollback.

### Available Workflows
- **Setup Site** (`POST /workflows/setup-site`) - Create site + optional SSL in one operation (3-6 steps)
- **Migrate Site** (`POST /workflows/migrate-site`) - Update site with auto-rollback if config validation fails (3 steps)

### Features
- Checkpoint-based rollback: steps that create transactions become rollback points
- SSE streaming: add `?stream=true` for real-time progress events
- Dry-run mode: add `?dry_run=true` to preview steps without executing
- Non-critical failure handling: SSL failures during setup don't rollback the site creation

See `docs/AGENT_WORKFLOWS.md` for full documentation.

## Authentication & Security (Phase 5)

Authentication is **opt-in** via `AUTH_ENABLED=true` (default: false for backward compatibility).

### Auth Methods
- **API Key**: `X-API-Key` header, SHA-256 hashed storage, key format `ngx_` + 64 hex chars
- **JWT Token**: `Authorization: Bearer <token>` header, exchanged from API key or user login
- **User Login**: `POST /auth/login` with username/password, returns JWT token

### Role Hierarchy
- **ADMIN** (level 3): Full access including user/key management and rollback
- **OPERATOR** (level 2): Create, update, delete sites/certs, reload NGINX
- **VIEWER** (level 1): Read-only access

### Security Features
- Rate limiting (slowapi): 60 req/min default, keyed by IP + auth identity
- Account lockout: 5 failed login attempts = 30 min lockout
- Security headers: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, Cache-Control
- NGINX config injection prevention (semicolons, braces, backticks, dollar signs blocked)
- SSRF prevention (cloud metadata endpoints blocked in proxy_pass)
- Private key encryption at rest (Fernet, optional)
- Security warnings surfaced in `/health` endpoint
- MCP auth: API key env var for stdio, Bearer header for HTTP transport

### Bootstrap Flow
```bash
# 1. Set environment variables
AUTH_ENABLED=true AUTH_MASTER_KEY=your-secret JWT_SECRET_KEY=your-jwt-secret

# 2. Create first admin key
curl -X POST http://localhost:8000/auth/bootstrap -H "X-Master-Key: your-secret"

# 3. Create user account
curl -X POST http://localhost:8000/auth/users \
  -H "X-API-Key: ngx_..." -d '{"username":"admin","password":"SecurePass123!","role":"admin"}'

# 4. Login
curl -X POST http://localhost:8000/auth/login \
  -d '{"username":"admin","password":"SecurePass123!"}'
```

## CI/CD Pipeline (Phase 6.1)

- **GitHub Actions CI** (`.github/workflows/ci.yml`): lint → test (with coverage) → Docker build on push/PR to main
- **GitHub Actions Release** (`.github/workflows/release.yml`): builds and pushes Docker images to ghcr.io on `v*` tags
- **Dependabot** (`.github/dependabot.yml`): pip (weekly), GitHub Actions (weekly), Docker (monthly)
- **Pre-commit hooks** (`.pre-commit-config.yaml`): ruff check+fix, ruff format, trailing whitespace, end-of-file, YAML, large files
- **Makefile**: `make lint`, `make format`, `make test`, `make test-cov`, `make ci`, `make dev`, `make down`
- **Ruff config**: in `pyproject.toml` — target Python 3.12, line-length 120, select rules (E, W, F, I, N, UP, B, SIM, RUF)
- **Test conftest** (`tests/conftest.py`): disables `AUTH_ENABLED` for unit tests so they don't require auth credentials
- **Coverage threshold**: 45% minimum (`--cov-fail-under=45`), current baseline ~52%

## Current Limitations

- No web dashboard (Phase 7, API only)
- 2FA not yet available (Phase 6.3)
- No mypy type checking (deferred — insufficient type annotations across codebase)
