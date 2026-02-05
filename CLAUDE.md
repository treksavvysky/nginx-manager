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
make dev                                          # Alias for dev-deploy.sh
make down                                         # Stop dev services
```

### Testing
```bash
make ci                                    # Full CI: lint + test with coverage
make lint                                  # Ruff check + format verification
make format                                # Auto-fix lint issues and format code
make test                                  # Run all unit tests
make test-cov                              # Tests with coverage (45% threshold)

# Run specific tests
uv run pytest tests/unit/test_nginx_endpoints.py -v          # Single file
uv run pytest tests/unit/test_nginx_endpoints.py::TestNginxStatus -v  # Single class
uv run pytest tests/unit/test_nginx_endpoints.py::TestNginxStatus::test_status_running_container -v  # Single test
uv run pytest -k "reload" -v               # Tests matching pattern
```

### Linting
```bash
uv run ruff check api/ tests/              # Check lint rules
uv run ruff check --fix api/ tests/        # Auto-fix lint issues
uv run ruff format api/ tests/             # Format code
```

### API & Documentation
- Swagger UI: http://localhost:{API_PORT}/docs (default 8000, check `.env`)
- ReDoc: http://localhost:{API_PORT}/redoc
- Dashboard: http://localhost:{API_PORT}/dashboard/

## Architecture

```
Client (AI Agents / REST API / Web Dashboard)
         │
    FastAPI App (api/main.py)
         │
    ├── Endpoints (api/endpoints/)     ← REST API
    ├── Dashboard (api/dashboard/)     ← HTMX web UI
    │
    Core Logic (api/core/)
         │
    NGINX Container + Docker Compose
```

### Key Modules

**Entry Points:**
- `api/main.py` - FastAPI app setup, lifespan manager, middleware, root/health endpoints
- `api/config.py` - Pydantic BaseSettings for all environment configuration

**REST Endpoints (`api/endpoints/`):**
- `sites.py` - Site CRUD (create, update, delete, enable, disable)
- `nginx.py` - NGINX control (reload, restart, status, test)
- `certificates.py` - SSL certificates (request, renew, upload, diagnose)
- `workflows.py` - Compound operations with SSE streaming
- `auth.py`, `users.py`, `totp.py`, `sessions.py` - Authentication & 2FA

**Core Services (`api/core/`):**
- `config_manager/crossplane_parser.py` - NGINX config parsing via crossplane
- `config_generator/generator.py` - Jinja2-based config generation
- `docker_service.py` - Docker SDK wrapper for NGINX container
- `cert_manager.py` - SSL certificate lifecycle
- `transaction_manager.py` - Transaction system with snapshots
- `workflow_engine.py` - Generic workflow execution with rollback

**MCP Server (`api/mcp_server/`):**
- `server.py` - MCP server with stdio/HTTP transport; auto-detects host vs container paths at startup
- `resources.py` - Read-only resources (sites, certs, health)
- `tools.py` - Executable actions (CRUD, reload, SSL)

**Dashboard (`api/dashboard/`):**
- `router.py` - All dashboard routes (HTMX fragments + full pages)
- `dependencies.py` - Cookie-based JWT auth
- Server-rendered with HTMX + Alpine.js + Jinja2

### Data Models (`api/models/`)
- `nginx.py` - ServerBlock, LocationBlock, UpstreamBlock, SSLConfig
- `certificate.py` - Certificate, CertificateStatus
- `transaction.py`, `event.py` - Audit trail
- `auth.py` - Role, APIKey, User, Session

### Docker Setup
- `docker/compose/dev.yml` - Development with hot reload
- `docker/compose/prod.yml` - Production hardened
- `docker/api/Dockerfile` - Python 3.12-slim
- `docker/nginx/Dockerfile` - nginx:alpine

### Directory Structure (Persistent Storage)
```
├── test-configs/          → /etc/nginx/conf.d                    (NGINX site configs)
├── www/                   → /var/www                             (Website content)
└── data/
    ├── ssl/               → /etc/ssl                             (SSL certs & keys)
    ├── acme-challenge/    → /var/www/.well-known/acme-challenge  (HTTP-01 challenges)
    ├── nginx-logs/        → NGINX logs
    ├── api-logs/          → API logs
    └── api-backups/       → Database & snapshots
```

### MCP Server Path Architecture

The MCP server runs on the **host** (not inside Docker). Some paths serve dual purposes: file I/O (must use host paths) and NGINX config directives (must use container paths). These are controlled by separate settings:

| Purpose | Write path (host) | NGINX config path (container) |
|---|---|---|
| ACME challenges | `ACME_CHALLENGE_DIR` → `data/acme-challenge` | `ACME_CHALLENGE_NGINX_PATH` → `/var/www/.well-known/acme-challenge` |
| SSL certificates | `SSL_CERT_DIR` → `data/ssl/certs` | `SSL_CERT_NGINX_PATH` → `/etc/ssl/certs` |

When running inside Docker (API container), both settings default to the same container-internal path. The split only matters for the MCP server on the host — configured in `server.py`'s `__main__` block and `.mcp.json` env vars.

## Testing Patterns

Tests use `pytest` with `pytest-asyncio`. Auth is disabled globally in `tests/conftest.py`:
```python
os.environ["AUTH_ENABLED"] = "false"
```

Common fixtures in `tests/conftest.py`:
- `mock_transaction_ctx` - Mocked transactional_operation
- `mock_docker_service` - Pre-configured DockerService mock
- `tmp_conf_dir` - Temporary NGINX conf directory
- `sample_site_config` - Standard site config dict

Test pattern using httpx AsyncClient:
```python
from httpx import ASGITransport, AsyncClient
from main import app

@pytest.mark.asyncio
async def test_endpoint():
    with patch("endpoints.nginx.docker_service") as mock:
        mock.get_container_status = AsyncMock(return_value={...})
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/nginx/status")
```

## Key Design Patterns

**All mutation endpoints support:**
- `?dry_run=true` - Preview changes without applying
- Transaction creation with snapshots for rollback
- Rich context responses with `suggestions` and `warnings` fields

**Authentication (opt-in via `AUTH_ENABLED=true`):**
- API Key: `X-API-Key` header (format: `ngx_` + 64 hex chars)
- JWT: `Authorization: Bearer <token>`
- Roles: ADMIN (level 3) > OPERATOR (level 2) > VIEWER (level 1)
- Optional TOTP 2FA for user logins

**Safety Features:**
- Config validation with `nginx -t` before deployment
- Auto-rollback if health check fails after reload
- NGINX config injection prevention
- SSRF prevention for proxy_pass URLs

## Sensitive Data - DO NOT COMMIT

These paths are in `.gitignore`:
- `data/ssl/` - SSL private keys
- `data/api-backups/*.db` - May contain ACME account keys
- `.env` files - API keys and credentials

## Current Limitations

- No mypy type checking (insufficient type annotations)
- 2FA enforcement is advisory only (soft warnings)
