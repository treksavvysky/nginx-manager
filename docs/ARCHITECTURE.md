# Architecture

This document describes the technical architecture of NGINX Manager.

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Clients                                   │
├─────────────────┬─────────────────┬─────────────────────────────┤
│   AI Agents     │   Web Dashboard │      REST Clients           │
│ (MCP/GPT/etc)   │   (Phase 6)     │    (curl/httpx/etc)         │
└────────┬────────┴────────┬────────┴──────────────┬──────────────┘
         │                 │                       │
         └─────────────────┼───────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                     FastAPI Application                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │  Endpoints  │  │  Middleware │  │  OpenAPI/Documentation  │  │
│  │  /sites     │  │  CORS       │  │  /docs, /redoc          │  │
│  │  /nginx     │  │  Auth (TBD) │  │  /openapi.json          │  │
│  │  /certs     │  │  Logging    │  │                         │  │
│  └──────┬──────┘  └─────────────┘  └─────────────────────────┘  │
│         │                                                        │
│         ▼                                                        │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    Core Services                             ││
│  │  ┌───────────────┐  ┌───────────────┐  ┌─────────────────┐  ││
│  │  │ ConfigManager │  │ CertManager   │  │ BackupManager   │  ││
│  │  │ - Parser      │  │ - ACME        │  │ - Snapshot      │  ││
│  │  │ - Validator   │  │ - Renewal     │  │ - Restore       │  ││
│  │  │ - Generator   │  │ - Storage     │  │ - Retention     │  ││
│  │  └───────────────┘  └───────────────┘  └─────────────────┘  ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Shared Volumes                               │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │ /etc/nginx/     │  │ /etc/ssl/       │  │ /var/backups/   │  │
│  │ conf.d/         │  │ certs/          │  │ nginx/          │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                     NGINX Container                              │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    nginx:alpine                              ││
│  │  - Serves HTTP/HTTPS traffic                                 ││
│  │  - Loads configs from /etc/nginx/conf.d/                     ││
│  │  - Health endpoint at /health                                ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## AI-Native Design Principles

NGINX Manager is designed as an AI-agent-first platform. The following principles guide architectural decisions:

### Rich Context in Every Response

Every API response provides complete context, not just acknowledgments:

```json
{
  "success": true,
  "data": { /* the requested/modified resource */ },
  "state": {
    "active_sites": 3,
    "ssl_enabled": 2,
    "pending_renewals": 1
  },
  "suggestions": [
    "Site 'api.example.com' has no SSL configured",
    "Consider enabling gzip compression for static assets"
  ],
  "warnings": [
    "Certificate for 'shop.example.com' expires in 7 days"
  ]
}
```

**Rationale**: AI agents make better decisions with complete context. They shouldn't need multiple API calls to understand system state.

### Transaction Model

All mutations follow a transaction pattern:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Mutation Request                             │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  1. Create Snapshot (automatic)                                  │
│     - Capture current config state                               │
│     - Record transaction ID                                      │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. Apply Change                                                 │
│     - Write new configuration                                    │
│     - Validate with nginx -t                                     │
└────────────────────────────┬────────────────────────────────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
              ▼                             ▼
┌─────────────────────────┐   ┌─────────────────────────────────┐
│  3a. Validation Failed   │   │  3b. Validation Passed          │
│      - Auto-rollback     │   │      - Reload NGINX             │
│      - Return error +    │   │      - Verify health            │
│        how to fix        │   │      - Return success + context │
└─────────────────────────┘   └─────────────────────────────────┘
```

**Rationale**: AI agents can experiment without fear. Every change can be undone, and failures provide guidance for correction.

### Predictive Operations (Dry Run)

All mutation endpoints support `?dry_run=true`:

```json
// POST /sites/?dry_run=true
{
  "would_create": "api.example.conf",
  "diff": {
    "added_lines": 15,
    "preview": "server {\n  listen 80;\n  server_name api.example.com;\n  ..."
  },
  "validation": {
    "status": "valid",
    "warnings": ["No SSL configured - site will be HTTP-only"]
  },
  "impact": {
    "services_affected": 0,
    "requires_reload": true
  }
}
```

**Rationale**: Agents can preview changes before committing. This enables confident automation and reduces error rates.

### Guided Error Responses

Errors include actionable guidance:

```json
{
  "error": "configuration_invalid",
  "message": "NGINX configuration test failed",
  "details": {
    "line": 12,
    "directive": "proxy_pass",
    "issue": "upstream 'backend' is not defined"
  },
  "suggestions": [
    "Define an upstream block named 'backend'",
    "Or use a direct URL: proxy_pass http://localhost:3000"
  ],
  "related": {
    "existing_upstreams": ["api-servers", "static-cache"],
    "documentation": "/docs#upstream-configuration"
  }
}
```

**Rationale**: Agents shouldn't need to search documentation or make guesses. The API tells them exactly what went wrong and how to fix it.

### MCP-First Design

The Model Context Protocol (MCP) interface is a first-class citizen, not a wrapper:

| MCP Concept | Implementation |
|-------------|----------------|
| **Resources** | Site configs, certificates, system health exposed as readable resources |
| **Tools** | CRUD operations, NGINX control as callable tools |
| **Prompts** | Pre-built workflows: "Setup new site", "Diagnose SSL issue" |

API endpoints are designed to map cleanly to MCP primitives. Response formats are optimized for LLM consumption—structured, predictable, and self-documenting.

---

## Component Details

### API Layer (`api/`)

| Component | Location | Responsibility |
|-----------|----------|----------------|
| Main App | `api/main.py` | FastAPI initialization, lifespan, root endpoints |
| Endpoints | `api/endpoints/` | Route handlers for each resource |
| Models | `api/models/` | Pydantic schemas for request/response validation |
| Core | `api/core/` | Business logic and service implementations |
| Config | `api/config.py` | Environment-based settings management |

### Core Services (`api/core/`)

#### ConfigManager (`config_manager/`)
- **CrossplaneParser** (`crossplane_parser.py`): Full NGINX config parsing via crossplane library
- **Adapter** (`adapter.py`): Converts parsed config to API response format
- **Generator** (planned): Creates NGINX configs from structured data

#### DockerService (`docker_service.py`)
- Docker SDK wrapper for NGINX container management
- Container status, reload, restart operations
- Command execution within containers (`nginx -t`, etc.)

#### HealthChecker (`health_checker.py`)
- HTTP health verification with configurable retries
- Used after reload/restart to verify NGINX is responding

#### CertManager (Phase 3)
- ACME client for Let's Encrypt
- Certificate storage and retrieval
- Renewal scheduling

#### BackupManager (Phase 2)
- Configuration snapshots before changes
- Timestamped backup storage
- Restore operations

### Docker Architecture

```yaml
services:
  api:
    build: docker/api/
    ports: ["8000:8000"]
    volumes:
      - nginx_conf:/etc/nginx/conf.d:ro  # Read configs
      - backups:/var/backups/nginx       # Write backups
      - /var/run/docker.sock:/var/run/docker.sock:ro  # Container control
    depends_on: [nginx]

  nginx:
    build: docker/nginx/
    ports: ["80:80", "443:443"]
    volumes:
      - nginx_conf:/etc/nginx/conf.d     # Serve configs
      - ssl_certs:/etc/ssl/certs         # SSL certificates
```

**Docker Socket**: The API container mounts the Docker socket (read-only) to manage the NGINX container. This enables reload, restart, status checks, and config testing via the Docker SDK.

## Data Flow

### Read Operation (GET /sites/)
```
Client Request
     │
     ▼
FastAPI Endpoint (sites.py)
     │
     ▼
ConfigManager.list_sites()
     │
     ▼
Scan /etc/nginx/conf.d/*.conf
     │
     ▼
Parser.parse_config_file() for each
     │
     ▼
Return SiteConfigResponse[]
```

### Write Operation (POST /sites/) - Phase 2
```
Client Request with SiteConfig
     │
     ▼
FastAPI Endpoint - Validate Pydantic model
     │
     ▼
BackupManager.create_snapshot() if AUTO_BACKUP
     │
     ▼
ConfigManager.generate_config()
     │
     ▼
Write to /etc/nginx/conf.d/{name}.conf
     │
     ▼
ConfigManager.validate() - Run nginx -t
     │
     ├── Failure: Restore backup, return error
     │
     ▼
NGINX.reload() - Graceful reload
     │
     ▼
Return success response
```

## Design Decisions

### Why Crossplane Parser?

**Decision**: Use `crossplane` library for NGINX config parsing.

**Rationale**:
- AI agents require reliable parsing—incorrect data leads to incorrect decisions
- Crossplane is NGINX Inc's official parser with full syntax support
- Handles nested blocks, includes, upstreams, and complex directives
- Parser reliability is a prerequisite for AI trust

**Implementation Details**:
- `crossplane_parser.py` wraps the library with rich data models
- `adapter.py` converts to legacy flat format for backward compatibility
- Uses `check_ctx=False` to parse fragment configs (conf.d files)
- Returns structured `ParsedNginxConfig` with server blocks, locations, upstreams

### Why Separate Containers?

**Decision**: Run API and NGINX in separate containers.

**Rationale**:
- Single responsibility principle
- Independent scaling
- Security isolation (API doesn't need root)
- Easier updates (can update API without touching NGINX)

**Trade-offs**:
- Requires shared volumes
- Inter-container communication overhead
- More complex deployment

### Why File-Based Storage Initially?

**Decision**: Store configurations as files, not in a database.

**Rationale**:
- NGINX configs ARE files - single source of truth
- No sync issues between DB and filesystem
- Simpler backup (just copy files)
- Works with existing NGINX setups

**Trade-offs**:
- Limited querying capability
- No version history (without Git)
- Consider SQLite for metadata in Phase 7

### Why FastAPI?

**Decision**: Use FastAPI over Flask/Django.

**Rationale**:
- Native async support
- Automatic OpenAPI generation (critical for AI agents)
- Pydantic integration for validation
- Modern Python type hints
- Excellent documentation

## Security Considerations

### Current (MVP)
- API exposed only on localhost in production
- No authentication (relies on network security)
- Read-only operations

### Planned (Phase 5)
- API key authentication
- JWT for web dashboard sessions
- Rate limiting
- Audit logging
- Input sanitization for config generation

### Best Practices
- Never expose API directly to internet without auth
- Use reverse proxy (ironically, NGINX) for TLS termination
- Validate all user input before writing configs
- Sanitize server names and paths to prevent injection

## Future Considerations

### Scaling
- Single-server focus for v1.0
- Multi-server support in Phase 7 via SSH
- Consider agent-based architecture for large deployments

### Database Migration
- SQLite for metadata when needed
- Keep file-based configs as source of truth
- DB for search, history, and user data only

### Plugin Architecture
- Consider plugin system for custom validators
- Template marketplace integration
- Webhook notifications
