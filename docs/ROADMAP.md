# NGINX Manager Development Roadmap

This document outlines the development plan for NGINX Manager, an AI-agent-first platform for managing NGINX configurations, inspired by tools like Dokploy but focused on reverse proxy and SSL management.

## Vision

A self-hosted NGINX management platform that provides:
- **AI-First API**: Optimized for LLM agents (Claude MCP, Custom GPTs, LangChain)
- **Human-Friendly UI**: Web dashboard for manual management
- **Zero-Downtime Operations**: Safe configuration changes with validation and rollback
- **Automated SSL**: Let's Encrypt integration with auto-renewal

### AI-Native Design Principles

The following principles guide all development decisions:

- **Rich Context**: Every response includes full state, not just acknowledgments. When an operation completes, return what changed, what's now active, and what the agent should consider next.

- **Predictive Operations**: Dry-run/preview for all mutations. Before any change takes effect, agents can see exactly what will happen, including diffs and potential issues.

- **Transaction Model**: All changes are atomic with rollback capability. Every mutation creates a checkpoint, and the system can always return to a known-good state.

- **Guided Actions**: Suggest next steps, don't just report errors. When something fails, explain why and how to fix it. When something succeeds, suggest logical follow-up actions.

- **MCP-First Design**: Design for Claude MCP natively, not as a REST wrapper. The MCP interface influences API design decisions, not the other way around.

---

## Phase 1: MVP Foundation (Current)

**Status: Complete**

### Completed Features
- [x] FastAPI application structure
- [x] Docker containerization (API + NGINX)
- [x] Development and production deployment scripts
- [x] NGINX configuration parser (regex-based)
- [x] Read-only API endpoints (`GET /sites/`, `GET /sites/{name}`)
- [x] Health check endpoints
- [x] OpenAPI documentation (Swagger/ReDoc)
- [x] Pydantic models for configuration validation

### Known Limitations
- Read-only operations only
- No authentication
- Limited NGINX directive parsing (regex-based)
- File-based storage only

---

## Phase 2: AI-Native Core

**Status: Complete**

This phase establishes the foundation for reliable AI agent interaction. The parser upgrade is a prerequisite—AI agents cannot trust a system that misparses configurations. The transaction model and rich context patterns must be in place before adding more operations.

### 2.1 Parser Upgrade (Foundation)
- [x] Replace regex parser with `crossplane` library
- [x] Full directive support including nested blocks
- [x] Upstream block parsing
- [x] Location block parsing with regex support
- [x] Rich data models (ServerBlock, LocationBlock, UpstreamBlock, SSLConfig)
- [x] Backward-compatible adapter for legacy response format
- [x] Include file resolution (`include` directives with glob support)
- [x] Map and geo directive parsing (MapBlock, GeoBlock models)

**Rationale**: Reliable parsing is a prerequisite for AI trust. An agent that sees incorrect configuration data will make incorrect decisions. This is not optional cleanup—it's foundational.

### 2.2 Transaction & Event Model
- [x] Every change creates a transaction with before/after state
- [x] Automatic snapshots before any mutation
- [x] `POST /transactions/{id}/rollback` - Restore to checkpoint
- [x] `GET /events/` - Recent changes with full context
- [x] `GET /events/{id}` - Detailed event information
- [x] `GET /transactions/` - List transactions with filtering
- [x] `GET /transactions/{id}` - Transaction details with diff
- [x] Configurable retention policy for transaction history

### 2.3 Rich Context Responses
- [x] All responses include current system state summary
- [x] Mutation responses return: what changed, what's now active, suggested next steps
- [x] Error responses include: why it failed, how to fix it, related context
- [x] `suggestions` field in all responses with contextual guidance
- [x] `warnings` field for non-blocking issues (e.g., "SSL cert expires in 7 days")

### 2.4 Predictive Operations
- [x] `?dry_run=true` query parameter on all mutation endpoints
- [x] Diff output showing before/after for config changes
- [x] Validation warnings (not just errors) in dry-run responses
- [ ] Confidence indicators for complex operations
- [x] Impact analysis: what services/sites will be affected

### 2.5 Site CRUD (with AI Patterns)
- [x] `POST /sites/` - Create new site configuration (static or reverse_proxy)
- [x] `PUT /sites/{name}` - Update existing site
- [x] `DELETE /sites/{name}` - Remove site configuration
- [x] `POST /sites/{name}/enable` - Enable site (file rename .conf.disabled -> .conf)
- [x] `POST /sites/{name}/disable` - Disable site without deletion
- [x] All responses include transaction IDs for rollback
- [x] Jinja2-based config generation from templates
- [x] Config validation with nginx -t before deployment
- [ ] Suggested actions in every response

### 2.6 NGINX Control
- [x] `POST /nginx/reload` - Graceful reload with health verification
- [x] `POST /nginx/restart` - Full restart with health verification
- [x] `GET /nginx/status` - Container status, uptime, health info
- [x] `POST /nginx/test` - Validate all configurations with `nginx -t`
- [x] Docker SDK integration for container management
- [x] Health checker with configurable retries
- [x] Automatic rollback if reload fails health check

### 2.7 MCP Interface Design (Design Only)
- [x] Define MCP resources schema (site configs, system health)
- [x] Define MCP tools schema (all CRUD operations)
- [x] Define MCP prompts ("Setup new site", "Diagnose issue")
- [x] Document API-to-MCP mapping for each endpoint
- [x] Design response formats optimized for Claude consumption
- [x] Create MCP design document

**Note**: Design document created at `docs/MCP_DESIGN.md`. Implementation completed in Phase 3.5.

---

## Phase 3: SSL + MCP Implementation

**Status: Complete**

SSL certificate management and MCP server are fully implemented.

### 3.1 SSL Certificate Management
- [x] `POST /certificates/` - Request new certificate (Let's Encrypt)
- [x] `GET /certificates/` - List all certificates with status
- [x] `GET /certificates/{domain}` - Certificate details, expiry, chain info
- [x] `DELETE /certificates/{domain}` - Revoke and remove
- [x] `POST /certificates/{domain}/renew` - Manual renewal trigger

### 3.2 Automated SSL (ACME)
- [x] ACME HTTP-01 challenge support
- [x] Auto-renewal scheduler (background task)
- [x] Expiry warnings in API responses and events
- [x] Certificate health monitoring
- [x] Automatic NGINX reload after renewal

### 3.3 Rich SSL Context
- [x] Certificate status included in site responses
- [x] DNS verification helpers ("your domain doesn't resolve to this server")
- [x] Suggested actions for SSL issues
- [x] `GET /certificates/{domain}/check` - Full SSL diagnostic
- [x] Chain validation and warnings

### 3.4 Custom Certificates
- [x] Upload custom SSL certificates
- [x] Certificate chain validation
- [x] Private key security (encrypted storage) — implemented in Phase 5
- [x] Expiry tracking for custom certs

### 3.5 MCP Server Implementation
- [x] MCP protocol implementation based on Phase 2 design
- [x] **Resources**: Site configs, certificate status, system health, event log
- [x] **Tools**: All CRUD operations, SSL management, NGINX control
- [x] **Prompts**: "Setup new site", "Add SSL to site", "Check expiring certs", "Diagnose connectivity"
- [x] MCP-optimized response formats
- [x] MCP server deployment documentation

**Implementation**: MCP server located in `api/mcp_server/`. See `docs/MCP_DEPLOYMENT.md` for usage.

---

## Phase 4: GPT Integration + Agent Workflows

**Status: Complete**

Complete AI agent integration with support for complex multi-step operations.

### 4.1 OpenAI Custom GPT
- [x] Actions schema from OpenAPI spec
- [x] Optimized response formats for GPT consumption
- [x] Authentication flow for Custom GPTs (API Key placeholder for Phase 5)
- [x] GPT-specific prompt templates
- [x] Example GPT configuration and instructions

### 4.2 Agent Workflows (Compound Operations)
- [x] `POST /workflows/setup-site` - Create site + request cert + enable + reload
- [x] `POST /workflows/migrate-site` - Backup + update + test + rollback on failure
- [x] Checkpoint-based execution with rollback points
- [x] Progress streaming for long operations (SSE)
- [x] Workflow templates for common patterns

### 4.3 Testing & Documentation
- [x] Agent integration tutorials (MCP and GPT)
- [x] Example conversations/workflows
- [x] Error handling patterns for AI agents
- [x] Best practices guide for AI integration
- [x] Testing harness for agent interactions

**Implementation**: Workflow engine in `api/core/workflow_engine.py`, GPT schema at `GET /gpt/openapi.json`. See `docs/GPT_INTEGRATION.md` and `docs/AGENT_WORKFLOWS.md`.

---

## Phase 5: Authentication & Security

**Status: Complete**

Full authentication, authorization, and security hardening. Backward-compatible: `AUTH_ENABLED=false` (default) preserves existing behavior.

### 5.1 API Authentication
- [x] API key authentication (`X-API-Key` header, SHA-256 hashed storage)
- [x] JWT token support for sessions (`Authorization: Bearer` header)
- [x] Token exchange (API key -> JWT) and refresh
- [x] Rate limiting per client (slowapi, in-memory, IP+identity keying)
- [x] Request logging and audit trail (client_ip, user_id, api_key_id on events)
- [x] Bootstrap endpoint for initial admin key setup

### 5.2 User Management
- [x] User accounts with roles (admin, operator, viewer)
- [x] Username/password login with JWT token issuance
- [x] bcrypt password hashing
- [x] Password policies (min 12 chars, mixed case + digit)
- [x] Account lockout after 5 failed attempts (30 min)
- [x] User CRUD (create, list, get, update, delete)
- [x] Password change (self + admin reset)
- [ ] Optional 2FA (deferred to 5.2b)

### 5.3 Security Hardening
- [x] Input sanitization for config generation (NGINX directive injection prevention)
- [x] SSRF prevention in proxy_pass validation (cloud metadata endpoint blocking)
- [x] Private key encryption at rest (Fernet/AES, PBKDF2 key derivation)
- [x] Security headers on API responses (X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, Cache-Control)
- [x] CORS tightening (wildcard only in debug mode, configurable origins)
- [x] MCP authentication integration (API key for stdio, Bearer for HTTP)
- [x] Security warnings in `/health` endpoint (auth, CORS, encryption, debug mode, JWT secret)
- [x] Role-based access control on all endpoints (VIEWER/OPERATOR/ADMIN hierarchy)

**Implementation**: Auth service in `api/core/auth_service.py`, user service in `api/core/user_service.py`, auth dependency in `api/core/auth_dependency.py`. Endpoints at `/auth/*`.

---

## Phase 6: Web Dashboard

**Status: Planned**

Dashboard is lowest priority for an AI-first tool—but valuable for monitoring and manual intervention.

### 6.1 Core UI
- [ ] Site list view with status indicators
- [ ] Site detail/edit forms
- [ ] Configuration syntax highlighting
- [ ] Real-time validation feedback

### 6.2 Dashboard Features
- [ ] System health overview
- [ ] Certificate expiry calendar
- [ ] Event/transaction log viewer
- [ ] Quick actions (reload, backup, etc.)

### 6.3 Technology Choice
- **Option A**: HTMX + Alpine.js (lightweight, server-rendered)
- **Option B**: React/Vue SPA (richer interactivity)
- **Recommendation**: Start with HTMX for simplicity, migrate if needed

---

## Phase 7: Advanced Features

**Status: Future**

### 7.1 Templates & Presets
- [ ] Built-in templates (static site, reverse proxy, load balancer)
- [ ] Custom template creation
- [ ] Variable substitution in templates
- [ ] Template marketplace/sharing

### 7.2 Monitoring & Metrics
- [ ] NGINX access log parsing
- [ ] Request rate and error tracking
- [ ] Upstream health monitoring
- [ ] Prometheus metrics endpoint

### 7.3 Multi-Server Support
- [ ] Remote NGINX server management
- [ ] SSH-based configuration deployment
- [ ] Centralized dashboard for multiple servers
- [ ] Configuration sync across servers

### 7.4 Database Backend
- [ ] SQLite for metadata storage
- [ ] Configuration version history
- [ ] Search and filtering capabilities
- [ ] Migration from file-based storage

---

## Testing Strategy

### Unit Tests
- [x] Parser tests with complex NGINX configs (35 tests: core, map, geo, include resolution)
- [x] NGINX endpoint tests with mocked Docker service (16 tests)
- [x] Transaction model and snapshot service tests (18 tests)
- [x] Config generator tests (14 tests)
- [x] Context helper tests (24 tests)
- [x] Dry-run mode tests (12 tests)
- [x] Certificate model tests (28 tests)
- [x] Certificate context helper tests (15 tests)
- [x] Certificate manager tests (15 tests)
- [x] Workflow engine tests (26 tests)
- [x] Workflow model tests (29 tests)
- [x] GPT schema generation tests (18 tests)
- [x] Authentication and auth dependency tests (23 tests)
- [x] JWT token tests (19 tests)
- [x] Input sanitization tests (27 tests)
- [x] Security headers tests (11 tests)
- [x] Rate limiting tests (11 tests)
- [x] Security suggestions tests (14 tests)
- [x] Encryption service tests (12 tests)
- [x] User service tests (24 tests)
- [x] User endpoint/model tests (25 tests)
- [x] Total: 420 unit tests

### Integration Tests
- [x] API endpoint tests with actual NGINX container
- [x] SSL workflow tests with production Let's Encrypt
- [ ] MCP protocol compliance tests

### Agent Tests
- [ ] Simulated agent conversation flows
- [ ] Error recovery scenarios
- [ ] Multi-step workflow tests

### CI/CD
- [ ] GitHub Actions pipeline
- [ ] Automated testing on PR
- [ ] Container image builds
- [ ] Staging deployment

---

## Release Milestones

| Version | Phase | Key Features |
|---------|-------|--------------|
| v0.1.0 | 1 | MVP read-only API (current) |
| v0.2.0 | 2 | AI-native core: transactions, rich context, reliable parser, CRUD, MCP design |
| v0.3.0 | 3 | SSL management + MCP server implementation |
| v0.4.0 | 4 | GPT integration + agent workflows |
| v0.5.0 | 5 | Authentication & security |
| v0.6.0 | 6 | Web dashboard |
| v1.0.0 | 7 | Multi-server, monitoring, production hardening |

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for development setup and contribution guidelines.

## Architecture Decisions

See [ARCHITECTURE.md](./ARCHITECTURE.md) for detailed technical decisions and rationale.
