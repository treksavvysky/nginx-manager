# Authentication System Analysis

An honest assessment of the current auth implementation relative to project maturity and roadmap needs.

## Current State

The auth system (Phases 5 + 6.3) provides:

- **API key auth** with SHA-256 hashed storage (`ngx_` + 64 hex chars)
- **User accounts** with bcrypt password hashing, login with lockout (5 attempts / 30 min)
- **Three-tier RBAC**: admin, operator, viewer
- **JWT sessions** with `jti` tracking, single/bulk revocation
- **TOTP 2FA** with QR enrollment, backup codes, Fernet-encrypted secrets at rest
- **Dashboard cookie auth** (HttpOnly, SameSite=Strict) with two-step 2FA login flow

All behind `AUTH_ENABLED=false` by default.

## What Justifies It

### Phase 9: Multi-Server Management (Future)

This is the real use case. When the system manages multiple remote NGINX instances:

- Multiple operators need scoped access (viewer for monitoring, operator for site changes, admin for server management)
- Session revocation matters when credentials may be shared across teams
- API keys become necessary for CI/CD pipelines deploying to specific servers
- Audit trails (which user changed which server) require authenticated identity

### Phase 8: Observability & Metrics (Future)

- Prometheus `/metrics` endpoint and webhook integrations benefit from auth gating
- However, basic API key auth alone would suffice here

### MCP + GPT Integration (Current)

- MCP server supports API key auth for stdio transport and Bearer tokens for HTTP
- Custom GPT Actions use `X-API-Key` header
- These are the most immediate consumers, but both work fine with a single static API key

## What's Overbuilt for Current Scope

The project currently manages **one local Docker NGINX container** for a single operator. Against that reality:

| Feature | Justified When | Current Need |
|---|---|---|
| Three-tier RBAC | Multiple users with different responsibilities | Single user does everything |
| Account lockout | Internet-exposed login endpoint | Localhost-only or LAN tool |
| TOTP 2FA | Browser-based access by multiple users | Single operator, often via API |
| Session revocation | Shared credentials, compromised tokens | One user, one session |
| Backup codes | Users who lose authenticator access | Single operator manages own 2FA |
| JWT `jti` tracking | Need to invalidate specific sessions | Stateless tokens would suffice |

## The Gap in the Roadmap

Phase 9 mentions the "auth model" will change for multi-server support but doesn't define:

- Per-server or per-group access scoping (can an operator manage server A but not server B?)
- Whether the role hierarchy needs a fourth tier (e.g., server-admin vs global-admin)
- How SSH key credentials for remote servers relate to the existing auth model
- Multi-tenant isolation (if multiple teams share one NGINX Manager instance)

The current auth system was built speculatively for a multi-user future that isn't well-defined yet. It may need restructuring when Phase 9 requirements solidify.

## Recommendations

1. **Keep `AUTH_ENABLED=false` as default** until multi-server or multi-user scenarios are real. The system works well without auth for single-operator use.

2. **Phase 9 planning should define auth scoping** before implementation starts. The current flat role model (admin/operator/viewer applies globally) likely won't survive multi-server requirements unchanged.

3. **API key auth is the most immediately useful piece** — it gates MCP and GPT access without the overhead of user accounts, sessions, and 2FA. Consider documenting a "lightweight auth" setup that uses only API keys.

4. **2FA is genuinely premature** until the dashboard is internet-exposed with multiple user accounts. It adds complexity to the login flow and codebase (TOTP service, session service, challenge tokens, backup codes) for a threat model that doesn't exist yet in single-operator deployments.

5. **The auth code is well-structured** and doesn't impose runtime cost when disabled. The main cost is maintenance surface area — any changes to the database schema, user model, or login flow must account for the 2FA paths.
