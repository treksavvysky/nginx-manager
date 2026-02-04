# MCP Interface Design Document

This document defines the Model Context Protocol (MCP) interface for NGINX Manager, following the MCP specification and AI-native design principles.

## Overview

The MCP server exposes NGINX Manager functionality through three primitives:
- **Resources**: Read-only data endpoints (similar to GET in REST)
- **Tools**: Executable actions with side effects (similar to POST/PUT/DELETE)
- **Prompts**: Reusable templates for common workflows

## Design Principles

1. **Rich Context**: Every response includes full state, not just acknowledgments
2. **Predictive Operations**: Dry-run support for all mutations
3. **Actionable Errors**: Error messages include why it failed and how to fix it
4. **Guided Actions**: Suggestions for logical next steps

---

## Resources

Resources expose read-only data that AI models can fetch for context. Each resource has a URI pattern and returns structured data.

### 1. `nginx://sites`
Lists all site configurations.

**URI**: `nginx://sites`

**Response Schema**:
```json
{
  "sites": [
    {
      "name": "example.com",
      "server_names": ["example.com", "www.example.com"],
      "listen_ports": [80, 443],
      "ssl_enabled": true,
      "site_type": "reverse_proxy",
      "proxy_pass": "http://localhost:3000",
      "enabled": true,
      "status": "valid"
    }
  ],
  "total": 5,
  "enabled_count": 4,
  "ssl_enabled_count": 3
}
```

### 2. `nginx://sites/{name}`
Get detailed configuration for a specific site.

**URI Pattern**: `nginx://sites/{name}`

**Response Schema**:
```json
{
  "name": "example.com",
  "server_names": ["example.com", "www.example.com"],
  "listen_ports": [80, 443],
  "ssl_enabled": true,
  "ssl_config": {
    "certificate": "/etc/ssl/certs/example.com.crt",
    "certificate_key": "/etc/ssl/private/example.com.key",
    "protocols": ["TLSv1.2", "TLSv1.3"]
  },
  "locations": [
    {
      "path": "/",
      "proxy_pass": "http://localhost:3000"
    }
  ],
  "enabled": true,
  "file_path": "/etc/nginx/conf.d/example.com.conf",
  "status": "valid"
}
```

### 3. `nginx://certificates`
Lists all SSL certificates with status.

**URI**: `nginx://certificates`

**Response Schema**:
```json
{
  "certificates": [
    {
      "domain": "example.com",
      "alt_names": ["www.example.com"],
      "type": "letsencrypt",
      "status": "valid",
      "issuer": "Let's Encrypt",
      "not_after": "2026-04-27T00:00:00Z",
      "days_until_expiry": 90,
      "auto_renew": true
    }
  ],
  "total": 3,
  "valid_count": 2,
  "expiring_soon_count": 1,
  "expired_count": 0
}
```

### 4. `nginx://certificates/{domain}`
Get detailed certificate information for a domain.

**URI Pattern**: `nginx://certificates/{domain}`

**Response Schema**:
```json
{
  "domain": "example.com",
  "alt_names": ["www.example.com"],
  "type": "letsencrypt",
  "status": "valid",
  "issuer": "Let's Encrypt",
  "serial_number": "04:AB:CD:...",
  "not_before": "2026-01-27T00:00:00Z",
  "not_after": "2026-04-27T00:00:00Z",
  "days_until_expiry": 90,
  "fingerprint_sha256": "AB:CD:EF:...",
  "cert_path": "/etc/ssl/certs/example.com.crt",
  "key_path": "/etc/ssl/private/example.com.key",
  "auto_renew": true,
  "last_renewed": "2026-01-27T00:00:00Z"
}
```

### 5. `nginx://health`
System health and status summary.

**URI**: `nginx://health`

**Response Schema**:
```json
{
  "status": "healthy",
  "nginx": {
    "status": "running",
    "container_id": "abc123...",
    "uptime_seconds": 86400,
    "worker_count": 4,
    "active_connections": 12,
    "config_valid": true
  },
  "sites": {
    "total": 5,
    "enabled": 4,
    "with_ssl": 3
  },
  "certificates": {
    "total": 3,
    "valid": 2,
    "expiring_soon": 1,
    "expired": 0
  },
  "recent_events": {
    "errors": 0,
    "warnings": 2
  }
}
```

### 6. `nginx://events`
Recent system events (last 24 hours by default).

**URI**: `nginx://events`
**URI with filter**: `nginx://events?severity=error&limit=50`

**Response Schema**:
```json
{
  "events": [
    {
      "id": "evt_123",
      "timestamp": "2026-01-27T10:30:00Z",
      "severity": "info",
      "category": "transaction",
      "action": "site_create",
      "resource_type": "site",
      "resource_id": "example.com",
      "message": "Created site example.com"
    }
  ],
  "total": 25
}
```

### 7. `nginx://transactions`
Recent transactions with rollback capability.

**URI**: `nginx://transactions`
**URI with filter**: `nginx://transactions?status=completed&limit=10`

**Response Schema**:
```json
{
  "transactions": [
    {
      "id": "txn_abc123",
      "operation": "site_create",
      "status": "completed",
      "resource_type": "site",
      "resource_id": "example.com",
      "created_at": "2026-01-27T10:30:00Z",
      "duration_ms": 450,
      "can_rollback": true
    }
  ],
  "total": 15
}
```

### 8. `nginx://transactions/{id}`
Detailed transaction information with diff.

**URI Pattern**: `nginx://transactions/{id}`

**Response Schema**:
```json
{
  "id": "txn_abc123",
  "operation": "site_update",
  "status": "completed",
  "resource_type": "site",
  "resource_id": "example.com",
  "created_at": "2026-01-27T10:30:00Z",
  "completed_at": "2026-01-27T10:30:01Z",
  "duration_ms": 450,
  "diff": {
    "files_changed": 1,
    "total_additions": 5,
    "total_deletions": 3
  },
  "can_rollback": true,
  "rollback_reason": null
}
```

---

## Tools

Tools enable AI models to perform actions. All mutation tools support `dry_run` parameter.

### Site Management

#### `create_site`
Create a new NGINX site configuration.

**Input Schema**:
```json
{
  "type": "object",
  "properties": {
    "name": {
      "type": "string",
      "description": "Site name (used as filename and identifier)"
    },
    "server_names": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Domain names for this site"
    },
    "site_type": {
      "type": "string",
      "enum": ["static", "reverse_proxy"],
      "description": "Type of site configuration"
    },
    "listen_port": {
      "type": "integer",
      "default": 80,
      "description": "Port to listen on"
    },
    "root_path": {
      "type": "string",
      "description": "Document root for static sites"
    },
    "proxy_pass": {
      "type": "string",
      "description": "Backend URL for reverse proxy sites"
    },
    "auto_reload": {
      "type": "boolean",
      "default": true,
      "description": "Reload NGINX after creating site"
    },
    "dry_run": {
      "type": "boolean",
      "default": false,
      "description": "Preview changes without applying"
    }
  },
  "required": ["name", "server_names", "site_type"]
}
```

**Output Schema**:
```json
{
  "type": "object",
  "properties": {
    "success": { "type": "boolean" },
    "message": { "type": "string" },
    "site_name": { "type": "string" },
    "transaction_id": { "type": "string" },
    "file_path": { "type": "string" },
    "reload_required": { "type": "boolean" },
    "reloaded": { "type": "boolean" },
    "suggestions": {
      "type": "array",
      "items": { "type": "string" }
    },
    "warnings": {
      "type": "array",
      "items": { "type": "string" }
    }
  }
}
```

#### `update_site`
Update an existing site configuration.

**Input Schema**:
```json
{
  "type": "object",
  "properties": {
    "name": {
      "type": "string",
      "description": "Site name to update"
    },
    "server_names": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Updated domain names"
    },
    "listen_port": {
      "type": "integer",
      "description": "Updated listen port"
    },
    "root_path": {
      "type": "string",
      "description": "Updated document root"
    },
    "proxy_pass": {
      "type": "string",
      "description": "Updated backend URL"
    },
    "auto_reload": {
      "type": "boolean",
      "default": true
    },
    "dry_run": {
      "type": "boolean",
      "default": false
    }
  },
  "required": ["name"]
}
```

#### `delete_site`
Delete a site configuration.

**Input Schema**:
```json
{
  "type": "object",
  "properties": {
    "name": {
      "type": "string",
      "description": "Site name to delete"
    },
    "auto_reload": {
      "type": "boolean",
      "default": true
    },
    "dry_run": {
      "type": "boolean",
      "default": false
    }
  },
  "required": ["name"]
}
```

#### `enable_site`
Enable a disabled site.

**Input Schema**:
```json
{
  "type": "object",
  "properties": {
    "name": {
      "type": "string",
      "description": "Site name to enable"
    },
    "auto_reload": {
      "type": "boolean",
      "default": true
    },
    "dry_run": {
      "type": "boolean",
      "default": false
    }
  },
  "required": ["name"]
}
```

#### `disable_site`
Disable a site without deleting it.

**Input Schema**:
```json
{
  "type": "object",
  "properties": {
    "name": {
      "type": "string",
      "description": "Site name to disable"
    },
    "auto_reload": {
      "type": "boolean",
      "default": true
    },
    "dry_run": {
      "type": "boolean",
      "default": false
    }
  },
  "required": ["name"]
}
```

### NGINX Control

#### `nginx_reload`
Gracefully reload NGINX configuration.

**Input Schema**:
```json
{
  "type": "object",
  "properties": {
    "dry_run": {
      "type": "boolean",
      "default": false,
      "description": "Preview what would happen"
    }
  },
  "additionalProperties": false
}
```

**Output Schema**:
```json
{
  "type": "object",
  "properties": {
    "success": { "type": "boolean" },
    "operation": { "type": "string" },
    "message": { "type": "string" },
    "duration_ms": { "type": "number" },
    "health_verified": { "type": "boolean" },
    "transaction_id": { "type": "string" },
    "auto_rolled_back": { "type": "boolean" },
    "suggestions": {
      "type": "array",
      "items": { "type": "string" }
    }
  }
}
```

#### `nginx_restart`
Full NGINX container restart (disruptive).

**Input Schema**:
```json
{
  "type": "object",
  "properties": {
    "dry_run": {
      "type": "boolean",
      "default": false
    }
  },
  "additionalProperties": false
}
```

#### `nginx_test`
Validate NGINX configuration without applying.

**Input Schema**:
```json
{
  "type": "object",
  "additionalProperties": false
}
```

**Output Schema**:
```json
{
  "type": "object",
  "properties": {
    "success": { "type": "boolean" },
    "message": { "type": "string" },
    "stdout": { "type": "string" },
    "stderr": { "type": "string" },
    "tested_at": { "type": "string", "format": "date-time" }
  }
}
```

### Certificate Management

#### `request_certificate`
Request a Let's Encrypt SSL certificate.

**Input Schema**:
```json
{
  "type": "object",
  "properties": {
    "domain": {
      "type": "string",
      "description": "Primary domain for the certificate"
    },
    "alt_names": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Additional domain names (SANs)"
    },
    "auto_renew": {
      "type": "boolean",
      "default": true,
      "description": "Enable automatic renewal"
    },
    "auto_reload": {
      "type": "boolean",
      "default": true,
      "description": "Reload NGINX after installation"
    },
    "dry_run": {
      "type": "boolean",
      "default": false,
      "description": "Check prerequisites without requesting"
    }
  },
  "required": ["domain"]
}
```

**Output Schema**:
```json
{
  "type": "object",
  "properties": {
    "success": { "type": "boolean" },
    "message": { "type": "string" },
    "domain": { "type": "string" },
    "transaction_id": { "type": "string" },
    "certificate": {
      "type": "object",
      "properties": {
        "domain": { "type": "string" },
        "status": { "type": "string" },
        "not_after": { "type": "string", "format": "date-time" },
        "days_until_expiry": { "type": "integer" }
      }
    },
    "suggestions": {
      "type": "array",
      "items": { "type": "string" }
    },
    "warnings": {
      "type": "array",
      "items": { "type": "string" }
    }
  }
}
```

#### `upload_certificate`
Upload a custom SSL certificate.

**Input Schema**:
```json
{
  "type": "object",
  "properties": {
    "domain": {
      "type": "string",
      "description": "Domain for the certificate"
    },
    "certificate_pem": {
      "type": "string",
      "description": "Certificate in PEM format"
    },
    "private_key_pem": {
      "type": "string",
      "description": "Private key in PEM format"
    },
    "chain_pem": {
      "type": "string",
      "description": "Optional certificate chain in PEM format"
    },
    "auto_reload": {
      "type": "boolean",
      "default": true
    },
    "dry_run": {
      "type": "boolean",
      "default": false
    }
  },
  "required": ["domain", "certificate_pem", "private_key_pem"]
}
```

#### `renew_certificate`
Manually trigger certificate renewal.

**Input Schema**:
```json
{
  "type": "object",
  "properties": {
    "domain": {
      "type": "string",
      "description": "Domain to renew"
    },
    "force": {
      "type": "boolean",
      "default": false,
      "description": "Force renewal even if not expiring soon"
    },
    "auto_reload": {
      "type": "boolean",
      "default": true
    },
    "dry_run": {
      "type": "boolean",
      "default": false
    }
  },
  "required": ["domain"]
}
```

#### `revoke_certificate`
Revoke and remove a certificate.

**Input Schema**:
```json
{
  "type": "object",
  "properties": {
    "domain": {
      "type": "string",
      "description": "Domain to revoke certificate for"
    },
    "auto_reload": {
      "type": "boolean",
      "default": true
    },
    "dry_run": {
      "type": "boolean",
      "default": false
    }
  },
  "required": ["domain"]
}
```

#### `diagnose_ssl`
Run comprehensive SSL diagnostic.

**Input Schema**:
```json
{
  "type": "object",
  "properties": {
    "domain": {
      "type": "string",
      "description": "Domain to diagnose"
    }
  },
  "required": ["domain"]
}
```

**Output Schema**:
```json
{
  "type": "object",
  "properties": {
    "domain": { "type": "string" },
    "dns_resolves": { "type": "boolean" },
    "dns_ip_addresses": {
      "type": "array",
      "items": { "type": "string" }
    },
    "points_to_this_server": { "type": "boolean" },
    "port_80_open": { "type": "boolean" },
    "port_443_open": { "type": "boolean" },
    "has_certificate": { "type": "boolean" },
    "certificate_valid": { "type": "boolean" },
    "certificate_expiry": { "type": "string", "format": "date-time" },
    "chain_valid": { "type": "boolean" },
    "ready_for_ssl": { "type": "boolean" },
    "issues": {
      "type": "array",
      "items": { "type": "string" }
    },
    "suggestions": {
      "type": "array",
      "items": { "type": "string" }
    }
  }
}
```

### Transaction Management

#### `rollback_transaction`
Rollback a transaction to restore previous state.

**Input Schema**:
```json
{
  "type": "object",
  "properties": {
    "transaction_id": {
      "type": "string",
      "description": "Transaction ID to rollback"
    },
    "reason": {
      "type": "string",
      "description": "Reason for rollback"
    }
  },
  "required": ["transaction_id"]
}
```

**Output Schema**:
```json
{
  "type": "object",
  "properties": {
    "success": { "type": "boolean" },
    "rollback_transaction_id": { "type": "string" },
    "original_transaction_id": { "type": "string" },
    "message": { "type": "string" },
    "warnings": {
      "type": "array",
      "items": { "type": "string" }
    }
  }
}
```

---

## Prompts

Prompts provide reusable templates for common workflows, helping AI models understand context and execute multi-step operations.

### `setup_new_site`
Guide for setting up a new website.

**Arguments**:
```json
{
  "domain": {
    "type": "string",
    "description": "Primary domain name",
    "required": true
  },
  "site_type": {
    "type": "string",
    "enum": ["static", "reverse_proxy"],
    "description": "Type of site",
    "required": true
  },
  "with_ssl": {
    "type": "boolean",
    "description": "Request SSL certificate",
    "default": true
  }
}
```

**Template**:
```
You are setting up a new website for domain: {domain}

Site type: {site_type}
SSL enabled: {with_ssl}

## Steps to complete:

1. First, check current system health using the `nginx://health` resource
2. Create the site configuration using `create_site` tool with dry_run=true to preview
3. If preview looks correct, create the site with dry_run=false
4. If SSL is requested:
   - Run `diagnose_ssl` to check prerequisites
   - If ready, use `request_certificate` to obtain SSL certificate
   - Update site configuration to use SSL
5. Verify the site is working by checking the site resource

## Important considerations:
- Ensure DNS is properly configured before requesting SSL
- Use dry-run mode to preview all changes before applying
- Keep track of transaction IDs for potential rollback
```

### `add_ssl_to_site`
Guide for adding SSL to an existing site.

**Arguments**:
```json
{
  "domain": {
    "type": "string",
    "description": "Domain to add SSL to",
    "required": true
  },
  "certificate_type": {
    "type": "string",
    "enum": ["letsencrypt", "custom"],
    "description": "Type of certificate",
    "default": "letsencrypt"
  }
}
```

**Template**:
```
You are adding SSL to: {domain}

Certificate type: {certificate_type}

## Steps to complete:

1. Check the site exists using `nginx://sites/{domain}` resource
2. Run `diagnose_ssl` to check SSL readiness:
   - DNS must resolve to this server
   - Port 80 must be accessible for HTTP-01 challenge
3. If using Let's Encrypt:
   - Use `request_certificate` with dry_run=true first
   - If checks pass, request the certificate
4. If using custom certificate:
   - Use `upload_certificate` with the PEM data
5. Verify certificate status using `nginx://certificates/{domain}`

## Common issues:
- DNS not pointing to server: Update DNS A/AAAA records
- Port 80 blocked: Ensure firewall allows HTTP traffic
- Rate limits: Use staging environment for testing
```

### `check_expiring_certificates`
Guide for managing certificate renewals.

**Arguments**:
```json
{
  "days_threshold": {
    "type": "integer",
    "description": "Days until expiry to consider 'expiring soon'",
    "default": 30
  }
}
```

**Template**:
```
Checking for certificates expiring within {days_threshold} days.

## Steps:

1. Fetch all certificates using `nginx://certificates` resource
2. Filter certificates where days_until_expiry <= {days_threshold}
3. For each expiring certificate:
   - If auto_renew is enabled, check for renewal errors
   - If auto_renew is disabled, recommend manual renewal
   - Use `renew_certificate` with dry_run=true to test renewal
4. Report findings with renewal recommendations

## Auto-renewal considerations:
- Certificates set to auto_renew will be renewed automatically
- Check recent events for renewal failures
- Manual intervention may be needed if DNS changed
```

### `diagnose_connectivity`
Guide for troubleshooting site connectivity issues.

**Arguments**:
```json
{
  "domain": {
    "type": "string",
    "description": "Domain experiencing issues",
    "required": true
  }
}
```

**Template**:
```
Diagnosing connectivity issues for: {domain}

## Diagnostic steps:

1. Check system health: `nginx://health`
   - Is NGINX running?
   - Is the configuration valid?

2. Check site configuration: `nginx://sites/{domain}`
   - Is the site enabled?
   - Are server_names correct?
   - Is the backend (proxy_pass) configured correctly?

3. Check SSL status: `diagnose_ssl`
   - Does DNS resolve correctly?
   - Is the certificate valid?
   - Is the certificate chain complete?

4. Check recent events: `nginx://events?severity=error`
   - Any recent errors for this site?
   - Any failed operations?

5. Test NGINX configuration: `nginx_test`
   - Are there syntax errors?

## Common solutions:
- DNS issues: Update A/AAAA records, wait for propagation
- Certificate expired: Renew with `renew_certificate`
- Config invalid: Check error messages, rollback if needed
- Backend down: Check upstream service, update proxy_pass
```

### `rollback_changes`
Guide for safely rolling back problematic changes.

**Arguments**:
```json
{
  "resource": {
    "type": "string",
    "description": "Resource that has issues (e.g., site name)",
    "required": false
  }
}
```

**Template**:
```
Rolling back recent changes{resource ? " for " + resource : ""}.

## Steps:

1. Check recent transactions: `nginx://transactions`
   - Find transactions related to the issue
   - Note transaction IDs

2. For each candidate transaction:
   - Get details: `nginx://transactions/{id}`
   - Check `can_rollback` status
   - Review the diff to understand what changed

3. Rollback the problematic transaction:
   - Use `rollback_transaction` with the transaction_id
   - Provide a reason for audit purposes

4. Verify the rollback:
   - Check system health
   - Test affected services
   - Review new transaction created by rollback

## Important notes:
- Rollbacks create new transactions (can be rolled back themselves)
- Some operations may not be rollbackable
- Check `rollback_reason` if rollback is unavailable
```

---

## API-to-MCP Mapping

| REST Endpoint | MCP Primitive | MCP Name |
|---------------|---------------|----------|
| `GET /sites/` | Resource | `nginx://sites` |
| `GET /sites/{name}` | Resource | `nginx://sites/{name}` |
| `POST /sites/` | Tool | `create_site` |
| `PUT /sites/{name}` | Tool | `update_site` |
| `DELETE /sites/{name}` | Tool | `delete_site` |
| `POST /sites/{name}/enable` | Tool | `enable_site` |
| `POST /sites/{name}/disable` | Tool | `disable_site` |
| `GET /nginx/status` | Resource | `nginx://health` |
| `POST /nginx/reload` | Tool | `nginx_reload` |
| `POST /nginx/restart` | Tool | `nginx_restart` |
| `POST /nginx/test` | Tool | `nginx_test` |
| `GET /certificates/` | Resource | `nginx://certificates` |
| `GET /certificates/{domain}` | Resource | `nginx://certificates/{domain}` |
| `POST /certificates/` | Tool | `request_certificate` |
| `POST /certificates/upload` | Tool | `upload_certificate` |
| `POST /certificates/{domain}/renew` | Tool | `renew_certificate` |
| `DELETE /certificates/{domain}` | Tool | `revoke_certificate` |
| `GET /certificates/{domain}/check` | Tool | `diagnose_ssl` |
| `GET /events/` | Resource | `nginx://events` |
| `GET /transactions/` | Resource | `nginx://transactions` |
| `GET /transactions/{id}` | Resource | `nginx://transactions/{id}` |
| `POST /transactions/{id}/rollback` | Tool | `rollback_transaction` |
| `GET /health` | Resource | `nginx://health` |

---

## Response Format Optimization

### For Claude Consumption

All MCP responses are optimized for AI consumption:

1. **Structured Data**: JSON with consistent field names
2. **Rich Context**: Include related information proactively
3. **Actionable Guidance**: `suggestions` array with next steps
4. **Warnings**: `warnings` array for non-blocking issues
5. **Error Details**: When errors occur, include:
   - What went wrong
   - Why it happened
   - How to fix it
   - Related context

### Example Optimized Response

```json
{
  "success": true,
  "message": "Site example.com created successfully",
  "site_name": "example.com",
  "transaction_id": "txn_abc123",
  "file_path": "/etc/nginx/conf.d/example.com.conf",
  "reload_required": true,
  "reloaded": true,
  "suggestions": [
    "Request SSL certificate with: request_certificate(domain='example.com')",
    "Test site accessibility at http://example.com",
    "View site details with resource: nginx://sites/example.com"
  ],
  "warnings": [
    "No SSL configured - site is HTTP only",
    "DNS not yet verified - ensure example.com points to this server"
  ]
}
```

---

## Security Considerations

1. **Input Validation**: All tool inputs validated against schemas
2. **Dry-Run Mode**: Preview changes before applying
3. **Transaction Audit**: All changes logged with transaction IDs
4. **Rollback Capability**: Restore previous state if issues occur
5. **Rate Limiting**: Applied at the REST API layer
6. **Human-in-the-Loop**: Clients should confirm sensitive operations

---

## Implementation Notes

### Transport

The MCP server will support:
- **stdio**: For local CLI integration
- **Streamable HTTP**: For remote connections (requires authentication in production)

### Dependencies

- `mcp` Python SDK for protocol implementation
- Reuse existing FastAPI services (no duplication)
- Async operations throughout

### File Structure

```
api/
├── mcp_server/
│   ├── __init__.py
│   ├── server.py          # MCP server setup
│   ├── resources.py       # Resource handlers
│   ├── tools.py           # Tool handlers
│   └── prompts.py         # Prompt templates

Note: Package named `mcp_server` to avoid conflicts with the official `mcp` SDK.
```
