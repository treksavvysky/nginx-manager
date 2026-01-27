# API Reference

This document provides detailed API documentation for NGINX Manager.

## Base URL

- **Development**: `http://localhost:8000`
- **Production**: `http://127.0.0.1:8000` (localhost only)

## Authentication

**Current Status**: No authentication (MVP)

**Planned (Phase 4)**:
- API Key via `X-API-Key` header
- JWT Bearer token for web dashboard

## Endpoints

### Health & Status

#### GET /
Returns API information and available features.

**Response**:
```json
{
  "message": "🎯 NGINX Manager API is running",
  "version": "0.1.0",
  "status": "healthy",
  "timestamp": "2026-01-26T12:00:00.000000",
  "docs_url": "/docs",
  "openapi_url": "/openapi.json",
  "features": [
    "Configuration Management",
    "SSL Certificate Lifecycle",
    "Reverse Proxy Setup"
  ]
}
```

#### GET /health
Health check endpoint for monitoring and orchestration. Shows real-time NGINX container status.

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2026-01-27T00:35:42.452815",
  "api": {
    "status": "running",
    "version": "0.1.0"
  },
  "nginx": {
    "status": "running",
    "container_id": "f8d9f425c91a",
    "uptime_seconds": 5547,
    "health_status": "healthy"
  },
  "ssl": {
    "status": "not_configured",
    "message": "SSL management not yet implemented"
  }
}
```

---

### Sites

#### GET /sites/
List all site configurations.

**Response** (returns array directly):
```json
[
  {
    "name": "example.com",
    "server_name": "example.com www.example.com",
    "listen_ports": [80],
    "ssl_enabled": false,
    "root_path": "/var/www/example",
    "proxy_pass": null,
    "has_ssl_cert": false,
    "status": "untested",
    "file_path": "/etc/nginx/conf.d/example.com.conf",
    "file_size": 189,
    "created_at": "2026-01-20T19:06:27.322568",
    "updated_at": "2026-01-20T19:06:27.322568",
    "last_validated": null
  }
]
```

**Errors**:
- `404`: Configuration directory not found
- `500`: Error parsing configuration files

#### GET /sites/{site_name}
Get a specific site configuration.

**Parameters**:
- `site_name` (path): Name of the site (without .conf extension)

**Response**:
```json
{
  "name": "api.example.com",
  "server_name": "api.example.com",
  "listen_ports": [80],
  "ssl_enabled": false,
  "root_path": null,
  "proxy_pass": "http://localhost:3000",
  "has_ssl_cert": false,
  "status": "untested",
  "file_path": "/etc/nginx/conf.d/api.example.com.conf",
  "file_size": 332,
  "created_at": "2026-01-20T19:06:27.322568",
  "updated_at": "2026-01-20T19:06:27.322568",
  "last_validated": null
}
```

**Errors**:
- `404`: Site not found
- `500`: Error parsing configuration

---

### Planned Endpoints (Phase 2+)

#### POST /sites/
Create a new site configuration.

**Request Body**:
```json
{
  "name": "newsite.com",
  "server_name": "newsite.com www.newsite.com",
  "listen_port": 80,
  "type": "static|proxy",
  "root_path": "/var/www/newsite",
  "proxy_pass": "http://localhost:3000",
  "ssl_enabled": false
}
```

#### PUT /sites/{site_name}
Update an existing site configuration.

#### DELETE /sites/{site_name}
Delete a site configuration.

#### POST /sites/{site_name}/enable
Enable a site (create symlink to sites-enabled).

#### POST /sites/{site_name}/disable
Disable a site without deleting configuration.

---

### NGINX Control

#### GET /nginx/status
Get detailed NGINX container status.

**Response**:
```json
{
  "status": "running",
  "container_id": "f8d9f425c91a",
  "container_name": "nginx-manager-nginx",
  "uptime_seconds": 5541,
  "started_at": "2026-01-26T23:03:15",
  "master_pid": 853740,
  "health_status": "healthy",
  "last_health_check": "2026-01-27T00:35:36.124038"
}
```

#### POST /nginx/test
Validate all NGINX configuration files with `nginx -t`.

**Response**:
```json
{
  "success": true,
  "message": "Configuration is valid",
  "stdout": null,
  "stderr": "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\nnginx: configuration file /etc/nginx/nginx.conf test is successful\n",
  "tested_at": "2026-01-27T00:35:41.443769",
  "config_file": "/etc/nginx/nginx.conf"
}
```

#### POST /nginx/reload
Graceful NGINX reload with health verification. Creates a transaction for audit and rollback.

**Response**:
```json
{
  "success": true,
  "operation": "reload",
  "message": "NGINX configuration reloaded successfully",
  "timestamp": "2026-01-27T00:35:41.973446",
  "duration_ms": 87,
  "health_verified": true,
  "previous_state": "running",
  "current_state": "running",
  "transaction_id": "7996fe43-3d1d-40d4-a821-70e5db9da725"
}
```

#### POST /nginx/restart
Full NGINX container restart with health verification. Creates a transaction for audit and rollback.

**Response**:
```json
{
  "success": true,
  "operation": "restart",
  "message": "NGINX container restarted successfully",
  "timestamp": "2026-01-27T00:35:51.221311",
  "duration_ms": 2550,
  "health_verified": true,
  "previous_state": "running",
  "current_state": "running",
  "transaction_id": "a05f88cc-07ee-425f-a941-34ceb721d76a"
}
```

**Note**: Restart is a disruptive operation that drops active connections. Prefer `/nginx/reload` for configuration changes.

---

### Transactions & Rollback

#### GET /transactions/
List all transactions with optional filtering.

**Query Parameters**:
- `status` (optional): Filter by status (pending, in_progress, completed, failed, rolled_back)
- `operation` (optional): Filter by operation type (nginx_reload, nginx_restart, etc.)
- `resource_type` (optional): Filter by resource type (site, nginx, certificate)
- `limit` (default: 50): Maximum transactions to return
- `offset` (default: 0): Offset for pagination

**Response**:
```json
{
  "transactions": [
    {
      "id": "7996fe43-3d1d-40d4-a821-70e5db9da725",
      "operation": "nginx_reload",
      "status": "completed",
      "resource_type": "nginx",
      "resource_id": "nginx",
      "created_at": "2026-01-27T01:04:24.476673",
      "completed_at": "2026-01-27T01:04:24.572462",
      "duration_ms": 89,
      "error_message": null
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0,
  "has_more": false
}
```

#### GET /transactions/{transaction_id}
Get detailed transaction information including diff.

**Response**:
```json
{
  "id": "7996fe43-3d1d-40d4-a821-70e5db9da725",
  "operation": "nginx_reload",
  "status": "completed",
  "resource_type": "nginx",
  "before_state": {
    "files": ["example.com.conf", "api.example.com.conf"],
    "total_size": 521
  },
  "after_state": {
    "files": ["example.com.conf", "api.example.com.conf"],
    "total_size": 521
  },
  "nginx_validated": true,
  "health_verified": true,
  "diff": {
    "files_changed": 0,
    "total_additions": 0,
    "total_deletions": 0,
    "files": []
  },
  "can_rollback": true,
  "rollback_reason": null
}
```

#### GET /transactions/{transaction_id}/can-rollback
Check if a transaction can be rolled back.

**Response**:
```json
{
  "transaction_id": "7996fe43-3d1d-40d4-a821-70e5db9da725",
  "can_rollback": true,
  "reason": null,
  "transaction_status": "completed"
}
```

#### POST /transactions/{transaction_id}/rollback
Rollback a transaction to restore previous configuration state.

**Request Body** (optional):
```json
{
  "reason": "Configuration caused errors"
}
```

**Response**:
```json
{
  "success": true,
  "rollback_transaction_id": "new-uuid",
  "original_transaction_id": "7996fe43-3d1d-40d4-a821-70e5db9da725",
  "restored_state": {
    "files_restored": ["example.com.conf"]
  },
  "message": "Configuration restored to state before transaction"
}
```

---

### Events & Audit Log

#### GET /events/
List system events with filtering.

**Query Parameters**:
- `since` (optional): Return events after this timestamp
- `until` (optional): Return events before this timestamp
- `severity` (optional): Filter by severity (info, warning, error, critical)
- `category` (optional): Filter by category (transaction, health, ssl, system, config)
- `transaction_id` (optional): Filter by transaction ID
- `page` (default: 1): Page number
- `page_size` (default: 50): Events per page

**Response**:
```json
{
  "events": [
    {
      "id": "evt-4fa438d1e432",
      "timestamp": "2026-01-27T01:04:24.575367",
      "severity": "info",
      "category": "transaction",
      "action": "completed",
      "transaction_id": "7996fe43-3d1d-40d4-a821-70e5db9da725",
      "resource_type": "nginx",
      "message": "Transaction completed: nginx_reload",
      "details": {
        "duration_ms": 89,
        "nginx_validated": true,
        "health_verified": true
      }
    }
  ],
  "total": 2,
  "page": 1,
  "page_size": 50,
  "has_more": false
}
```

#### GET /events/counts
Get event counts grouped by severity.

**Response**:
```json
{
  "info": 2,
  "warning": 0,
  "error": 0,
  "critical": 0,
  "total": 2
}
```

#### GET /events/{event_id}
Get detailed information about a specific event.

**Response**:
```json
{
  "id": "evt-4fa438d1e432",
  "timestamp": "2026-01-27T01:04:24.575367",
  "severity": "info",
  "category": "transaction",
  "action": "completed",
  "transaction_id": "7996fe43-3d1d-40d4-a821-70e5db9da725",
  "resource_type": "nginx",
  "resource_id": "nginx",
  "message": "Transaction completed: nginx_reload",
  "details": {
    "duration_ms": 89,
    "nginx_validated": true,
    "health_verified": true
  },
  "source": "api"
}

---

#### GET /certificates/
List all SSL certificates.

#### POST /certificates/
Request new Let's Encrypt certificate.

#### GET /certificates/{domain}
Get certificate details and expiry information.

#### POST /certificates/{domain}/renew
Trigger manual certificate renewal.

---

#### GET /backups/
List available configuration backups.

#### POST /backups/{id}/restore
Restore configuration from a backup.

---

## Error Responses

All errors follow this format:

```json
{
  "detail": "Human-readable error message",
  "error_code": "SITE_NOT_FOUND",
  "context": {
    "site_name": "missing.com"
  }
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `SITE_NOT_FOUND` | 404 | Requested site does not exist |
| `CONFIG_PARSE_ERROR` | 500 | Failed to parse NGINX config |
| `VALIDATION_ERROR` | 400 | Invalid request data |
| `NGINX_TEST_FAILED` | 422 | Configuration failed `nginx -t` |
| `BACKUP_NOT_FOUND` | 404 | Backup ID does not exist |

---

## AI Agent Integration

### OpenAPI Schema

The full OpenAPI 3.0 schema is available at `/openapi.json`. This can be used to:
- Generate client SDKs
- Configure OpenAI Custom GPT Actions
- Build Claude MCP tool definitions

### Response Design for LLMs

Responses are designed to be easily parsed by AI agents:
- Consistent JSON structure
- Descriptive field names
- ISO 8601 timestamps
- Enum values for status fields

### Example: Claude MCP Tool Definition

```json
{
  "name": "list_nginx_sites",
  "description": "List all NGINX site configurations managed by this server",
  "input_schema": {
    "type": "object",
    "properties": {},
    "required": []
  }
}
```

### Example: OpenAI GPT Action

```yaml
openapi: 3.0.0
info:
  title: NGINX Manager
  version: 0.1.0
paths:
  /sites/:
    get:
      operationId: listSites
      summary: List all site configurations
      responses:
        '200':
          description: List of sites
```

---

## Rate Limits (Planned)

| Tier | Requests/min | Burst |
|------|--------------|-------|
| Anonymous | 60 | 10 |
| Authenticated | 300 | 50 |
| Admin | Unlimited | - |
