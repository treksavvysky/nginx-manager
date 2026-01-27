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
Graceful NGINX reload with health verification.

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
  "current_state": "running"
}
```

#### POST /nginx/restart
Full NGINX container restart with health verification.

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
  "current_state": "running"
}
```

**Note**: Restart is a disruptive operation that drops active connections. Prefer `/nginx/reload` for configuration changes.

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
