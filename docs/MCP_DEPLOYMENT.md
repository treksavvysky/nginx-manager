# MCP Server Deployment Guide

This guide covers deploying and using the NGINX Manager MCP (Model Context Protocol) server for AI agent integration.

## Overview

The MCP server exposes NGINX Manager functionality through the Model Context Protocol, enabling AI agents like Claude to manage NGINX configurations, SSL certificates, and reverse proxy setups.

## Prerequisites

- Python 3.12+
- NGINX Manager API running
- Docker (for NGINX container management)

## Installation

### 1. Install MCP SDK

Add the MCP SDK to your environment:

```bash
# Using pip
pip install "mcp[cli]>=1.0.0"

# Or add to requirements.txt
echo 'mcp[cli]>=1.0.0' >> requirements.txt
pip install -r requirements.txt
```

### 2. Verify Installation

```bash
python -c "from mcp.server.fastmcp import FastMCP; print('MCP SDK installed successfully')"
```

## Running the MCP Server

### Option 1: Stdio Transport (Local CLI)

For integration with local tools like Claude Desktop:

```bash
cd /path/to/nginx-manager/api
python3 mcp_server/server.py
```

Or using the module directly:

```bash
python -c "from mcp import run_mcp_server; run_mcp_server(transport='stdio')"
```

### Option 2: HTTP Transport (Remote Access)

For remote connections (requires additional security measures):

```bash
cd /path/to/nginx-manager/api
python3 mcp_server/server.py --transport streamable-http --host 127.0.0.1 --port 8080
```

**Security Warning**: Never expose the HTTP transport on `0.0.0.0` without authentication. Always bind to `127.0.0.1` for local access or use a reverse proxy with authentication.

## Claude Desktop Integration

### Configuration

Add to your Claude Desktop MCP configuration (`~/.claude/mcp.json` or similar):

```json
{
  "mcpServers": {
    "nginx-manager": {
      "command": "python",
      "args": ["-m", "mcp.server"],
      "cwd": "/path/to/nginx-manager/api",
      "env": {
        "NGINX_CONF_DIR": "/etc/nginx/conf.d",
        "NGINX_CONTAINER_NAME": "nginx-manager-nginx"
      }
    }
  }
}
```

### Environment Variables

The MCP server inherits all environment variables from the main API. Key variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `NGINX_CONF_DIR` | NGINX configuration directory | `/etc/nginx/conf.d` |
| `NGINX_CONTAINER_NAME` | Docker container name | `nginx-manager-nginx` |
| `ACME_ACCOUNT_EMAIL` | Let's Encrypt account email | (required for SSL) |
| `ACME_USE_STAGING` | Use staging environment | `false` |
| `TRANSACTION_DB_PATH` | SQLite database path | `/var/backups/nginx/transactions.db` |

## Available Capabilities

### Resources (Read-Only Data)

| URI | Description |
|-----|-------------|
| `nginx://sites` | List all site configurations |
| `nginx://sites/{name}` | Get specific site details |
| `nginx://certificates` | List all SSL certificates |
| `nginx://certificates/{domain}` | Get certificate details |
| `nginx://health` | System health summary |
| `nginx://events` | Recent system events |
| `nginx://transactions` | Recent transactions |
| `nginx://transactions/{id}` | Transaction details |

### Tools (Actions)

**Site Management:**
- `create_site` - Create new site configuration
- `update_site` - Update existing site
- `delete_site` - Delete site configuration
- `enable_site` - Enable disabled site
- `disable_site` - Disable site without deleting

**NGINX Control:**
- `nginx_reload` - Graceful configuration reload
- `nginx_restart` - Full container restart
- `nginx_test` - Validate configuration

**Certificate Management:**
- `request_certificate` - Request Let's Encrypt certificate
- `upload_certificate` - Upload custom certificate
- `renew_certificate` - Manually renew certificate
- `revoke_certificate` - Revoke and remove certificate
- `diagnose_ssl` - Run SSL diagnostic

**Transaction Management:**
- `rollback_transaction` - Rollback to previous state

### Prompts (Workflow Templates)

- `setup_new_site` - Guide for setting up a new website
- `add_ssl_to_site` - Guide for adding SSL to existing site
- `check_expiring_certs` - Guide for certificate renewal management
- `diagnose_connectivity` - Guide for troubleshooting connectivity
- `rollback_changes` - Guide for safely rolling back changes

## Usage Examples

### Example 1: Create a New Site

```
User: Create a reverse proxy site for api.example.com that proxies to localhost:3000

Claude: I'll create a reverse proxy site for api.example.com.

First, let me preview the changes:
[Calls create_site with dry_run=true]

The preview shows the configuration would be valid. Creating the site now:
[Calls create_site with dry_run=false]

Site created successfully! Transaction ID: txn_abc123

Suggestions:
- Add SSL: request_certificate(domain='api.example.com')
- View site: nginx://sites/api.example.com
```

### Example 2: Add SSL Certificate

```
User: Add SSL to example.com

Claude: I'll add an SSL certificate to example.com.

First, let me run diagnostics:
[Calls diagnose_ssl]

DNS resolves correctly and port 80 is accessible. Requesting certificate:
[Calls request_certificate with dry_run=true]

Prerequisites check passed. Requesting the certificate:
[Calls request_certificate]

Certificate installed successfully!
- Expires: 2026-04-27
- Auto-renewal: enabled
```

### Example 3: Troubleshoot Connectivity

```
User: My site example.com isn't working

Claude: Let me diagnose the connectivity issues for example.com.
[Uses diagnose_connectivity prompt as guide]

1. Checking system health:
[Fetches nginx://health]
NGINX is running and healthy.

2. Checking site configuration:
[Fetches nginx://sites/example.com]
Site is enabled with correct settings.

3. Running SSL diagnostic:
[Calls diagnose_ssl]

Issue found: Certificate expired 2 days ago.

Solution: Renewing certificate...
[Calls renew_certificate]

Certificate renewed. Site should now be accessible.
```

## Docker Deployment

### Running MCP Server in Docker

Add to your docker-compose configuration:

```yaml
services:
  mcp-server:
    build:
      context: .
      dockerfile: docker/api/Dockerfile
    command: python3 mcp_server/server.py --transport streamable-http --host 0.0.0.0 --port 8080
    ports:
      - "127.0.0.1:8080:8080"  # Local only!
    environment:
      - NGINX_CONF_DIR=/etc/nginx/conf.d
      - NGINX_CONTAINER_NAME=nginx-manager-nginx
    volumes:
      - ./test-configs:/etc/nginx/conf.d
      - ./data/ssl:/etc/ssl
      - ./data/api-backups:/var/backups/nginx
    networks:
      - nginx-network
```

### Health Check

```bash
# Check if MCP server is responding (HTTP transport)
curl http://localhost:8080/health
```

## Security Considerations

### 1. Network Security

- **Never expose MCP HTTP transport publicly** without authentication
- Use Unix sockets or stdio transport for local access
- If HTTP is required, place behind authenticated reverse proxy

### 2. Input Validation

- All tool inputs are validated against JSON schemas
- Path traversal protection is enforced
- Domain names are validated before certificate operations

### 3. Transaction Safety

- All mutations create transactions with rollback capability
- Dry-run mode available for all mutation operations
- Automatic rollback on health check failure (configurable)

### 4. SSL Certificate Security

- Private keys stored with restricted permissions (600)
- Never expose key material in responses
- ACME account keys stored securely in database

## Troubleshooting

### MCP SDK Not Found

```
Error: ModuleNotFoundError: No module named 'mcp'
```

Solution:
```bash
pip install "mcp[cli]>=1.0.0"
```

### Connection Refused

```
Error: Connection refused on localhost:8080
```

Check:
1. MCP server is running
2. Correct port is specified
3. Firewall allows connection

### Docker Container Not Found

```
Error: Container 'nginx-manager-nginx' not found
```

Check:
1. Docker is running
2. Container name matches `NGINX_CONTAINER_NAME`
3. API has access to Docker socket

### Database Errors

```
Error: Unable to open database
```

Check:
1. Database directory exists and is writable
2. `TRANSACTION_DB_PATH` points to valid location
3. SQLite file permissions allow access

## Monitoring

### Log Output

The MCP server logs to stderr. Configure logging level via:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Metrics

Monitor these key indicators:
- Transaction success rate
- Certificate expiry warnings
- NGINX reload failures
- Event error counts

Use the `nginx://health` resource for real-time status.

## API Documentation

For detailed API documentation, see:
- [MCP Design Document](./MCP_DESIGN.md) - Full schema definitions
- [API Documentation](./API.md) - REST API reference
- [Architecture](./ARCHITECTURE.md) - System architecture

## Support

For issues and feature requests:
- GitHub Issues: https://github.com/your-repo/nginx-manager/issues
- MCP SDK Documentation: https://modelcontextprotocol.io/
