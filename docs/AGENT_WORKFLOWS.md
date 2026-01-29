# Agent Workflows

Agent workflows are compound operations that orchestrate multiple API calls into a single atomic operation with automatic rollback on failure.

## Concepts

### Steps
Each workflow consists of a sequence of steps executed in order. Each step either succeeds or fails, and its result is available to subsequent steps.

### Checkpoints
Steps that create transactions are marked as **checkpoints**. If a later step fails, all checkpoint transactions are rolled back in reverse order, restoring the system to its previous state.

### Rollback Behavior
- **Critical failures** (e.g., site creation fails, config validation fails) trigger automatic rollback of all checkpoints
- **Non-critical failures** (e.g., SSL diagnostics fail) do not trigger rollback - the workflow reports partial completion and the site remains usable over HTTP

## Available Workflows

### Setup Site (`POST /workflows/setup-site`)

Creates a complete site with optional SSL in one operation.

**Steps:**
| # | Name | Description | Checkpoint |
|---|------|-------------|------------|
| 1 | check_prerequisites | Verify NGINX running, name available | No |
| 2 | create_site | Create NGINX config file | Yes |
| 3 | verify_site | Run `nginx -t` to validate | No |
| 4 | diagnose_ssl* | Check DNS/port prerequisites | No |
| 5 | request_certificate* | Request Let's Encrypt cert | Yes |
| 6 | verify_ssl* | Verify SSL installation | No |

*Steps 4-6 only execute if `request_ssl=true`

**Request:**
```json
{
  "name": "example.com",
  "server_names": ["example.com", "www.example.com"],
  "site_type": "static",
  "root_path": "/var/www/example",
  "request_ssl": true,
  "ssl_alt_names": ["www.example.com"],
  "auto_renew": true
}
```

**Dry run:**
```bash
curl -X POST "http://localhost:8000/workflows/setup-site?dry_run=true" \
  -H "Content-Type: application/json" \
  -d '{"name": "example.com", "server_names": ["example.com"], "site_type": "static", "root_path": "/var/www/example", "request_ssl": false}'
```

### Migrate Site (`POST /workflows/migrate-site`)

Safely updates an existing site with automatic rollback if the new configuration is invalid.

**Steps:**
| # | Name | Description | Checkpoint |
|---|------|-------------|------------|
| 1 | verify_exists | Confirm site exists | No |
| 2 | update_site | Apply configuration changes | Yes |
| 3 | test_config | Run `nginx -t` to validate | No |

**Request:**
```json
{
  "name": "example.com",
  "server_names": ["new.example.com"],
  "listen_port": 8080
}
```

**Dry run:**
```bash
curl -X POST "http://localhost:8000/workflows/migrate-site?dry_run=true" \
  -H "Content-Type: application/json" \
  -d '{"name": "example.com", "proxy_pass": "http://localhost:4000"}'
```

## Response Format

### Successful Workflow
```json
{
  "workflow_id": "wf-a1b2c3d4e5f6",
  "workflow_type": "setup_site",
  "status": "completed",
  "message": "Workflow completed successfully (3/3 steps)",
  "total_steps": 3,
  "completed_steps": 3,
  "steps": [
    {
      "step_name": "check_prerequisites",
      "step_number": 1,
      "status": "completed",
      "message": "Prerequisites satisfied",
      "duration_ms": 45
    },
    {
      "step_name": "create_site",
      "step_number": 2,
      "status": "completed",
      "message": "Site 'example.com' created successfully",
      "transaction_id": "abc-123",
      "is_checkpoint": true,
      "duration_ms": 230
    },
    {
      "step_name": "verify_site",
      "step_number": 3,
      "status": "completed",
      "message": "NGINX config valid",
      "duration_ms": 120
    }
  ],
  "transaction_ids": ["abc-123"],
  "suggestions": [
    {
      "action": "Test the site by sending a request",
      "command": "curl -H 'Host: example.com' http://localhost/"
    }
  ]
}
```

### Failed Workflow with Rollback
```json
{
  "workflow_id": "wf-x1y2z3",
  "workflow_type": "migrate_site",
  "status": "rolled_back",
  "message": "Workflow failed at step 'test_config' - all changes rolled back",
  "failed_step": "test_config",
  "rolled_back": true,
  "rollback_details": {
    "rollbacks": [
      {"transaction_id": "def-456", "success": true, "message": "Rolled back"}
    ]
  }
}
```

## SSE Streaming

For real-time progress updates, add `?stream=true` to the request:

```bash
curl -N -X POST "http://localhost:8000/workflows/setup-site?stream=true" \
  -H "Content-Type: application/json" \
  -d '{"name": "example.com", "server_names": ["example.com"], "site_type": "static", "root_path": "/var/www/example"}'
```

Events follow the standard SSE format:

```
event: workflow_started
data: {"workflow_id": "wf-abc", "event_type": "workflow_started", "total_steps": 3, "message": "Starting..."}

event: step_started
data: {"workflow_id": "wf-abc", "event_type": "step_started", "step_name": "check_prerequisites", "step_number": 1, "total_steps": 3}

event: step_completed
data: {"workflow_id": "wf-abc", "event_type": "step_completed", "step_name": "check_prerequisites", "step_number": 1}

event: step_started
data: {"workflow_id": "wf-abc", "event_type": "step_started", "step_name": "create_site", "step_number": 2}

event: step_completed
data: {"workflow_id": "wf-abc", "event_type": "step_completed", "step_name": "create_site", "step_number": 2, "data": {"transaction_id": "txn-123"}}

event: workflow_completed
data: {"workflow_id": "wf-abc", "event_type": "workflow_completed", "message": "Workflow completed successfully"}

event: result
data: {"workflow_id": "wf-abc", "status": "completed", "steps": [...], ...}
```

## MCP Usage

Workflows are also available as MCP tools:

- `setup_site_workflow` - Same parameters as the REST endpoint
- `migrate_site_workflow` - Same parameters as the REST endpoint

Both support the `dry_run` parameter for previewing operations.

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `WORKFLOW_STEP_TIMEOUT` | 120 | Timeout in seconds for individual steps |
| `WORKFLOW_AUTO_ROLLBACK` | true | Automatically rollback on step failure |

## Error Handling

### SSL Failure During Setup
If SSL steps fail during `setup-site`, the site creation is **not** rolled back. The site remains usable over HTTP, and the response indicates partial completion with suggestions to fix the SSL issue and retry.

### Config Validation Failure During Migration
If `nginx -t` fails after a site update in `migrate-site`, the update is automatically rolled back. The site returns to its previous working configuration.

### Step Timeout
If a step exceeds the configured timeout (`WORKFLOW_STEP_TIMEOUT`), it is marked as failed and the workflow proceeds with rollback as appropriate.
