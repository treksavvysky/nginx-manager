# OpenAI Custom GPT Integration

This guide explains how to create an OpenAI Custom GPT that manages your NGINX server through the NGINX Manager API.

## Prerequisites

- NGINX Manager API deployed and accessible from the internet (or via a tunnel)
- An OpenAI account with access to Custom GPTs (ChatGPT Plus or Team)
- The API must be reachable at a public URL (e.g., `https://your-server.example.com:8000`)

## Setup Steps

### 1. Get the GPT-Compatible Schema

NGINX Manager provides a pre-built OpenAPI schema optimized for Custom GPT Actions:

```
GET /gpt/openapi.json?server_url=https://your-server.example.com:8000
```

This schema:
- Includes only the endpoints relevant to GPT usage (sites, NGINX control, SSL, workflows)
- Sets the correct server URL
- Ensures all operations have unique `operationId` values
- Truncates descriptions to fit GPT schema size limits
- Includes an API Key security scheme placeholder

### 2. Create the Custom GPT

1. Go to [ChatGPT](https://chat.openai.com) and click **Explore GPTs** > **Create**
2. In the **Configure** tab:
   - **Name**: NGINX Manager
   - **Description**: Manages NGINX sites, SSL certificates, and reverse proxies on your VPS
3. Under **Instructions**, paste the contents from:
   ```
   GET /gpt/instructions
   ```
   Or retrieve them with:
   ```bash
   curl https://your-server.example.com:8000/gpt/instructions
   ```

### 3. Add Actions

1. In the GPT builder, click **Create new action**
2. Under **Authentication**, select **API Key** and set:
   - Auth Type: API Key
   - API Key: (any value for now - authentication is not yet enforced)
   - Header Name: `X-API-Key`
3. Under **Schema**, either:
   - **Import from URL**: Enter `https://your-server.example.com:8000/gpt/openapi.json`
   - **Paste schema**: Copy the JSON from the URL above and paste it
4. Click **Test** on any endpoint to verify connectivity

### 4. Add Conversation Starters

Suggested starters:
- "Set up a new website for example.com with SSL"
- "List all my sites and check for expiring certificates"
- "Create a reverse proxy for my Node.js app on port 3000"
- "Diagnose why my-site.com is not loading"
- "Show me the current NGINX status and recent events"

### 5. Save and Test

Save your GPT and try the conversation starters. The GPT should be able to:
- List existing sites
- Create new sites (static or reverse proxy)
- Request SSL certificates
- Run compound workflows (setup-site, migrate-site)
- Diagnose issues and suggest fixes

## Example Configuration

See `api/gpt/example_config.json` for a reference GPT configuration.

## Security Notes

- **No authentication is currently enforced.** The API Key scheme is a placeholder for Phase 5 (Authentication & Security). For now, anyone with the URL can access the API.
- **Restrict access** by binding the API to localhost and using a reverse proxy with authentication, or by using network-level controls (firewall, VPN).
- **Do not expose the API to the public internet** without access controls in a production environment.

## Troubleshooting

### GPT can't connect to the API
- Verify the API is accessible from the internet: `curl https://your-server.example.com:8000/health`
- Check that CORS is configured to allow requests from `chat.openai.com`
- Ensure the `server_url` in the schema matches your actual deployment URL

### Schema import fails
- The schema must be valid OpenAPI 3.1 JSON
- Try fetching it directly: `curl https://your-server.example.com:8000/gpt/openapi.json | python3 -m json.tool`
- Check for schema size issues - the GPT schema has undocumented size limits

### GPT makes incorrect API calls
- Review the schema for missing or incorrect `operationId` values
- Ensure the GPT instructions mention the correct endpoint patterns
- Use dry-run mode (`?dry_run=true`) to preview operations before executing
