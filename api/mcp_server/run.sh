#!/bin/bash
# MCP Server wrapper script
# Sets environment variables for host-based execution

export PYTHONPATH="/root/nginx-manager/api"
export NGINX_CONF_DIR="/root/nginx-manager/test-configs"
export TRANSACTION_DB_PATH="/root/nginx-manager/data/api-backups/transactions.db"
export SNAPSHOT_DIR="/root/nginx-manager/data/api-backups/snapshots"
export SSL_CERT_DIR="/root/nginx-manager/data/ssl"
export ACME_CHALLENGE_DIR="/root/nginx-manager/data/acme-challenge"

# Debug logging
echo "MCP Server starting with DB: $TRANSACTION_DB_PATH" >> /tmp/mcp-debug.log

cd /root/nginx-manager/api
exec python3 mcp_server/server.py "$@"
