"""
MCP (Model Context Protocol) server for NGINX Manager.

This module provides an MCP interface for AI agents to manage NGINX
configurations, SSL certificates, and reverse proxy setups.

Components:
- resources: Read-only data endpoints (sites, certificates, health, events)
- tools: Executable actions (CRUD operations, NGINX control, SSL management)
- prompts: Reusable workflow templates for common tasks
- server: Main MCP server setup and transport configuration
"""

from .server import create_mcp_server, run_mcp_server

__all__ = ["create_mcp_server", "run_mcp_server"]
