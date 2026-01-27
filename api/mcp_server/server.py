"""
MCP Server for NGINX Manager.

This module implements the Model Context Protocol server that exposes
NGINX Manager functionality to AI agents like Claude.

Supports multiple transports:
- stdio: For local CLI integration
- streamable-http: For remote connections (requires authentication in production)
"""

import asyncio
import logging
import json
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Try to import MCP SDK - provide helpful error if not installed
try:
    from mcp.server.fastmcp import FastMCP
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
    logger.warning("MCP SDK not installed. Run: pip install 'mcp[cli]'")


def create_mcp_server(name: str = "nginx-manager") -> Optional[Any]:
    """
    Create and configure the MCP server with all resources, tools, and prompts.

    Args:
        name: Server name for identification

    Returns:
        FastMCP server instance, or None if MCP SDK not available
    """
    if not MCP_AVAILABLE:
        logger.error("MCP SDK not available. Install with: pip install 'mcp[cli]'")
        return None

    # Create FastMCP server
    mcp = FastMCP(name)

    # ==========================================================================
    # Register Resources
    # ==========================================================================

    @mcp.resource("nginx://sites")
    async def resource_sites() -> str:
        """List all NGINX site configurations."""
        from mcp_server.resources import get_sites_resource
        result = await get_sites_resource()
        return json.dumps(result, indent=2, default=str)

    @mcp.resource("nginx://sites/{name}")
    async def resource_site(name: str) -> str:
        """Get detailed configuration for a specific site."""
        from mcp_server.resources import get_site_resource
        result = await get_site_resource(name)
        return json.dumps(result, indent=2, default=str)

    @mcp.resource("nginx://certificates")
    async def resource_certificates() -> str:
        """List all SSL certificates with status."""
        from mcp_server.resources import get_certificates_resource
        result = await get_certificates_resource()
        return json.dumps(result, indent=2, default=str)

    @mcp.resource("nginx://certificates/{domain}")
    async def resource_certificate(domain: str) -> str:
        """Get detailed certificate information for a domain."""
        from mcp_server.resources import get_certificate_resource
        result = await get_certificate_resource(domain)
        return json.dumps(result, indent=2, default=str)

    @mcp.resource("nginx://health")
    async def resource_health() -> str:
        """Get system health and status summary."""
        from mcp_server.resources import get_health_resource
        result = await get_health_resource()
        return json.dumps(result, indent=2, default=str)

    @mcp.resource("nginx://events")
    async def resource_events() -> str:
        """Get recent system events (last 24 hours)."""
        from mcp_server.resources import get_events_resource
        result = await get_events_resource()
        return json.dumps(result, indent=2, default=str)

    @mcp.resource("nginx://transactions")
    async def resource_transactions() -> str:
        """Get recent transactions with rollback capability."""
        from mcp_server.resources import get_transactions_resource
        result = await get_transactions_resource()
        return json.dumps(result, indent=2, default=str)

    @mcp.resource("nginx://transactions/{transaction_id}")
    async def resource_transaction(transaction_id: str) -> str:
        """Get detailed transaction information with diff."""
        from mcp_server.resources import get_transaction_resource
        result = await get_transaction_resource(transaction_id)
        return json.dumps(result, indent=2, default=str)

    # ==========================================================================
    # Register Tools - Site Management
    # ==========================================================================

    @mcp.tool()
    async def create_site(
        name: str,
        server_names: list[str],
        site_type: str,
        listen_port: int = 80,
        root_path: str = None,
        proxy_pass: str = None,
        auto_reload: bool = True,
        dry_run: bool = False
    ) -> str:
        """
        Create a new NGINX site configuration.

        Args:
            name: Site name (used as filename and identifier)
            server_names: Domain names for this site
            site_type: Type of site - "static" or "reverse_proxy"
            listen_port: Port to listen on (default: 80)
            root_path: Document root for static sites
            proxy_pass: Backend URL for reverse proxy sites
            auto_reload: Reload NGINX after creating site (default: True)
            dry_run: Preview changes without applying (default: False)

        Returns:
            Operation result with transaction_id and suggestions
        """
        from mcp_server.tools import create_site as create_site_impl
        result = await create_site_impl(
            name=name,
            server_names=server_names,
            site_type=site_type,
            listen_port=listen_port,
            root_path=root_path,
            proxy_pass=proxy_pass,
            auto_reload=auto_reload,
            dry_run=dry_run
        )
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    async def update_site(
        name: str,
        server_names: list[str] = None,
        listen_port: int = None,
        root_path: str = None,
        proxy_pass: str = None,
        auto_reload: bool = True,
        dry_run: bool = False
    ) -> str:
        """
        Update an existing site configuration.

        Args:
            name: Site name to update
            server_names: Updated domain names (optional)
            listen_port: Updated listen port (optional)
            root_path: Updated document root (optional)
            proxy_pass: Updated backend URL (optional)
            auto_reload: Reload NGINX after update (default: True)
            dry_run: Preview changes without applying (default: False)

        Returns:
            Operation result with transaction_id and suggestions
        """
        from mcp_server.tools import update_site as update_site_impl
        result = await update_site_impl(
            name=name,
            server_names=server_names,
            listen_port=listen_port,
            root_path=root_path,
            proxy_pass=proxy_pass,
            auto_reload=auto_reload,
            dry_run=dry_run
        )
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    async def delete_site(
        name: str,
        auto_reload: bool = False,
        dry_run: bool = False
    ) -> str:
        """
        Delete a site configuration.

        Args:
            name: Site name to delete
            auto_reload: Reload NGINX after deletion (default: False)
            dry_run: Preview changes without applying (default: False)

        Returns:
            Operation result with transaction_id
        """
        from mcp_server.tools import delete_site as delete_site_impl
        result = await delete_site_impl(
            name=name,
            auto_reload=auto_reload,
            dry_run=dry_run
        )
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    async def enable_site(
        name: str,
        auto_reload: bool = True,
        dry_run: bool = False
    ) -> str:
        """
        Enable a disabled site.

        Args:
            name: Site name to enable
            auto_reload: Reload NGINX after enabling (default: True)
            dry_run: Preview changes without applying (default: False)

        Returns:
            Operation result with transaction_id
        """
        from mcp_server.tools import enable_site as enable_site_impl
        result = await enable_site_impl(
            name=name,
            auto_reload=auto_reload,
            dry_run=dry_run
        )
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    async def disable_site(
        name: str,
        auto_reload: bool = True,
        dry_run: bool = False
    ) -> str:
        """
        Disable a site without deleting it.

        Args:
            name: Site name to disable
            auto_reload: Reload NGINX after disabling (default: True)
            dry_run: Preview changes without applying (default: False)

        Returns:
            Operation result with transaction_id
        """
        from mcp_server.tools import disable_site as disable_site_impl
        result = await disable_site_impl(
            name=name,
            auto_reload=auto_reload,
            dry_run=dry_run
        )
        return json.dumps(result, indent=2, default=str)

    # ==========================================================================
    # Register Tools - NGINX Control
    # ==========================================================================

    @mcp.tool()
    async def nginx_reload(dry_run: bool = False) -> str:
        """
        Gracefully reload NGINX configuration.

        This performs a graceful reload that doesn't drop connections.
        Use this after making configuration changes.

        Args:
            dry_run: Preview what would happen (default: False)

        Returns:
            Operation result with health status
        """
        from mcp_server.tools import nginx_reload as nginx_reload_impl
        result = await nginx_reload_impl(dry_run=dry_run)
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    async def nginx_restart(dry_run: bool = False) -> str:
        """
        Full NGINX container restart (disruptive).

        WARNING: This will drop all active connections.
        Use nginx_reload for graceful config updates.

        Args:
            dry_run: Preview what would happen (default: False)

        Returns:
            Operation result with health status
        """
        from mcp_server.tools import nginx_restart as nginx_restart_impl
        result = await nginx_restart_impl(dry_run=dry_run)
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    async def nginx_test() -> str:
        """
        Validate NGINX configuration without applying.

        Runs 'nginx -t' to check configuration syntax.
        Use this to verify config before reloading.

        Returns:
            Validation result with details
        """
        from mcp_server.tools import nginx_test as nginx_test_impl
        result = await nginx_test_impl()
        return json.dumps(result, indent=2, default=str)

    # ==========================================================================
    # Register Tools - Certificate Management
    # ==========================================================================

    @mcp.tool()
    async def request_certificate(
        domain: str,
        alt_names: list[str] = None,
        auto_renew: bool = True,
        auto_reload: bool = True,
        dry_run: bool = False
    ) -> str:
        """
        Request a Let's Encrypt SSL certificate.

        Uses HTTP-01 challenge - domain must resolve to this server
        and port 80 must be accessible.

        Args:
            domain: Primary domain for the certificate
            alt_names: Additional domain names (SANs)
            auto_renew: Enable automatic renewal (default: True)
            auto_reload: Reload NGINX after installation (default: True)
            dry_run: Check prerequisites without requesting (default: False)

        Returns:
            Operation result with certificate details
        """
        from mcp_server.tools import request_certificate as request_certificate_impl
        result = await request_certificate_impl(
            domain=domain,
            alt_names=alt_names,
            auto_renew=auto_renew,
            auto_reload=auto_reload,
            dry_run=dry_run
        )
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    async def upload_certificate(
        domain: str,
        certificate_pem: str,
        private_key_pem: str,
        chain_pem: str = None,
        auto_reload: bool = True,
        dry_run: bool = False
    ) -> str:
        """
        Upload a custom SSL certificate.

        Use this for certificates from other CAs or internal PKI.

        Args:
            domain: Domain for the certificate
            certificate_pem: Certificate in PEM format
            private_key_pem: Private key in PEM format
            chain_pem: Optional certificate chain in PEM format
            auto_reload: Reload NGINX after installation (default: True)
            dry_run: Validate without uploading (default: False)

        Returns:
            Operation result with certificate details
        """
        from mcp_server.tools import upload_certificate as upload_certificate_impl
        result = await upload_certificate_impl(
            domain=domain,
            certificate_pem=certificate_pem,
            private_key_pem=private_key_pem,
            chain_pem=chain_pem,
            auto_reload=auto_reload,
            dry_run=dry_run
        )
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    async def renew_certificate(
        domain: str,
        force: bool = False,
        auto_reload: bool = True,
        dry_run: bool = False
    ) -> str:
        """
        Manually trigger certificate renewal.

        Certificates with auto_renew=true are renewed automatically.
        Use this for manual renewal or to force early renewal.

        Args:
            domain: Domain to renew
            force: Force renewal even if not expiring soon (default: False)
            auto_reload: Reload NGINX after renewal (default: True)
            dry_run: Check renewal status without renewing (default: False)

        Returns:
            Operation result with certificate details
        """
        from mcp_server.tools import renew_certificate as renew_certificate_impl
        result = await renew_certificate_impl(
            domain=domain,
            force=force,
            auto_reload=auto_reload,
            dry_run=dry_run
        )
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    async def revoke_certificate(
        domain: str,
        auto_reload: bool = True,
        dry_run: bool = False
    ) -> str:
        """
        Revoke and remove a certificate.

        WARNING: This permanently revokes the certificate.
        The site will no longer be accessible via HTTPS.

        Args:
            domain: Domain to revoke certificate for
            auto_reload: Reload NGINX after revocation (default: True)
            dry_run: Preview revocation without executing (default: False)

        Returns:
            Operation result
        """
        from mcp_server.tools import revoke_certificate as revoke_certificate_impl
        result = await revoke_certificate_impl(
            domain=domain,
            auto_reload=auto_reload,
            dry_run=dry_run
        )
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    async def diagnose_ssl(domain: str) -> str:
        """
        Run comprehensive SSL diagnostic.

        Checks DNS resolution, port accessibility, certificate validity,
        and chain completeness. Use before requesting SSL certificates.

        Args:
            domain: Domain to diagnose

        Returns:
            Diagnostic results with issues and suggestions
        """
        from mcp_server.tools import diagnose_ssl as diagnose_ssl_impl
        result = await diagnose_ssl_impl(domain=domain)
        return json.dumps(result, indent=2, default=str)

    # ==========================================================================
    # Register Tools - Transaction Management
    # ==========================================================================

    @mcp.tool()
    async def rollback_transaction(
        transaction_id: str,
        reason: str = None
    ) -> str:
        """
        Rollback a transaction to restore previous state.

        Restores configuration files from the transaction's snapshot.
        Creates a new transaction to track the rollback.

        Args:
            transaction_id: Transaction ID to rollback
            reason: Reason for rollback (optional, for audit)

        Returns:
            Rollback result
        """
        from mcp_server.tools import rollback_transaction as rollback_transaction_impl
        result = await rollback_transaction_impl(
            transaction_id=transaction_id,
            reason=reason
        )
        return json.dumps(result, indent=2, default=str)

    # ==========================================================================
    # Register Prompts
    # ==========================================================================

    @mcp.prompt()
    def setup_new_site(
        domain: str,
        site_type: str,
        with_ssl: bool = True
    ) -> str:
        """
        Guide for setting up a new website.

        Provides step-by-step instructions for creating a site,
        optionally with SSL certificate.

        Args:
            domain: Primary domain name
            site_type: "static" or "reverse_proxy"
            with_ssl: Request SSL certificate (default: true)
        """
        from mcp_server.prompts import get_setup_new_site_prompt
        return get_setup_new_site_prompt(domain, site_type, with_ssl)

    @mcp.prompt()
    def add_ssl_to_site(
        domain: str,
        certificate_type: str = "letsencrypt"
    ) -> str:
        """
        Guide for adding SSL certificate to an existing site.

        Provides diagnostics and step-by-step instructions.

        Args:
            domain: Domain to add SSL to
            certificate_type: "letsencrypt" or "custom"
        """
        from mcp_server.prompts import get_add_ssl_prompt
        return get_add_ssl_prompt(domain, certificate_type)

    @mcp.prompt()
    def check_expiring_certs(days_threshold: int = 30) -> str:
        """
        Guide for managing certificate renewals.

        Reviews all certificates and identifies those needing renewal.

        Args:
            days_threshold: Days until expiry to consider "expiring soon"
        """
        from mcp_server.prompts import get_check_expiring_certs_prompt
        return get_check_expiring_certs_prompt(days_threshold)

    @mcp.prompt()
    def diagnose_connectivity(domain: str) -> str:
        """
        Guide for troubleshooting site connectivity issues.

        Systematic diagnostic workflow for resolving access problems.

        Args:
            domain: Domain experiencing issues
        """
        from mcp_server.prompts import get_diagnose_connectivity_prompt
        return get_diagnose_connectivity_prompt(domain)

    @mcp.prompt()
    def rollback_changes(resource: str = None) -> str:
        """
        Guide for safely rolling back problematic changes.

        Helps identify and revert transactions that caused issues.

        Args:
            resource: Optional resource name that has issues
        """
        from mcp_server.prompts import get_rollback_changes_prompt
        return get_rollback_changes_prompt(resource)

    logger.info(f"MCP server '{name}' configured with resources, tools, and prompts")
    return mcp


def run_mcp_server(
    transport: str = "stdio",
    host: str = "127.0.0.1",
    port: int = 8080
):
    """
    Run the MCP server with specified transport.

    Args:
        transport: Transport type - "stdio" or "streamable-http"
        host: Host for HTTP transport (default: 127.0.0.1)
        port: Port for HTTP transport (default: 8080)
    """
    mcp = create_mcp_server()

    if mcp is None:
        logger.error("Failed to create MCP server")
        return

    if transport == "stdio":
        logger.info("Starting MCP server with stdio transport")
        mcp.run()
    elif transport == "streamable-http":
        logger.info(f"Starting MCP server with HTTP transport on {host}:{port}")
        mcp.run(transport="streamable-http", host=host, port=port)
    else:
        logger.error(f"Unknown transport: {transport}")


# CLI entry point
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="NGINX Manager MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default="stdio",
        help="Transport type (default: stdio)"
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host for HTTP transport (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port for HTTP transport (default: 8080)"
    )

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    run_mcp_server(
        transport=args.transport,
        host=args.host,
        port=args.port
    )
