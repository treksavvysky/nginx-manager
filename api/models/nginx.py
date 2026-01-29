"""
Pydantic models for NGINX configuration structures.

These models represent the full hierarchical structure of NGINX configurations
as parsed by crossplane. They provide rich typing for AI agents and enable
detailed configuration inspection.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ListenDirective(BaseModel):
    """Represents a listen directive with all its options."""

    port: int = Field(..., description="Port number to listen on")
    address: str | None = Field(None, description="IP address or socket path")
    ssl: bool = Field(default=False, description="SSL/TLS enabled on this listener")
    http2: bool = Field(default=False, description="HTTP/2 enabled")
    default_server: bool = Field(default=False, description="Default server for this port")
    raw_args: list[str] = Field(default_factory=list, description="Original arguments")


class LocationBlock(BaseModel):
    """Represents an NGINX location block."""

    modifier: str | None = Field(None, description="Location modifier: =, ~, ~*, ^~, or None for prefix match")
    path: str = Field(..., description="Location path or pattern")
    proxy_pass: str | None = Field(None, description="Upstream URL for reverse proxy")
    root: str | None = Field(None, description="Document root for this location")
    alias: str | None = Field(None, description="Alias path")
    index: list[str] | None = Field(None, description="Index files")
    try_files: str | None = Field(None, description="try_files directive value")
    return_code: int | None = Field(None, description="Return status code")
    return_value: str | None = Field(None, description="Return body or redirect URL")
    rewrite_rules: list[dict[str, Any]] = Field(default_factory=list, description="Rewrite rules in this location")
    headers: dict[str, str] = Field(default_factory=dict, description="Headers set via proxy_set_header or add_header")
    directives: dict[str, Any] = Field(default_factory=dict, description="Other directives as key-value pairs")
    line: int = Field(..., description="Source line number for error reporting")


class UpstreamServer(BaseModel):
    """Represents a server in an upstream block."""

    address: str = Field(..., description="Server address (host:port or unix socket)")
    weight: int | None = Field(None, description="Server weight for load balancing")
    max_fails: int | None = Field(None, description="Max failures before marking down")
    fail_timeout: str | None = Field(None, description="Timeout for fail count reset")
    backup: bool = Field(default=False, description="Backup server flag")
    down: bool = Field(default=False, description="Server marked as down")


class UpstreamBlock(BaseModel):
    """Represents an NGINX upstream block."""

    name: str = Field(..., description="Upstream group name")
    servers: list[UpstreamServer] = Field(default_factory=list, description="Servers in this upstream group")
    load_balancing: str | None = Field(None, description="Load balancing method: ip_hash, least_conn, etc.")
    keepalive: int | None = Field(None, description="Keepalive connections to upstream")
    line: int = Field(..., description="Source line number")


class SSLConfig(BaseModel):
    """SSL/TLS configuration details."""

    enabled: bool = Field(default=False, description="SSL is enabled")
    certificate: str | None = Field(None, description="Path to SSL certificate")
    certificate_key: str | None = Field(None, description="Path to SSL private key")
    trusted_certificate: str | None = Field(None, description="Path to trusted CA cert")
    protocols: list[str] = Field(default_factory=list, description="Enabled SSL protocols (e.g., TLSv1.2, TLSv1.3)")
    ciphers: str | None = Field(None, description="SSL cipher suite")
    prefer_server_ciphers: bool = Field(default=False, description="Prefer server ciphers")
    session_cache: str | None = Field(None, description="SSL session cache config")
    session_timeout: str | None = Field(None, description="SSL session timeout")


class MapBlock(BaseModel):
    """Represents an NGINX map directive block."""

    source_variable: str = Field(..., description="Source variable to map from (e.g., $uri)")
    target_variable: str = Field(..., description="Target variable to create (e.g., $new_uri)")
    default: str | None = Field(None, description="Default value if no match")
    hostnames: bool = Field(default=False, description="Enable hostname matching mode")
    volatile: bool = Field(default=False, description="Variable is volatile (no caching)")
    mappings: dict[str, str] = Field(default_factory=dict, description="Map entries: source value -> target value")
    line: int = Field(default=0, description="Source line number")


class GeoBlock(BaseModel):
    """Represents an NGINX geo directive block."""

    source_variable: str | None = Field(None, description="Source variable (defaults to $remote_addr if not specified)")
    target_variable: str = Field(..., description="Target variable to create")
    default: str | None = Field(None, description="Default value if no match")
    delete: list[str] = Field(default_factory=list, description="Networks to remove from consideration")
    proxy: list[str] = Field(default_factory=list, description="Trusted proxy addresses for X-Forwarded-For")
    proxy_recursive: bool = Field(default=False, description="Enable recursive proxy address search")
    ranges: bool = Field(default=False, description="Use memory-efficient range mode")
    mappings: dict[str, str] = Field(default_factory=dict, description="Geo entries: CIDR/address -> value")
    includes: list[str] = Field(default_factory=list, description="Included geo data files")
    line: int = Field(default=0, description="Source line number")


class ServerBlock(BaseModel):
    """Represents a complete NGINX server block."""

    server_names: list[str] = Field(default_factory=list, description="All server_name values")
    listen: list[ListenDirective] = Field(default_factory=list, description="All listen directives")
    ssl: SSLConfig = Field(default_factory=SSLConfig, description="SSL configuration")
    root: str | None = Field(None, description="Default document root")
    index: list[str] | None = Field(None, description="Default index files")
    locations: list[LocationBlock] = Field(default_factory=list, description="Location blocks")
    error_pages: dict[int, str] = Field(default_factory=dict, description="Error page mappings (status -> path)")
    access_log: str | None = Field(None, description="Access log path")
    error_log: str | None = Field(None, description="Error log path")
    directives: dict[str, Any] = Field(default_factory=dict, description="Other directives")
    line: int = Field(default=0, description="Source line number")


class ParsedNginxConfig(BaseModel):
    """Complete parsed NGINX configuration from a file."""

    file_path: str = Field(..., description="Full path to the config file")
    file_size: int = Field(..., description="File size in bytes")
    created_at: datetime | None = Field(None, description="File creation time")
    updated_at: datetime | None = Field(None, description="File modification time")
    status: str = Field(default="ok", description="Parse status: ok or failed")
    errors: list[dict[str, Any]] = Field(default_factory=list, description="Parse errors with line numbers")
    server_blocks: list[ServerBlock] = Field(default_factory=list, description="All server blocks in the file")
    upstreams: list[UpstreamBlock] = Field(default_factory=list, description="Upstream definitions")
    maps: list[MapBlock] = Field(default_factory=list, description="Parsed map directive blocks")
    geos: list[GeoBlock] = Field(default_factory=list, description="Parsed geo directive blocks")
    includes: list[str] = Field(default_factory=list, description="Referenced include file patterns (unresolved)")
    resolved_includes: list[str] = Field(
        default_factory=list, description="Resolved include file paths (after glob expansion)"
    )
    included_configs: list["ParsedNginxConfig"] = Field(
        default_factory=list, description="Parsed content of included configuration files"
    )
    raw_directives: list[dict[str, Any]] = Field(
        default_factory=list, description="Full crossplane output for advanced use"
    )


# =============================================================================
# NGINX Control Models (for container management endpoints)
# =============================================================================


class NginxProcessStatus(str, Enum):
    """NGINX process/container status."""

    RUNNING = "running"
    STOPPED = "stopped"
    RESTARTING = "restarting"
    ERROR = "error"
    UNKNOWN = "unknown"


class NginxOperationResult(BaseModel):
    """Result of an NGINX control operation (reload/restart)."""

    success: bool = Field(..., description="Whether the operation completed successfully")
    operation: str = Field(..., description="The operation performed (reload/restart/test)")
    message: str = Field(..., description="Human-readable result message")
    timestamp: datetime = Field(default_factory=datetime.now, description="When the operation was performed")
    duration_ms: int | None = Field(None, description="Operation duration in milliseconds")
    health_verified: bool = Field(default=False, description="Whether health check passed after operation")
    previous_state: str | None = Field(None, description="Container state before operation")
    current_state: str | None = Field(None, description="Container state after operation")
    transaction_id: str | None = Field(None, description="Transaction ID for this operation (for rollback/audit)")
    auto_rolled_back: bool = Field(
        default=False, description="Whether configuration was automatically rolled back due to health check failure"
    )
    rollback_reason: str | None = Field(None, description="Reason for automatic rollback (if auto_rolled_back is True)")
    rollback_transaction_id: str | None = Field(
        None, description="Transaction ID of the rollback operation (if auto_rolled_back is True)"
    )

    # Rich context for AI agents
    suggestions: list[dict[str, Any]] = Field(
        default_factory=list, description="Suggested next actions based on the operation result"
    )
    warnings: list[dict[str, Any]] = Field(
        default_factory=list, description="Non-blocking warnings about the current state"
    )


class NginxStatusResponse(BaseModel):
    """Detailed NGINX status information."""

    status: NginxProcessStatus = Field(..., description="Current NGINX process status")
    container_id: str | None = Field(None, description="Docker container ID (short)")
    container_name: str = Field(..., description="Docker container name")
    uptime_seconds: int | None = Field(None, description="Container uptime in seconds")
    started_at: datetime | None = Field(None, description="When the container was started")

    # Process info
    master_pid: int | None = Field(None, description="NGINX master process PID")
    worker_count: int | None = Field(None, description="Number of worker processes")

    # Connection stats (from stub_status if available)
    active_connections: int | None = Field(None, description="Active client connections")
    accepts: int | None = Field(None, description="Total accepted connections")
    handled: int | None = Field(None, description="Total handled connections")
    requests: int | None = Field(None, description="Total client requests")
    reading: int | None = Field(None, description="Connections reading request")
    writing: int | None = Field(None, description="Connections writing response")
    waiting: int | None = Field(None, description="Keep-alive connections waiting")

    # Health
    health_status: str = Field(default="unknown", description="Container health check status")
    last_health_check: datetime | None = Field(None, description="When health was last verified")

    # Configuration
    config_test_result: bool | None = Field(None, description="Result of last nginx -t")


class NginxConfigTestResult(BaseModel):
    """Result of NGINX configuration test (nginx -t)."""

    success: bool = Field(..., description="Whether configuration is valid")
    message: str = Field(..., description="Result message from nginx -t")
    stdout: str | None = Field(None, description="Standard output from test")
    stderr: str | None = Field(None, description="Standard error from test (contains result)")
    tested_at: datetime = Field(default_factory=datetime.now, description="When the test was performed")
    config_file: str = Field(default="/etc/nginx/nginx.conf", description="Configuration file tested")


class NginxDryRunResult(BaseModel):
    """Result of a dry-run nginx operation."""

    dry_run: bool = Field(default=True, description="Always true for dry-run responses")
    would_succeed: bool = Field(..., description="Whether the operation would likely succeed")
    operation: str = Field(..., description="Operation that would be performed")
    message: str = Field(..., description="Summary of what would happen")

    # Current state info
    current_state: str = Field(..., description="Current NGINX container state")
    container_running: bool = Field(..., description="Whether NGINX container is running")

    # Config validation
    config_valid: bool = Field(default=True, description="Whether current NGINX configuration is valid (from nginx -t)")
    config_test_output: str | None = Field(None, description="Output from nginx -t validation")

    # Impact assessment
    would_drop_connections: bool = Field(
        default=False, description="Whether this operation would drop active connections"
    )
    estimated_downtime_ms: int | None = Field(None, description="Estimated downtime in milliseconds (0 for reload)")

    # Warnings
    warnings: list[str] = Field(default_factory=list, description="Potential issues or considerations")
