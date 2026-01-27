"""
Pydantic models for NGINX configuration structures.

These models represent the full hierarchical structure of NGINX configurations
as parsed by crossplane. They provide rich typing for AI agents and enable
detailed configuration inspection.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class ListenDirective(BaseModel):
    """Represents a listen directive with all its options."""

    port: int = Field(..., description="Port number to listen on")
    address: Optional[str] = Field(None, description="IP address or socket path")
    ssl: bool = Field(default=False, description="SSL/TLS enabled on this listener")
    http2: bool = Field(default=False, description="HTTP/2 enabled")
    default_server: bool = Field(default=False, description="Default server for this port")
    raw_args: List[str] = Field(default_factory=list, description="Original arguments")


class LocationBlock(BaseModel):
    """Represents an NGINX location block."""

    modifier: Optional[str] = Field(
        None,
        description="Location modifier: =, ~, ~*, ^~, or None for prefix match"
    )
    path: str = Field(..., description="Location path or pattern")
    proxy_pass: Optional[str] = Field(None, description="Upstream URL for reverse proxy")
    root: Optional[str] = Field(None, description="Document root for this location")
    alias: Optional[str] = Field(None, description="Alias path")
    index: Optional[List[str]] = Field(None, description="Index files")
    try_files: Optional[str] = Field(None, description="try_files directive value")
    return_code: Optional[int] = Field(None, description="Return status code")
    return_value: Optional[str] = Field(None, description="Return body or redirect URL")
    rewrite_rules: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Rewrite rules in this location"
    )
    headers: Dict[str, str] = Field(
        default_factory=dict,
        description="Headers set via proxy_set_header or add_header"
    )
    directives: Dict[str, Any] = Field(
        default_factory=dict,
        description="Other directives as key-value pairs"
    )
    line: int = Field(..., description="Source line number for error reporting")


class UpstreamServer(BaseModel):
    """Represents a server in an upstream block."""

    address: str = Field(..., description="Server address (host:port or unix socket)")
    weight: Optional[int] = Field(None, description="Server weight for load balancing")
    max_fails: Optional[int] = Field(None, description="Max failures before marking down")
    fail_timeout: Optional[str] = Field(None, description="Timeout for fail count reset")
    backup: bool = Field(default=False, description="Backup server flag")
    down: bool = Field(default=False, description="Server marked as down")


class UpstreamBlock(BaseModel):
    """Represents an NGINX upstream block."""

    name: str = Field(..., description="Upstream group name")
    servers: List[UpstreamServer] = Field(
        default_factory=list,
        description="Servers in this upstream group"
    )
    load_balancing: Optional[str] = Field(
        None,
        description="Load balancing method: ip_hash, least_conn, etc."
    )
    keepalive: Optional[int] = Field(None, description="Keepalive connections to upstream")
    line: int = Field(..., description="Source line number")


class SSLConfig(BaseModel):
    """SSL/TLS configuration details."""

    enabled: bool = Field(default=False, description="SSL is enabled")
    certificate: Optional[str] = Field(None, description="Path to SSL certificate")
    certificate_key: Optional[str] = Field(None, description="Path to SSL private key")
    trusted_certificate: Optional[str] = Field(None, description="Path to trusted CA cert")
    protocols: List[str] = Field(
        default_factory=list,
        description="Enabled SSL protocols (e.g., TLSv1.2, TLSv1.3)"
    )
    ciphers: Optional[str] = Field(None, description="SSL cipher suite")
    prefer_server_ciphers: bool = Field(default=False, description="Prefer server ciphers")
    session_cache: Optional[str] = Field(None, description="SSL session cache config")
    session_timeout: Optional[str] = Field(None, description="SSL session timeout")


class ServerBlock(BaseModel):
    """Represents a complete NGINX server block."""

    server_names: List[str] = Field(
        default_factory=list,
        description="All server_name values"
    )
    listen: List[ListenDirective] = Field(
        default_factory=list,
        description="All listen directives"
    )
    ssl: SSLConfig = Field(
        default_factory=SSLConfig,
        description="SSL configuration"
    )
    root: Optional[str] = Field(None, description="Default document root")
    index: Optional[List[str]] = Field(None, description="Default index files")
    locations: List[LocationBlock] = Field(
        default_factory=list,
        description="Location blocks"
    )
    error_pages: Dict[int, str] = Field(
        default_factory=dict,
        description="Error page mappings (status -> path)"
    )
    access_log: Optional[str] = Field(None, description="Access log path")
    error_log: Optional[str] = Field(None, description="Error log path")
    directives: Dict[str, Any] = Field(
        default_factory=dict,
        description="Other directives"
    )
    line: int = Field(default=0, description="Source line number")


class ParsedNginxConfig(BaseModel):
    """Complete parsed NGINX configuration from a file."""

    file_path: str = Field(..., description="Full path to the config file")
    file_size: int = Field(..., description="File size in bytes")
    created_at: Optional[datetime] = Field(None, description="File creation time")
    updated_at: Optional[datetime] = Field(None, description="File modification time")
    status: str = Field(default="ok", description="Parse status: ok or failed")
    errors: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Parse errors with line numbers"
    )
    server_blocks: List[ServerBlock] = Field(
        default_factory=list,
        description="All server blocks in the file"
    )
    upstreams: List[UpstreamBlock] = Field(
        default_factory=list,
        description="Upstream definitions"
    )
    maps: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Map directive blocks"
    )
    includes: List[str] = Field(
        default_factory=list,
        description="Referenced include files"
    )
    raw_directives: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Full crossplane output for advanced use"
    )


# =============================================================================
# NGINX Control Models (for container management endpoints)
# =============================================================================

from enum import Enum


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
    timestamp: datetime = Field(
        default_factory=datetime.now,
        description="When the operation was performed"
    )
    duration_ms: Optional[int] = Field(None, description="Operation duration in milliseconds")
    health_verified: bool = Field(
        default=False,
        description="Whether health check passed after operation"
    )
    previous_state: Optional[str] = Field(None, description="Container state before operation")
    current_state: Optional[str] = Field(None, description="Container state after operation")


class NginxStatusResponse(BaseModel):
    """Detailed NGINX status information."""

    status: NginxProcessStatus = Field(..., description="Current NGINX process status")
    container_id: Optional[str] = Field(None, description="Docker container ID (short)")
    container_name: str = Field(..., description="Docker container name")
    uptime_seconds: Optional[int] = Field(None, description="Container uptime in seconds")
    started_at: Optional[datetime] = Field(None, description="When the container was started")

    # Process info
    master_pid: Optional[int] = Field(None, description="NGINX master process PID")
    worker_count: Optional[int] = Field(None, description="Number of worker processes")

    # Connection stats (from stub_status if available)
    active_connections: Optional[int] = Field(None, description="Active client connections")
    accepts: Optional[int] = Field(None, description="Total accepted connections")
    handled: Optional[int] = Field(None, description="Total handled connections")
    requests: Optional[int] = Field(None, description="Total client requests")
    reading: Optional[int] = Field(None, description="Connections reading request")
    writing: Optional[int] = Field(None, description="Connections writing response")
    waiting: Optional[int] = Field(None, description="Keep-alive connections waiting")

    # Health
    health_status: str = Field(default="unknown", description="Container health check status")
    last_health_check: Optional[datetime] = Field(
        None,
        description="When health was last verified"
    )

    # Configuration
    config_test_result: Optional[bool] = Field(
        None,
        description="Result of last nginx -t"
    )


class NginxConfigTestResult(BaseModel):
    """Result of NGINX configuration test (nginx -t)."""

    success: bool = Field(..., description="Whether configuration is valid")
    message: str = Field(..., description="Result message from nginx -t")
    stdout: Optional[str] = Field(None, description="Standard output from test")
    stderr: Optional[str] = Field(None, description="Standard error from test (contains result)")
    tested_at: datetime = Field(
        default_factory=datetime.now,
        description="When the test was performed"
    )
    config_file: str = Field(
        default="/etc/nginx/nginx.conf",
        description="Configuration file tested"
    )
