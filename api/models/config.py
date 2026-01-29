"""
Pydantic models for NGINX configuration management.

These models define the data structures used throughout the API
and automatically generate OpenAPI schemas for documentation.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ConfigStatus(str, Enum):
    """Status of NGINX configuration."""

    VALID = "valid"
    INVALID = "invalid"
    UNTESTED = "untested"


class SiteConfig(BaseModel):
    """
    NGINX server block configuration.

    Represents a single .conf file in the conf.d directory.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "example.com",
                "server_name": "example.com www.example.com",
                "listen_port": 80,
                "ssl_enabled": False,
                "root_path": "/var/www/html",
                "proxy_pass": None,
            }
        }
    )

    name: str = Field(..., description="Unique identifier for this site configuration", min_length=1, max_length=100)
    server_name: str = Field(
        ...,
        description="NGINX server_name directive (domain names)",
        examples=["example.com", "example.com www.example.com"],
    )
    listen_port: int = Field(default=80, description="Port to listen on", ge=1, le=65535)
    ssl_enabled: bool = Field(default=False, description="Whether SSL/TLS is enabled for this site")
    root_path: str | None = Field(default=None, description="Document root path for static files")
    proxy_pass: str | None = Field(
        default=None,
        description="Upstream URL for reverse proxy",
        examples=["http://localhost:3000", "http://backend:8080"],
    )
    status: ConfigStatus = Field(
        default=ConfigStatus.UNTESTED, description="Current validation status of the configuration"
    )
    created_at: datetime | None = Field(default=None, description="When this configuration was created")
    updated_at: datetime | None = Field(default=None, description="When this configuration was last modified")


class SiteConfigResponse(BaseModel):
    """Response model for site configuration with additional metadata."""

    name: str = Field(..., description="Unique identifier for this site configuration")
    server_name: str | None = Field(None, description="NGINX server_name directive")
    listen_ports: list[int] = Field(default_factory=list, description="Ports this site listens on")
    ssl_enabled: bool = Field(default=False, description="Whether SSL/TLS is enabled")
    root_path: str | None = Field(None, description="Document root path")
    proxy_pass: str | None = Field(None, description="Upstream URL for reverse proxy")
    has_ssl_cert: bool = Field(default=False, description="Whether SSL certificate is configured")
    status: ConfigStatus = Field(default=ConfigStatus.UNTESTED, description="Config validation status")
    enabled: bool = Field(default=True, description="Whether the site is enabled (active in NGINX)")

    # File metadata
    file_path: str = Field(..., description="Full path to the configuration file")
    file_size: int = Field(..., description="Size of the configuration file in bytes")
    created_at: datetime | None = Field(None, description="When the file was created")
    updated_at: datetime | None = Field(None, description="When the file was last modified")
    last_validated: datetime | None = Field(None, description="When this config was last validated")

    # Rich fields (optional, for enhanced consumers)
    server_names: list[str] | None = Field(None, description="All server_name values as a list")
    locations: list[dict[str, Any]] | None = Field(None, description="Location blocks with proxy_pass, root, headers")
    upstreams: list[dict[str, Any]] | None = Field(None, description="Upstream definitions with servers")
    ssl_config: dict[str, Any] | None = Field(None, description="Detailed SSL configuration")
    parse_errors: list[dict[str, Any]] | None = Field(None, description="Parse errors with line numbers")
    certificate: dict[str, Any] | None = Field(
        None, description="SSL certificate details if a matching certificate exists"
    )


class ConfigValidationResult(BaseModel):
    """Result of NGINX configuration validation."""

    is_valid: bool = Field(..., description="Whether the configuration is valid")
    error_message: str | None = Field(default=None, description="Error message if validation failed")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal warnings about the configuration")
    validated_at: datetime = Field(..., description="When the validation was performed")


class ApiResponse(BaseModel):
    """Standard API response wrapper."""

    success: bool = Field(..., description="Whether the operation was successful")
    message: str = Field(..., description="Human-readable message about the operation result")
    data: dict[str, Any] | None = Field(default=None, description="Response data payload")
