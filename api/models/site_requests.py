"""
Request and response models for Site CRUD operations.

Provides Pydantic models for creating, updating, and managing
NGINX site configurations with full validation.
"""

import re
from enum import Enum
from typing import Optional, List, Dict
from datetime import datetime
from urllib.parse import urlparse
from pydantic import BaseModel, Field, field_validator, model_validator


class SiteType(str, Enum):
    """Type of site configuration."""
    STATIC = "static"
    REVERSE_PROXY = "reverse_proxy"


class SiteCreateRequest(BaseModel):
    """Request to create a new site configuration."""

    name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Site identifier (becomes the config filename)"
    )
    server_names: List[str] = Field(
        ...,
        min_length=1,
        description="Domain names for server_name directive"
    )
    site_type: SiteType = Field(
        ...,
        description="Type of site: static file serving or reverse proxy"
    )
    listen_port: int = Field(
        default=80,
        ge=1,
        le=65535,
        description="Port to listen on"
    )

    # Static site options
    root_path: Optional[str] = Field(
        None,
        description="Document root path (required for static sites)"
    )
    index_files: List[str] = Field(
        default=["index.html", "index.htm"],
        description="Index files for static sites"
    )

    # Reverse proxy options
    proxy_pass: Optional[str] = Field(
        None,
        description="Upstream URL (required for reverse proxy sites)"
    )

    # Operation options
    auto_reload: bool = Field(
        default=False,
        description="Automatically reload NGINX after creating the site"
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate site name for safe filesystem usage."""
        # Only allow alphanumeric, hyphens, dots, underscores
        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$", v):
            raise ValueError(
                "Site name must start with alphanumeric and contain only "
                "alphanumeric characters, dots, hyphens, and underscores"
            )
        # Prevent path traversal
        if ".." in v or "/" in v or "\\" in v:
            raise ValueError("Site name cannot contain path separators or '..'")
        return v

    @field_validator("server_names")
    @classmethod
    def validate_server_names(cls, v: List[str]) -> List[str]:
        """Validate server names."""
        validated = []
        for name in v:
            name = name.strip().lower()
            if not name:
                continue
            # Basic domain/IP validation
            if not re.match(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", name):
                raise ValueError(f"Invalid server name: {name}")
            validated.append(name)
        if not validated:
            raise ValueError("At least one valid server name is required")
        return validated

    @field_validator("root_path")
    @classmethod
    def validate_root_path(cls, v: Optional[str]) -> Optional[str]:
        """Validate root path is absolute."""
        if v is not None:
            if not v.startswith("/"):
                raise ValueError("Root path must be an absolute path")
            if ".." in v:
                raise ValueError("Root path cannot contain '..'")
        return v

    @field_validator("proxy_pass")
    @classmethod
    def validate_proxy_pass(cls, v: Optional[str]) -> Optional[str]:
        """Validate proxy pass URL with strict parsing."""
        if v is None:
            return v
        parsed = urlparse(v)
        # Must be http or https
        if parsed.scheme not in ("http", "https"):
            raise ValueError("Proxy pass must be an HTTP or HTTPS URL")
        # Must have a host
        if not parsed.hostname:
            raise ValueError("Proxy pass URL must include a hostname")
        # Reject credentials in URL
        if parsed.username or parsed.password:
            raise ValueError("Proxy pass URL must not contain credentials")
        # Reject query strings and fragments
        if parsed.query:
            raise ValueError("Proxy pass URL must not contain query strings")
        if parsed.fragment:
            raise ValueError("Proxy pass URL must not contain fragments")
        # Reject cloud metadata endpoints (SSRF prevention)
        metadata_hosts = {"169.254.169.254", "metadata.google.internal"}
        if parsed.hostname in metadata_hosts:
            raise ValueError("Proxy pass URL must not target cloud metadata endpoints")
        # Validate port if specified
        if parsed.port is not None and (parsed.port < 1 or parsed.port > 65535):
            raise ValueError("Proxy pass port must be between 1 and 65535")
        return v

    @model_validator(mode="after")
    def validate_site_type_requirements(self):
        """Ensure required fields are present based on site type."""
        if self.site_type == SiteType.STATIC:
            if not self.root_path:
                raise ValueError("root_path is required for static sites")
        elif self.site_type == SiteType.REVERSE_PROXY:
            if not self.proxy_pass:
                raise ValueError("proxy_pass is required for reverse proxy sites")
        return self


class SiteUpdateRequest(BaseModel):
    """Request to update an existing site configuration."""

    server_names: Optional[List[str]] = Field(
        None,
        description="Updated domain names"
    )
    listen_port: Optional[int] = Field(
        None,
        ge=1,
        le=65535,
        description="Updated listen port"
    )
    root_path: Optional[str] = Field(
        None,
        description="Updated document root (for static sites)"
    )
    proxy_pass: Optional[str] = Field(
        None,
        description="Updated upstream URL (for reverse proxy sites)"
    )
    index_files: Optional[List[str]] = Field(
        None,
        description="Updated index files (for static sites)"
    )
    auto_reload: bool = Field(
        default=False,
        description="Automatically reload NGINX after update"
    )

    @field_validator("server_names")
    @classmethod
    def validate_server_names(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        """Validate server names if provided."""
        if v is None:
            return v
        validated = []
        for name in v:
            name = name.strip().lower()
            if not name:
                continue
            if not re.match(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", name):
                raise ValueError(f"Invalid server name: {name}")
            validated.append(name)
        if not validated:
            raise ValueError("At least one valid server name is required")
        return validated

    @field_validator("root_path")
    @classmethod
    def validate_root_path(cls, v: Optional[str]) -> Optional[str]:
        """Validate root path is absolute."""
        if v is not None:
            if not v.startswith("/"):
                raise ValueError("Root path must be an absolute path")
            if ".." in v:
                raise ValueError("Root path cannot contain '..'")
        return v

    @field_validator("proxy_pass")
    @classmethod
    def validate_proxy_pass(cls, v: Optional[str]) -> Optional[str]:
        """Validate proxy pass URL with strict parsing."""
        if v is None:
            return v
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("Proxy pass must be an HTTP or HTTPS URL")
        if not parsed.hostname:
            raise ValueError("Proxy pass URL must include a hostname")
        if parsed.username or parsed.password:
            raise ValueError("Proxy pass URL must not contain credentials")
        if parsed.query:
            raise ValueError("Proxy pass URL must not contain query strings")
        if parsed.fragment:
            raise ValueError("Proxy pass URL must not contain fragments")
        metadata_hosts = {"169.254.169.254", "metadata.google.internal"}
        if parsed.hostname in metadata_hosts:
            raise ValueError("Proxy pass URL must not target cloud metadata endpoints")
        if parsed.port is not None and (parsed.port < 1 or parsed.port > 65535):
            raise ValueError("Proxy pass port must be between 1 and 65535")
        return v


class SiteEnableDisableRequest(BaseModel):
    """Request to enable or disable a site."""

    auto_reload: bool = Field(
        default=False,
        description="Automatically reload NGINX after enabling/disabling"
    )


class SiteMutationResponse(BaseModel):
    """Response from site mutation operations (create, update, delete, enable, disable)."""

    success: bool = Field(..., description="Whether the operation succeeded")
    message: str = Field(..., description="Human-readable result message")
    site_name: str = Field(..., description="Name of the affected site")
    transaction_id: str = Field(..., description="Transaction ID for audit/rollback")
    file_path: str = Field(..., description="Path to the config file")
    reload_required: bool = Field(
        default=True,
        description="Whether NGINX reload is needed to apply changes"
    )
    reloaded: bool = Field(
        default=False,
        description="Whether NGINX was reloaded"
    )
    enabled: bool = Field(
        default=True,
        description="Whether the site is currently enabled"
    )
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the operation was performed"
    )

    # Rich context for AI agents
    suggestions: List[Dict] = Field(
        default_factory=list,
        description="Suggested next actions based on the operation result"
    )
    warnings: List[Dict] = Field(
        default_factory=list,
        description="Non-blocking warnings about the configuration"
    )


class SiteDeleteResponse(BaseModel):
    """Response from site deletion."""

    success: bool = Field(..., description="Whether the deletion succeeded")
    message: str = Field(..., description="Human-readable result message")
    site_name: str = Field(..., description="Name of the deleted site")
    transaction_id: str = Field(..., description="Transaction ID for audit/rollback")
    reload_required: bool = Field(
        default=True,
        description="Whether NGINX reload is needed"
    )
    reloaded: bool = Field(
        default=False,
        description="Whether NGINX was reloaded"
    )

    # Rich context for AI agents
    suggestions: List[Dict] = Field(
        default_factory=list,
        description="Suggested next actions based on the operation result"
    )
    warnings: List[Dict] = Field(
        default_factory=list,
        description="Non-blocking warnings about the configuration"
    )


class ValidationWarning(BaseModel):
    """A non-blocking warning about a configuration."""

    code: str = Field(..., description="Warning code (e.g., 'missing_index')")
    message: str = Field(..., description="Human-readable warning message")
    suggestion: Optional[str] = Field(None, description="How to fix the warning")


class DryRunDiff(BaseModel):
    """Shows what would change in a dry-run operation."""

    operation: str = Field(..., description="Operation type: create, update, delete, enable, disable")
    file_path: str = Field(..., description="Path to the config file that would be affected")
    current_content: Optional[str] = Field(None, description="Current file content (for update/delete)")
    new_content: Optional[str] = Field(None, description="New file content (for create/update)")
    lines_added: int = Field(default=0, description="Number of lines that would be added")
    lines_removed: int = Field(default=0, description="Number of lines that would be removed")


class DryRunResult(BaseModel):
    """
    Result of a dry-run operation.

    Shows what would happen if the operation were executed,
    without actually making any changes.
    """

    dry_run: bool = Field(default=True, description="Always true for dry-run responses")
    would_succeed: bool = Field(..., description="Whether the operation would succeed")
    operation: str = Field(..., description="Operation that would be performed")
    message: str = Field(..., description="Summary of what would happen")

    # Validation
    validation_passed: bool = Field(
        default=True,
        description="Whether NGINX config validation would pass"
    )
    validation_output: Optional[str] = Field(
        None,
        description="Output from nginx -t validation"
    )

    # Warnings (non-blocking issues)
    warnings: List[ValidationWarning] = Field(
        default_factory=list,
        description="Non-blocking warnings about the configuration"
    )

    # What would change
    diff: Optional[DryRunDiff] = Field(
        None,
        description="Details of what would change"
    )

    # Impact analysis
    affected_sites: List[str] = Field(
        default_factory=list,
        description="Sites that would be affected by this operation"
    )
    reload_required: bool = Field(
        default=True,
        description="Whether NGINX reload would be needed"
    )

    # For create/update operations
    generated_config: Optional[str] = Field(
        None,
        description="The NGINX config that would be generated"
    )
