"""
Request and response models for Site CRUD operations.

Provides Pydantic models for creating, updating, and managing
NGINX site configurations with full validation.
"""

import re
from enum import Enum
from typing import Optional, List, Dict
from datetime import datetime
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
        """Validate proxy pass URL."""
        if v is not None:
            if not v.startswith(("http://", "https://")):
                raise ValueError("Proxy pass must be an HTTP or HTTPS URL")
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
        """Validate proxy pass URL."""
        if v is not None:
            if not v.startswith(("http://", "https://")):
                raise ValueError("Proxy pass must be an HTTP or HTTPS URL")
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
