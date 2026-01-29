"""
Workflow models for compound agent operations.

Provides Pydantic models for multi-step workflows with
checkpoint-based execution and automatic rollback support.
"""

import re
import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class WorkflowType(str, Enum):
    """Available workflow types."""

    SETUP_SITE = "setup_site"
    MIGRATE_SITE = "migrate_site"


class WorkflowStepStatus(str, Enum):
    """Status of an individual workflow step."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ROLLED_BACK = "rolled_back"


class WorkflowStatus(str, Enum):
    """Overall workflow execution status."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    PARTIALLY_COMPLETED = "partially_completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


# =============================================================================
# Step Result
# =============================================================================


class WorkflowStepResult(BaseModel):
    """Result of a single workflow step execution."""

    step_name: str = Field(..., description="Step identifier")
    step_number: int = Field(..., description="Step sequence number (1-based)")
    status: WorkflowStepStatus = Field(..., description="Step outcome")
    message: str = Field(..., description="Human-readable result")
    transaction_id: str | None = Field(None, description="Transaction ID if step created one (rollback point)")
    started_at: datetime | None = Field(None, description="When step execution began")
    completed_at: datetime | None = Field(None, description="When step finished")
    duration_ms: int | None = Field(None, description="Step execution time in milliseconds")
    data: dict[str, Any] | None = Field(None, description="Step-specific result data")
    error: str | None = Field(None, description="Error message if failed")
    is_checkpoint: bool = Field(default=False, description="Whether this step is a rollback point")


# =============================================================================
# Workflow Requests
# =============================================================================


class SetupSiteRequest(BaseModel):
    """
    Request for the setup-site workflow.

    Creates a site configuration, optionally requests an SSL certificate,
    and verifies everything is working.
    """

    name: str = Field(
        ..., min_length=1, max_length=100, description="Site name/identifier (becomes the config filename)"
    )
    server_names: list[str] = Field(..., min_length=1, description="Domain names for server_name directive")
    site_type: str = Field(..., description="Type of site: 'static' or 'reverse_proxy'")
    listen_port: int = Field(default=80, ge=1, le=65535, description="Port to listen on")

    # Static site options
    root_path: str | None = Field(None, description="Document root path (required for static sites)")

    # Reverse proxy options
    proxy_pass: str | None = Field(None, description="Backend URL (required for reverse proxy sites)")

    # SSL options
    request_ssl: bool = Field(default=False, description="Request a Let's Encrypt SSL certificate after site creation")
    ssl_alt_names: list[str] | None = Field(None, description="Additional domain names for the SSL certificate (SANs)")
    auto_renew: bool = Field(default=True, description="Enable automatic certificate renewal")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$", v):
            raise ValueError(
                "Site name must start with alphanumeric and contain only "
                "alphanumeric characters, dots, hyphens, and underscores"
            )
        if ".." in v or "/" in v or "\\" in v:
            raise ValueError("Site name cannot contain path separators or '..'")
        return v

    @field_validator("server_names")
    @classmethod
    def validate_server_names(cls, v: list[str]) -> list[str]:
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

    @field_validator("site_type")
    @classmethod
    def validate_site_type(cls, v: str) -> str:
        if v.lower() not in ("static", "reverse_proxy"):
            raise ValueError("site_type must be 'static' or 'reverse_proxy'")
        return v.lower()

    @field_validator("root_path")
    @classmethod
    def validate_root_path(cls, v: str | None) -> str | None:
        if v is not None:
            if not v.startswith("/"):
                raise ValueError("Root path must be an absolute path")
            if ".." in v:
                raise ValueError("Root path cannot contain '..'")
        return v

    @field_validator("proxy_pass")
    @classmethod
    def validate_proxy_pass(cls, v: str | None) -> str | None:
        if v is not None:
            if not v.startswith(("http://", "https://")):
                raise ValueError("Proxy pass must be an HTTP or HTTPS URL")
        return v

    @model_validator(mode="after")
    def validate_site_type_requirements(self):
        if self.site_type == "static":
            if not self.root_path:
                raise ValueError("root_path is required for static sites")
        elif self.site_type == "reverse_proxy":
            if not self.proxy_pass:
                raise ValueError("proxy_pass is required for reverse proxy sites")
        return self


class MigrateSiteRequest(BaseModel):
    """
    Request for the migrate-site workflow.

    Safely updates a site configuration with automatic
    backup, validation, and rollback on failure.
    """

    name: str = Field(..., min_length=1, max_length=100, description="Site name to migrate")
    server_names: list[str] | None = Field(None, description="Updated domain names")
    listen_port: int | None = Field(None, ge=1, le=65535, description="Updated listen port")
    root_path: str | None = Field(None, description="Updated document root")
    proxy_pass: str | None = Field(None, description="Updated backend URL")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$", v):
            raise ValueError(
                "Site name must start with alphanumeric and contain only "
                "alphanumeric characters, dots, hyphens, and underscores"
            )
        if ".." in v or "/" in v or "\\" in v:
            raise ValueError("Site name cannot contain path separators or '..'")
        return v

    @field_validator("server_names")
    @classmethod
    def validate_server_names(cls, v: list[str] | None) -> list[str] | None:
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
    def validate_root_path(cls, v: str | None) -> str | None:
        if v is not None:
            if not v.startswith("/"):
                raise ValueError("Root path must be an absolute path")
            if ".." in v:
                raise ValueError("Root path cannot contain '..'")
        return v

    @field_validator("proxy_pass")
    @classmethod
    def validate_proxy_pass(cls, v: str | None) -> str | None:
        if v is not None:
            if not v.startswith(("http://", "https://")):
                raise ValueError("Proxy pass must be an HTTP or HTTPS URL")
        return v


# =============================================================================
# Workflow Responses
# =============================================================================


class WorkflowResponse(BaseModel):
    """Response from a workflow execution."""

    workflow_id: str = Field(
        default_factory=lambda: f"wf-{uuid.uuid4().hex[:12]}", description="Unique workflow execution ID"
    )
    workflow_type: WorkflowType = Field(..., description="Type of workflow executed")
    status: WorkflowStatus = Field(..., description="Overall workflow outcome")
    message: str = Field(..., description="Summary of what happened")

    # Execution details
    total_steps: int = Field(..., description="Total number of steps in workflow")
    completed_steps: int = Field(default=0, description="Steps that completed successfully")
    failed_step: str | None = Field(None, description="Name of step that failed, if any")

    # Step details
    steps: list[WorkflowStepResult] = Field(default_factory=list, description="Detailed result for each step")

    # Rollback info
    rolled_back: bool = Field(default=False, description="Whether rollback was performed after failure")
    rollback_details: dict[str, Any] | None = Field(None, description="Details of rollback operations if performed")

    # Timing
    started_at: datetime | None = Field(None, description="Workflow start time")
    completed_at: datetime | None = Field(None, description="Workflow end time")
    total_duration_ms: int | None = Field(None, description="Total execution time")

    # Transaction tracking
    transaction_ids: list[str] = Field(default_factory=list, description="All transaction IDs created during workflow")

    # AI context
    suggestions: list[dict[str, Any]] = Field(default_factory=list, description="Suggested next actions")
    warnings: list[dict[str, Any]] = Field(default_factory=list, description="Non-blocking warnings")


class WorkflowDryRunResponse(BaseModel):
    """Response from a dry-run workflow execution."""

    dry_run: bool = Field(default=True, description="Always true for dry-run responses")
    workflow_type: WorkflowType = Field(..., description="Type of workflow")
    would_succeed: bool = Field(..., description="Whether the workflow is expected to succeed (best estimate)")
    message: str = Field(..., description="Summary of what would happen")

    steps: list[dict[str, Any]] = Field(default_factory=list, description="What each step would do")

    warnings: list[dict[str, Any]] = Field(default_factory=list, description="Potential issues identified")

    prerequisites_met: bool = Field(default=True, description="Whether all prerequisites are satisfied")
    missing_prerequisites: list[str] = Field(default_factory=list, description="Prerequisites that are not met")


class WorkflowProgressEvent(BaseModel):
    """SSE event for workflow progress updates."""

    workflow_id: str = Field(..., description="Workflow execution ID")
    event_type: str = Field(
        ...,
        description="Event type: workflow_started, step_started, step_completed, "
        "step_failed, step_skipped, workflow_completed, workflow_failed",
    )
    step_name: str | None = Field(None, description="Current step name")
    step_number: int | None = Field(None, description="Current step number (1-based)")
    total_steps: int = Field(default=0, description="Total steps in workflow")
    message: str = Field(default="", description="Human-readable progress message")
    data: dict[str, Any] | None = Field(None, description="Event-specific data")
