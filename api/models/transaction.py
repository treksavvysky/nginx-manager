"""
Transaction models for tracking configuration changes.

Transactions capture before/after state for all mutations,
enabling rollback and providing a complete audit trail.
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class TransactionStatus(str, Enum):
    """Transaction lifecycle states."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class OperationType(str, Enum):
    """Types of mutation operations."""

    # Site operations
    SITE_CREATE = "site_create"
    SITE_UPDATE = "site_update"
    SITE_DELETE = "site_delete"
    SITE_ENABLE = "site_enable"
    SITE_DISABLE = "site_disable"

    # NGINX control
    NGINX_RELOAD = "nginx_reload"
    NGINX_RESTART = "nginx_restart"

    # SSL operations (Phase 3)
    SSL_INSTALL = "ssl_install"
    SSL_RENEW = "ssl_renew"
    SSL_REMOVE = "ssl_remove"

    # Workflows (Phase 4)
    WORKFLOW_EXECUTE = "workflow_execute"

    # Rollback
    ROLLBACK = "rollback"


class Transaction(BaseModel):
    """
    Represents an atomic configuration change with full context.

    Every mutation creates a transaction that captures before/after state,
    enabling reliable rollback and complete audit trail.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique transaction identifier (UUID)")
    operation: OperationType = Field(..., description="Type of operation performed")
    status: TransactionStatus = Field(default=TransactionStatus.PENDING, description="Current transaction status")

    # Timing
    created_at: datetime = Field(default_factory=datetime.utcnow, description="When transaction was initiated")
    started_at: datetime | None = Field(None, description="When operation execution began")
    completed_at: datetime | None = Field(None, description="When transaction reached terminal state")
    duration_ms: int | None = Field(None, description="Total execution time in milliseconds")

    # Target
    resource_type: str = Field(..., description="Type of resource affected (site, certificate, nginx)")
    resource_id: str | None = Field(None, description="Identifier of affected resource (e.g., site name)")

    # State
    snapshot_path: str | None = Field(None, description="Path to snapshot directory for this transaction")
    before_state: dict[str, Any] | None = Field(None, description="Summary of state before change")
    after_state: dict[str, Any] | None = Field(None, description="Summary of state after change")

    # Input/Output
    request_data: dict[str, Any] | None = Field(None, description="Original request parameters")
    result_data: dict[str, Any] | None = Field(None, description="Operation result details")

    # Error handling
    error_message: str | None = Field(None, description="Error description if failed")
    error_details: dict[str, Any] | None = Field(None, description="Structured error information")

    # Relationships
    parent_transaction_id: str | None = Field(None, description="ID of parent transaction (for rollbacks)")
    rollback_transaction_id: str | None = Field(None, description="ID of transaction that rolled this one back")

    # Verification
    nginx_validated: bool = Field(default=False, description="Whether nginx -t passed after change")
    health_verified: bool = Field(default=False, description="Whether health check passed after change")


class TransactionSummary(BaseModel):
    """Lightweight transaction info for list views."""

    id: str
    operation: OperationType
    status: TransactionStatus
    resource_type: str
    resource_id: str | None = None
    created_at: datetime
    completed_at: datetime | None = None
    duration_ms: int | None = None
    error_message: str | None = None


class FileDiff(BaseModel):
    """Diff information for a single file."""

    file_path: str = Field(..., description="Path to the file")
    change_type: str = Field(..., description="added, modified, or deleted")
    additions: int = Field(default=0, description="Lines added")
    deletions: int = Field(default=0, description="Lines deleted")
    diff_content: str | None = Field(None, description="Unified diff content")


class TransactionDiff(BaseModel):
    """Diff information for a transaction."""

    files_changed: int = Field(default=0, description="Number of files changed")
    total_additions: int = Field(default=0, description="Total lines added")
    total_deletions: int = Field(default=0, description="Total lines deleted")
    files: list[FileDiff] = Field(default_factory=list, description="Per-file diffs")


class TransactionDetail(Transaction):
    """Full transaction with diff information."""

    diff: TransactionDiff | None = Field(None, description="Configuration change diff")
    affected_files: list[str] = Field(default_factory=list, description="List of files modified")
    can_rollback: bool = Field(default=False, description="Whether this transaction can be rolled back")
    rollback_reason: str | None = Field(None, description="Why rollback is not available if can_rollback is False")


class RollbackRequest(BaseModel):
    """Request to rollback a transaction."""

    reason: str | None = Field(None, description="Reason for rollback (for audit)")
    skip_health_check: bool = Field(default=False, description="Skip health verification after rollback")


class RollbackResult(BaseModel):
    """Result of a rollback operation."""

    success: bool = Field(..., description="Whether rollback succeeded")
    rollback_transaction_id: str = Field(..., description="ID of the new transaction created for rollback")
    original_transaction_id: str = Field(..., description="ID of the transaction that was rolled back")
    restored_state: dict[str, Any] = Field(default_factory=dict, description="Summary of restored configuration state")
    message: str = Field(..., description="Human-readable result message")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal warnings during rollback")


class TransactionListResponse(BaseModel):
    """Paginated list of transactions."""

    transactions: list[TransactionSummary]
    total: int = Field(..., description="Total number of matching transactions")
    limit: int = Field(default=50, description="Transactions per page")
    offset: int = Field(default=0, description="Current offset")
    has_more: bool = Field(default=False, description="More transactions available")
