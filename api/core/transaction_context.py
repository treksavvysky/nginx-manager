"""
Transaction context manager for wrapping mutation operations.

Provides a clean interface for ensuring all mutations are
wrapped in transactions with automatic snapshot and rollback handling.
"""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from config import settings
from core.transaction_manager import get_transaction_manager
from models.transaction import OperationType, Transaction

logger = logging.getLogger(__name__)


class TransactionContext:
    """Context for a transaction in progress."""

    def __init__(self, transaction: Transaction):
        self.transaction = transaction
        self.result_data: dict[str, Any] | None = None
        self.after_state: dict[str, Any] | None = None
        self.nginx_validated: bool = False
        self.health_verified: bool = False

    @property
    def id(self) -> str:
        """Get the transaction ID."""
        return self.transaction.id

    def set_result(self, result: dict[str, Any]) -> None:
        """Set the operation result data."""
        self.result_data = result

    def set_after_state(self, state: dict[str, Any]) -> None:
        """Set the after-state summary."""
        self.after_state = state

    def set_nginx_validated(self, validated: bool = True) -> None:
        """Mark nginx configuration as validated."""
        self.nginx_validated = validated

    def set_health_verified(self, verified: bool = True) -> None:
        """Mark health check as verified."""
        self.health_verified = verified


@asynccontextmanager
async def transactional_operation(
    operation: OperationType,
    resource_type: str,
    resource_id: str | None = None,
    request_data: dict[str, Any] | None = None,
    auto_rollback_on_failure: bool = True,
) -> AsyncGenerator[TransactionContext, None]:
    """
    Context manager for transactional operations.

    Wraps any mutation operation in a transaction with automatic
    snapshot creation, event recording, and optional rollback on failure.

    Usage:
        async with transactional_operation(
            operation=OperationType.SITE_CREATE,
            resource_type="site",
            resource_id="example.com"
        ) as ctx:
            # Perform the operation
            result = await create_site_config(...)
            ctx.set_result(result)

            # If an exception is raised, transaction is marked failed
            # and auto-rollback occurs if enabled

    Args:
        operation: Type of operation being performed
        resource_type: Type of resource being affected
        resource_id: Identifier of the resource (optional)
        request_data: Original request parameters (optional)
        auto_rollback_on_failure: Whether to auto-rollback on failure

    Yields:
        TransactionContext for tracking operation state
    """
    transaction_manager = get_transaction_manager()

    # Begin transaction and capture before-state
    transaction = await transaction_manager.begin_transaction(
        operation=operation, resource_type=resource_type, resource_id=resource_id, request_data=request_data
    )

    # Mark as in progress
    await transaction_manager.start_transaction(transaction.id)

    ctx = TransactionContext(transaction)

    try:
        yield ctx

        # Success - complete transaction
        await transaction_manager.complete_transaction(
            transaction_id=transaction.id,
            result_data=ctx.result_data,
            after_state=ctx.after_state,
            nginx_validated=ctx.nginx_validated,
            health_verified=ctx.health_verified,
        )

    except Exception as e:
        # Failure - mark failed and optionally rollback
        logger.error(f"Transaction {transaction.id} failed: {e}")

        await transaction_manager.fail_transaction(
            transaction_id=transaction.id,
            error_message=str(e),
            error_details={"exception_type": type(e).__name__},
            auto_rollback=auto_rollback_on_failure and settings.auto_rollback_on_failure,
        )
        raise


class TransactionError(Exception):
    """Base exception for transaction errors."""

    def __init__(self, message: str, transaction_id: str | None = None):
        self.message = message
        self.transaction_id = transaction_id
        super().__init__(message)


class RollbackError(TransactionError):
    """Error during rollback operation."""

    pass


class SnapshotError(TransactionError):
    """Error during snapshot operation."""

    pass
