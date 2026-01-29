"""
Transaction lifecycle management.

Coordinates snapshots, events, and rollback operations
for all mutation transactions in the system.
"""

import logging
from datetime import datetime
from typing import Any

from config import settings
from core.database import deserialize_json, get_database, serialize_json
from core.event_store import get_event_store
from core.snapshot_service import get_snapshot_service
from models.event import EventSeverity
from models.transaction import (
    FileDiff,
    OperationType,
    RollbackResult,
    Transaction,
    TransactionDetail,
    TransactionDiff,
    TransactionListResponse,
    TransactionStatus,
    TransactionSummary,
)

logger = logging.getLogger(__name__)


class TransactionManager:
    """Manages transaction lifecycle for all mutation operations."""

    def __init__(self):
        self.db = get_database()
        self.event_store = get_event_store()
        self.snapshot_service = get_snapshot_service()

    async def begin_transaction(
        self,
        operation: OperationType,
        resource_type: str,
        resource_id: str | None = None,
        request_data: dict[str, Any] | None = None,
    ) -> Transaction:
        """
        Create a new transaction and capture before-state snapshot.

        Args:
            operation: Type of operation being performed
            resource_type: Type of resource being affected
            resource_id: Identifier of the resource
            request_data: Original request parameters

        Returns:
            The created Transaction object
        """
        transaction = Transaction(
            operation=operation,
            resource_type=resource_type,
            resource_id=resource_id,
            request_data=request_data,
            status=TransactionStatus.PENDING,
        )

        # Capture before-state snapshot
        if settings.auto_backup:
            snapshot = await self.snapshot_service.create_snapshot(transaction.id, stage="before")
            transaction.snapshot_path = snapshot.path
            transaction.before_state = {"files": snapshot.files, "total_size": snapshot.total_size}

        # Save transaction to database
        await self._save_transaction(transaction)

        # Record event
        await self.event_store.record_event(
            category="transaction",
            action="created",
            message=f"Transaction started: {operation.value} on {resource_type}",
            severity=EventSeverity.INFO,
            transaction_id=transaction.id,
            resource_type=resource_type,
            resource_id=resource_id,
            details={"request_data": request_data},
        )

        logger.info(f"Transaction {transaction.id} created: {operation.value}")

        return transaction

    async def start_transaction(self, transaction_id: str) -> Transaction | None:
        """Mark a transaction as in progress."""
        transaction = await self.get_transaction(transaction_id)
        if not transaction:
            return None

        transaction.status = TransactionStatus.IN_PROGRESS
        transaction.started_at = datetime.utcnow()

        await self._update_transaction(transaction)

        return transaction

    async def complete_transaction(
        self,
        transaction_id: str,
        result_data: dict[str, Any] | None = None,
        after_state: dict[str, Any] | None = None,
        nginx_validated: bool = False,
        health_verified: bool = False,
    ) -> Transaction | None:
        """
        Mark transaction as completed successfully.

        Args:
            transaction_id: Transaction to complete
            result_data: Operation result details
            after_state: Summary of state after change
            nginx_validated: Whether nginx -t passed
            health_verified: Whether health check passed

        Returns:
            The updated Transaction object
        """
        transaction = await self.get_transaction(transaction_id)
        if not transaction:
            return None

        transaction.status = TransactionStatus.COMPLETED
        transaction.completed_at = datetime.utcnow()
        transaction.result_data = result_data
        transaction.nginx_validated = nginx_validated
        transaction.health_verified = health_verified

        # Calculate duration
        if transaction.started_at:
            duration = transaction.completed_at - transaction.started_at
            transaction.duration_ms = int(duration.total_seconds() * 1000)
        elif transaction.created_at:
            duration = transaction.completed_at - transaction.created_at
            transaction.duration_ms = int(duration.total_seconds() * 1000)

        # Capture after-state snapshot
        if settings.auto_backup:
            snapshot = await self.snapshot_service.create_snapshot(transaction_id, stage="after")
            transaction.after_state = after_state or {"files": snapshot.files, "total_size": snapshot.total_size}

        await self._update_transaction(transaction)

        # Record event
        await self.event_store.record_event(
            category="transaction",
            action="completed",
            message=f"Transaction completed: {transaction.operation.value}",
            severity=EventSeverity.INFO,
            transaction_id=transaction_id,
            resource_type=transaction.resource_type,
            resource_id=transaction.resource_id,
            details={
                "duration_ms": transaction.duration_ms,
                "nginx_validated": nginx_validated,
                "health_verified": health_verified,
            },
        )

        logger.info(f"Transaction {transaction_id} completed in {transaction.duration_ms}ms")

        return transaction

    async def fail_transaction(
        self,
        transaction_id: str,
        error_message: str,
        error_details: dict[str, Any] | None = None,
        auto_rollback: bool = True,
    ) -> Transaction | None:
        """
        Mark transaction as failed and optionally rollback.

        Args:
            transaction_id: Transaction to fail
            error_message: Error description
            error_details: Structured error information
            auto_rollback: Whether to automatically rollback

        Returns:
            The updated Transaction object
        """
        transaction = await self.get_transaction(transaction_id)
        if not transaction:
            return None

        transaction.status = TransactionStatus.FAILED
        transaction.completed_at = datetime.utcnow()
        transaction.error_message = error_message
        transaction.error_details = error_details

        # Calculate duration
        if transaction.started_at:
            duration = transaction.completed_at - transaction.started_at
            transaction.duration_ms = int(duration.total_seconds() * 1000)

        await self._update_transaction(transaction)

        # Record event
        await self.event_store.record_event(
            category="transaction",
            action="failed",
            message=f"Transaction failed: {error_message}",
            severity=EventSeverity.ERROR,
            transaction_id=transaction_id,
            resource_type=transaction.resource_type,
            resource_id=transaction.resource_id,
            details=error_details,
        )

        logger.error(f"Transaction {transaction_id} failed: {error_message}")

        # Auto-rollback if enabled
        if auto_rollback and settings.auto_rollback_on_failure:
            can_rollback, _reason = await self.can_rollback(transaction_id)
            if can_rollback:
                logger.info(f"Auto-rolling back failed transaction {transaction_id}")
                await self.rollback_transaction(transaction_id, reason="Auto-rollback on failure")

        return transaction

    async def rollback_transaction(self, transaction_id: str, reason: str | None = None) -> RollbackResult:
        """
        Restore configuration to state before transaction.

        Args:
            transaction_id: Transaction to rollback
            reason: Reason for rollback (for audit)

        Returns:
            RollbackResult with details about the rollback
        """
        from core.docker_service import docker_service
        from core.health_checker import HealthCheckError, health_checker

        original = await self.get_transaction(transaction_id)
        if not original:
            return RollbackResult(
                success=False,
                rollback_transaction_id="",
                original_transaction_id=transaction_id,
                message=f"Transaction {transaction_id} not found",
            )

        can_rollback, rollback_reason = await self.can_rollback(transaction_id)
        if not can_rollback:
            return RollbackResult(
                success=False,
                rollback_transaction_id="",
                original_transaction_id=transaction_id,
                message=f"Cannot rollback: {rollback_reason}",
            )

        # Create rollback transaction
        rollback_txn = await self.begin_transaction(
            operation=OperationType.ROLLBACK,
            resource_type=original.resource_type,
            resource_id=original.resource_id,
            request_data={"original_transaction_id": transaction_id, "reason": reason},
        )

        await self.start_transaction(rollback_txn.id)

        warnings: list[str] = []

        try:
            # Restore configuration from snapshot
            restore_result = await self.snapshot_service.restore_snapshot(transaction_id, stage="before")

            if not restore_result.success:
                raise Exception(f"Restore failed: {', '.join(restore_result.errors)}")

            warnings.extend(restore_result.errors)

            # Validate restored configuration
            success, _stdout, stderr = await docker_service.test_config()
            if not success:
                raise Exception(f"Configuration validation failed: {stderr}")

            rollback_txn.nginx_validated = True

            # Reload NGINX
            reload_success, _, reload_stderr = await docker_service.reload_nginx()
            if not reload_success:
                warnings.append(f"Reload warning: {reload_stderr}")

            # Verify health
            try:
                await health_checker.verify_health()
                rollback_txn.health_verified = True
            except HealthCheckError as e:
                warnings.append(f"Health check warning: {e.message}")

            # Complete rollback transaction
            await self.complete_transaction(
                rollback_txn.id,
                result_data={"files_restored": restore_result.files_restored, "nginx_reloaded": reload_success},
                nginx_validated=rollback_txn.nginx_validated,
                health_verified=rollback_txn.health_verified,
            )

            # Update original transaction
            original.status = TransactionStatus.ROLLED_BACK
            original.rollback_transaction_id = rollback_txn.id
            await self._update_transaction(original)

            # Record event
            await self.event_store.record_event(
                category="transaction",
                action="rolled_back",
                message="Transaction rolled back successfully",
                severity=EventSeverity.WARNING,
                transaction_id=transaction_id,
                resource_type=original.resource_type,
                resource_id=original.resource_id,
                details={
                    "rollback_transaction_id": rollback_txn.id,
                    "reason": reason,
                    "files_restored": restore_result.files_restored,
                },
            )

            return RollbackResult(
                success=True,
                rollback_transaction_id=rollback_txn.id,
                original_transaction_id=transaction_id,
                restored_state={
                    "files_restored": restore_result.files_restored,
                    "nginx_reloaded": reload_success,
                    "health_verified": rollback_txn.health_verified,
                },
                message="Configuration restored to state before transaction",
                warnings=warnings,
            )

        except Exception as e:
            await self.fail_transaction(
                rollback_txn.id,
                error_message=str(e),
                auto_rollback=False,  # Don't recursively rollback
            )

            return RollbackResult(
                success=False,
                rollback_transaction_id=rollback_txn.id,
                original_transaction_id=transaction_id,
                message=f"Rollback failed: {e}",
                warnings=warnings,
            )

    async def can_rollback(self, transaction_id: str) -> tuple[bool, str]:
        """
        Check if a transaction can be rolled back.

        Returns:
            Tuple of (can_rollback, reason)
        """
        transaction = await self.get_transaction(transaction_id)
        if not transaction:
            return False, "Transaction not found"

        if transaction.status == TransactionStatus.ROLLED_BACK:
            return False, "Transaction has already been rolled back"

        if transaction.status == TransactionStatus.PENDING:
            return False, "Transaction has not been applied yet"

        if transaction.operation == OperationType.ROLLBACK:
            return False, "Cannot rollback a rollback transaction"

        # Check if snapshot exists
        if not await self.snapshot_service.snapshot_exists(transaction_id, "before"):
            return False, "Snapshot not found (may have been cleaned by retention policy)"

        return True, ""

    async def get_transaction(self, transaction_id: str) -> Transaction | None:
        """Get a transaction by ID."""
        row = await self.db.fetch_one("SELECT * FROM transactions WHERE id = ?", (transaction_id,))

        if not row:
            return None

        return self._row_to_transaction(row)

    async def get_transaction_detail(self, transaction_id: str) -> TransactionDetail | None:
        """Get full transaction details including diff."""
        transaction = await self.get_transaction(transaction_id)
        if not transaction:
            return None

        # Get diff
        diff_data = await self.snapshot_service.get_diff(transaction_id)

        diff = TransactionDiff(
            files_changed=diff_data.get("files_changed", 0),
            total_additions=diff_data.get("total_additions", 0),
            total_deletions=diff_data.get("total_deletions", 0),
            files=[FileDiff(**f) for f in diff_data.get("files", [])],
        )

        # Check rollback eligibility
        can_rollback, rollback_reason = await self.can_rollback(transaction_id)

        return TransactionDetail(
            **transaction.model_dump(),
            diff=diff,
            affected_files=[f.file_path for f in diff.files],
            can_rollback=can_rollback,
            rollback_reason=rollback_reason if not can_rollback else None,
        )

    async def list_transactions(
        self,
        limit: int = 50,
        offset: int = 0,
        status: TransactionStatus | None = None,
        operation: OperationType | None = None,
        resource_type: str | None = None,
    ) -> TransactionListResponse:
        """List transactions with filtering."""
        where_clauses = []
        params: list[Any] = []

        if status:
            where_clauses.append("status = ?")
            params.append(status.value)

        if operation:
            where_clauses.append("operation = ?")
            params.append(operation.value)

        if resource_type:
            where_clauses.append("resource_type = ?")
            params.append(resource_type)

        where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"

        # Get total count
        count_result = await self.db.fetch_one(
            f"SELECT COUNT(*) as count FROM transactions WHERE {where_sql}", tuple(params)
        )
        total = count_result["count"] if count_result else 0

        # Get paginated results
        query = f"""
            SELECT * FROM transactions
            WHERE {where_sql}
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        rows = await self.db.fetch_all(query, tuple(params))
        transactions = [
            TransactionSummary(
                id=row["id"],
                operation=OperationType(row["operation"]),
                status=TransactionStatus(row["status"]),
                resource_type=row["resource_type"],
                resource_id=row.get("resource_id"),
                created_at=datetime.fromisoformat(row["created_at"]),
                completed_at=datetime.fromisoformat(row["completed_at"]) if row.get("completed_at") else None,
                duration_ms=row.get("duration_ms"),
                error_message=row.get("error_message"),
            )
            for row in rows
        ]

        return TransactionListResponse(
            transactions=transactions,
            total=total,
            limit=limit,
            offset=offset,
            has_more=(offset + len(transactions)) < total,
        )

    async def _save_transaction(self, transaction: Transaction) -> None:
        """Save a new transaction to the database."""
        data = {
            "id": transaction.id,
            "operation": transaction.operation.value,
            "status": transaction.status.value,
            "created_at": transaction.created_at.isoformat(),
            "started_at": transaction.started_at.isoformat() if transaction.started_at else None,
            "completed_at": transaction.completed_at.isoformat() if transaction.completed_at else None,
            "duration_ms": transaction.duration_ms,
            "resource_type": transaction.resource_type,
            "resource_id": transaction.resource_id,
            "snapshot_path": transaction.snapshot_path,
            "before_state_json": serialize_json(transaction.before_state),
            "after_state_json": serialize_json(transaction.after_state),
            "request_data_json": serialize_json(transaction.request_data),
            "result_data_json": serialize_json(transaction.result_data),
            "error_message": transaction.error_message,
            "error_details_json": serialize_json(transaction.error_details),
            "parent_transaction_id": transaction.parent_transaction_id,
            "rollback_transaction_id": transaction.rollback_transaction_id,
            "nginx_validated": transaction.nginx_validated,
            "health_verified": transaction.health_verified,
        }

        await self.db.insert("transactions", data)

    async def _update_transaction(self, transaction: Transaction) -> None:
        """Update an existing transaction in the database."""
        data = {
            "status": transaction.status.value,
            "started_at": transaction.started_at.isoformat() if transaction.started_at else None,
            "completed_at": transaction.completed_at.isoformat() if transaction.completed_at else None,
            "duration_ms": transaction.duration_ms,
            "after_state_json": serialize_json(transaction.after_state),
            "result_data_json": serialize_json(transaction.result_data),
            "error_message": transaction.error_message,
            "error_details_json": serialize_json(transaction.error_details),
            "rollback_transaction_id": transaction.rollback_transaction_id,
            "nginx_validated": transaction.nginx_validated,
            "health_verified": transaction.health_verified,
        }

        await self.db.update("transactions", transaction.id, data)

    def _row_to_transaction(self, row: dict[str, Any]) -> Transaction:
        """Convert a database row to a Transaction object."""
        return Transaction(
            id=row["id"],
            operation=OperationType(row["operation"]),
            status=TransactionStatus(row["status"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            started_at=datetime.fromisoformat(row["started_at"]) if row.get("started_at") else None,
            completed_at=datetime.fromisoformat(row["completed_at"]) if row.get("completed_at") else None,
            duration_ms=row.get("duration_ms"),
            resource_type=row["resource_type"],
            resource_id=row.get("resource_id"),
            snapshot_path=row.get("snapshot_path"),
            before_state=deserialize_json(row.get("before_state_json")),
            after_state=deserialize_json(row.get("after_state_json")),
            request_data=deserialize_json(row.get("request_data_json")),
            result_data=deserialize_json(row.get("result_data_json")),
            error_message=row.get("error_message"),
            error_details=deserialize_json(row.get("error_details_json")),
            parent_transaction_id=row.get("parent_transaction_id"),
            rollback_transaction_id=row.get("rollback_transaction_id"),
            nginx_validated=bool(row.get("nginx_validated")),
            health_verified=bool(row.get("health_verified")),
        )


# Singleton instance
_transaction_manager: TransactionManager | None = None


def get_transaction_manager() -> TransactionManager:
    """Get the global transaction manager instance."""
    global _transaction_manager
    if _transaction_manager is None:
        _transaction_manager = TransactionManager()
    return _transaction_manager
