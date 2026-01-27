"""
Unit tests for the transaction manager.

Tests transaction lifecycle, snapshot management, and rollback functionality.
"""

import pytest
import tempfile
import shutil
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "api"))

from models.transaction import (
    Transaction,
    TransactionStatus,
    OperationType,
    TransactionSummary,
    TransactionDetail,
)


class TestTransactionModels:
    """Tests for transaction Pydantic models."""

    def test_transaction_creation(self):
        """Test creating a Transaction model."""
        txn = Transaction(
            id="test-123",
            operation=OperationType.NGINX_RELOAD,
            status=TransactionStatus.PENDING,
            resource_type="nginx",
            resource_id="nginx",
        )
        assert txn.id == "test-123"
        assert txn.operation == OperationType.NGINX_RELOAD
        assert txn.status == TransactionStatus.PENDING

    def test_transaction_status_enum(self):
        """Test TransactionStatus enum values."""
        assert TransactionStatus.PENDING.value == "pending"
        assert TransactionStatus.IN_PROGRESS.value == "in_progress"
        assert TransactionStatus.COMPLETED.value == "completed"
        assert TransactionStatus.FAILED.value == "failed"
        assert TransactionStatus.ROLLED_BACK.value == "rolled_back"

    def test_operation_type_enum(self):
        """Test OperationType enum values."""
        assert OperationType.NGINX_RELOAD.value == "nginx_reload"
        assert OperationType.NGINX_RESTART.value == "nginx_restart"
        assert OperationType.SITE_CREATE.value == "site_create"
        assert OperationType.ROLLBACK.value == "rollback"

    def test_transaction_summary(self):
        """Test TransactionSummary model."""
        summary = TransactionSummary(
            id="test-123",
            operation=OperationType.NGINX_RELOAD,
            status=TransactionStatus.COMPLETED,
            resource_type="nginx",
            created_at=datetime.now(),
            duration_ms=100,
        )
        assert summary.id == "test-123"
        assert summary.duration_ms == 100


class TestSnapshotService:
    """Tests for the snapshot service."""

    @pytest.fixture
    def temp_dirs(self):
        """Create temporary directories for testing."""
        nginx_conf = tempfile.mkdtemp()
        snapshot_dir = tempfile.mkdtemp()
        yield nginx_conf, snapshot_dir
        shutil.rmtree(nginx_conf, ignore_errors=True)
        shutil.rmtree(snapshot_dir, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_snapshot_creation(self, temp_dirs):
        """Test creating a configuration snapshot."""
        nginx_conf, snapshot_dir = temp_dirs

        # Create a test config file
        config_file = Path(nginx_conf) / "test.conf"
        config_file.write_text("server { listen 80; }")

        # Import and test snapshot service
        with patch("core.snapshot_service.settings") as mock_settings:
            mock_settings.nginx_conf_dir = nginx_conf
            mock_settings.snapshot_dir = snapshot_dir
            mock_settings.max_snapshots = 10
            mock_settings.snapshot_retention_days = 30

            from core.snapshot_service import SnapshotService
            service = SnapshotService(
                snapshot_dir=snapshot_dir,
                nginx_conf_dir=nginx_conf
            )

            # Create snapshot (await the async method)
            txn_id = "test-txn-123"
            snapshot_info = await service.create_snapshot(txn_id, "before")

            snapshot_path = Path(snapshot_info.path)
            assert snapshot_path.exists()
            assert (snapshot_path / "test.conf").exists()
            assert (snapshot_path / "test.conf").read_text() == "server { listen 80; }"

    @pytest.mark.asyncio
    async def test_snapshot_restore(self, temp_dirs):
        """Test restoring from a snapshot."""
        nginx_conf, snapshot_dir = temp_dirs

        # Create initial config
        config_file = Path(nginx_conf) / "test.conf"
        config_file.write_text("server { listen 80; }")

        with patch("core.snapshot_service.settings") as mock_settings:
            mock_settings.nginx_conf_dir = nginx_conf
            mock_settings.snapshot_dir = snapshot_dir
            mock_settings.max_snapshots = 10
            mock_settings.snapshot_retention_days = 30

            from core.snapshot_service import SnapshotService
            service = SnapshotService(
                snapshot_dir=snapshot_dir,
                nginx_conf_dir=nginx_conf
            )

            # Create snapshot
            txn_id = "test-txn-123"
            await service.create_snapshot(txn_id, "before")

            # Modify the config
            config_file.write_text("server { listen 8080; }")
            assert config_file.read_text() == "server { listen 8080; }"

            # Restore from snapshot
            result = await service.restore_snapshot(txn_id, "before")

            assert result.success is True
            assert "test.conf" in result.files_restored
            assert config_file.read_text() == "server { listen 80; }"

    @pytest.mark.asyncio
    async def test_snapshot_diff(self, temp_dirs):
        """Test generating diff between before/after snapshots."""
        nginx_conf, snapshot_dir = temp_dirs

        # Create initial config
        config_file = Path(nginx_conf) / "test.conf"
        config_file.write_text("server { listen 80; }")

        with patch("core.snapshot_service.settings") as mock_settings:
            mock_settings.nginx_conf_dir = nginx_conf
            mock_settings.snapshot_dir = snapshot_dir
            mock_settings.max_snapshots = 10
            mock_settings.snapshot_retention_days = 30

            from core.snapshot_service import SnapshotService
            service = SnapshotService(
                snapshot_dir=snapshot_dir,
                nginx_conf_dir=nginx_conf
            )

            txn_id = "test-txn-123"

            # Create before snapshot
            await service.create_snapshot(txn_id, "before")

            # Modify config
            config_file.write_text("server { listen 8080; }")

            # Create after snapshot
            await service.create_snapshot(txn_id, "after")

            # Get diff
            diff = await service.get_diff(txn_id)

            assert diff is not None
            assert "files_changed" in diff
            assert diff["files_changed"] >= 1

    @pytest.mark.asyncio
    async def test_snapshot_exists(self, temp_dirs):
        """Test checking if snapshot exists."""
        nginx_conf, snapshot_dir = temp_dirs

        config_file = Path(nginx_conf) / "test.conf"
        config_file.write_text("server { listen 80; }")

        with patch("core.snapshot_service.settings") as mock_settings:
            mock_settings.nginx_conf_dir = nginx_conf
            mock_settings.snapshot_dir = snapshot_dir
            mock_settings.snapshot_retention_days = 30

            from core.snapshot_service import SnapshotService
            service = SnapshotService(
                snapshot_dir=snapshot_dir,
                nginx_conf_dir=nginx_conf
            )

            txn_id = "test-txn-456"

            # Check before creation
            assert await service.snapshot_exists(txn_id, "before") is False

            # Create snapshot
            await service.create_snapshot(txn_id, "before")

            # Check after creation
            assert await service.snapshot_exists(txn_id, "before") is True

    @pytest.mark.asyncio
    async def test_delete_snapshot(self, temp_dirs):
        """Test deleting a snapshot."""
        nginx_conf, snapshot_dir = temp_dirs

        config_file = Path(nginx_conf) / "test.conf"
        config_file.write_text("server { listen 80; }")

        with patch("core.snapshot_service.settings") as mock_settings:
            mock_settings.nginx_conf_dir = nginx_conf
            mock_settings.snapshot_dir = snapshot_dir
            mock_settings.snapshot_retention_days = 30

            from core.snapshot_service import SnapshotService
            service = SnapshotService(
                snapshot_dir=snapshot_dir,
                nginx_conf_dir=nginx_conf
            )

            txn_id = "test-txn-789"

            # Create snapshot
            await service.create_snapshot(txn_id, "before")
            assert await service.snapshot_exists(txn_id, "before") is True

            # Delete snapshot
            result = await service.delete_snapshot(txn_id)
            assert result is True
            assert await service.snapshot_exists(txn_id, "before") is False


class TestEventModels:
    """Tests for event Pydantic models."""

    def test_event_severity_enum(self):
        """Test EventSeverity enum values."""
        from models.event import EventSeverity
        assert EventSeverity.INFO.value == "info"
        assert EventSeverity.WARNING.value == "warning"
        assert EventSeverity.ERROR.value == "error"
        assert EventSeverity.CRITICAL.value == "critical"

    def test_event_creation(self):
        """Test creating an Event model."""
        from models.event import Event
        event = Event(
            id="evt-123",
            timestamp=datetime.now(),
            severity="info",
            category="transaction",
            action="started",
            message="Test event"
        )
        assert event.id == "evt-123"
        assert event.severity == "info"
        assert event.message == "Test event"

    def test_event_filters(self):
        """Test EventFilters model."""
        from models.event import EventFilters, EventSeverity
        filters = EventFilters(
            severity=[EventSeverity.ERROR, EventSeverity.CRITICAL],
            category=["transaction"]
        )
        assert len(filters.severity) == 2
        assert "transaction" in filters.category


class TestTransactionRollbackModels:
    """Tests for rollback-related models."""

    def test_rollback_request(self):
        """Test RollbackRequest model."""
        from models.transaction import RollbackRequest
        request = RollbackRequest(reason="Configuration caused errors")
        assert request.reason == "Configuration caused errors"

    def test_rollback_result(self):
        """Test RollbackResult model."""
        from models.transaction import RollbackResult
        result = RollbackResult(
            success=True,
            rollback_transaction_id="rollback-123",
            original_transaction_id="orig-456",
            restored_state={"files_restored": ["test.conf"]},
            message="Successfully restored configuration"
        )
        assert result.success is True
        assert result.rollback_transaction_id == "rollback-123"
        assert result.original_transaction_id == "orig-456"
        assert "test.conf" in result.restored_state["files_restored"]


class TestTransactionContext:
    """Tests for the transaction context without database."""

    def test_transaction_context_class(self):
        """Test TransactionContext class properties."""
        from core.transaction_context import TransactionContext
        from models.transaction import Transaction, OperationType, TransactionStatus

        txn = Transaction(
            id="test-ctx-123",
            operation=OperationType.NGINX_RELOAD,
            status=TransactionStatus.IN_PROGRESS,
            resource_type="nginx"
        )

        ctx = TransactionContext(txn)
        assert ctx.id == "test-ctx-123"
        assert ctx.nginx_validated is False
        assert ctx.health_verified is False

        ctx.set_nginx_validated(True)
        ctx.set_health_verified(True)
        ctx.set_result({"success": True})

        assert ctx.nginx_validated is True
        assert ctx.health_verified is True
        assert ctx.result_data == {"success": True}


class TestTransactionExceptions:
    """Tests for transaction-related exceptions."""

    def test_transaction_error(self):
        """Test TransactionError exception."""
        from core.transaction_context import TransactionError
        error = TransactionError("Test error", transaction_id="txn-123")
        assert error.message == "Test error"
        assert error.transaction_id == "txn-123"
        assert str(error) == "Test error"

    def test_rollback_error(self):
        """Test RollbackError exception."""
        from core.transaction_context import RollbackError
        error = RollbackError("Rollback failed", transaction_id="txn-456")
        assert error.message == "Rollback failed"
        assert error.transaction_id == "txn-456"

    def test_snapshot_error(self):
        """Test SnapshotError exception."""
        from core.transaction_context import SnapshotError
        error = SnapshotError("Snapshot creation failed")
        assert error.message == "Snapshot creation failed"
