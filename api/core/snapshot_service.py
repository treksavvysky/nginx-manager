"""
Configuration snapshot management for transactions.

Captures and restores NGINX configuration state,
enabling rollback and diff generation.
"""

import difflib
import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from config import settings

logger = logging.getLogger(__name__)


class SnapshotInfo(BaseModel):
    """Information about a snapshot."""

    transaction_id: str
    stage: str  # "before" or "after"
    path: str
    files: list[str] = Field(default_factory=list)
    total_size: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)


class RestoreResult(BaseModel):
    """Result of a snapshot restore operation."""

    success: bool
    files_restored: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class SnapshotService:
    """Manages configuration state snapshots for transactions."""

    def __init__(self, snapshot_dir: str | None = None, nginx_conf_dir: str | None = None):
        self.snapshot_dir = Path(snapshot_dir or settings.snapshot_dir)
        self.nginx_conf_dir = Path(nginx_conf_dir or settings.nginx_conf_dir)

    async def create_snapshot(self, transaction_id: str, stage: str = "before") -> SnapshotInfo:
        """
        Capture current configuration state to snapshot directory.

        Args:
            transaction_id: Transaction this snapshot belongs to
            stage: "before" or "after"

        Returns:
            SnapshotInfo with details about the created snapshot
        """
        snapshot_path = self._get_snapshot_path(transaction_id, stage)
        snapshot_path.mkdir(parents=True, exist_ok=True)

        files: list[str] = []
        total_size = 0

        # Copy all .conf files from nginx conf directory
        if self.nginx_conf_dir.exists():
            for conf_file in self.nginx_conf_dir.glob("*.conf"):
                dest = snapshot_path / conf_file.name
                shutil.copy2(conf_file, dest)
                files.append(conf_file.name)
                total_size += conf_file.stat().st_size

        logger.info(
            f"Created {stage} snapshot for transaction {transaction_id}: {len(files)} files, {total_size} bytes"
        )

        return SnapshotInfo(
            transaction_id=transaction_id, stage=stage, path=str(snapshot_path), files=files, total_size=total_size
        )

    async def restore_snapshot(self, transaction_id: str, stage: str = "before") -> RestoreResult:
        """
        Restore configuration from a snapshot.

        Args:
            transaction_id: Transaction to restore from
            stage: Which snapshot to restore ("before" or "after")

        Returns:
            RestoreResult with details about the restoration
        """
        snapshot_path = self._get_snapshot_path(transaction_id, stage)

        if not snapshot_path.exists():
            return RestoreResult(success=False, errors=[f"Snapshot not found: {snapshot_path}"])

        files_restored: list[str] = []
        errors: list[str] = []

        # Clear current configs and restore from snapshot
        for conf_file in snapshot_path.glob("*.conf"):
            dest = self.nginx_conf_dir / conf_file.name
            try:
                shutil.copy2(conf_file, dest)
                files_restored.append(conf_file.name)
            except Exception as e:
                errors.append(f"Failed to restore {conf_file.name}: {e}")

        # Remove any configs that weren't in the snapshot
        snapshot_files = set(f.name for f in snapshot_path.glob("*.conf"))
        for conf_file in self.nginx_conf_dir.glob("*.conf"):
            if conf_file.name not in snapshot_files:
                try:
                    conf_file.unlink()
                    logger.info(f"Removed config not in snapshot: {conf_file.name}")
                except Exception as e:
                    errors.append(f"Failed to remove {conf_file.name}: {e}")

        success = len(errors) == 0
        logger.info(f"Restored snapshot {transaction_id}/{stage}: {len(files_restored)} files, {len(errors)} errors")

        return RestoreResult(success=success, files_restored=files_restored, errors=errors)

    async def get_diff(self, transaction_id: str) -> dict[str, Any]:
        """
        Generate unified diff between before and after states.

        Args:
            transaction_id: Transaction to diff

        Returns:
            Dict with diff information per file
        """
        before_path = self._get_snapshot_path(transaction_id, "before")
        after_path = self._get_snapshot_path(transaction_id, "after")

        result = {"files_changed": 0, "total_additions": 0, "total_deletions": 0, "files": []}

        if not before_path.exists():
            return result

        # Get all files from both snapshots
        before_files = set(f.name for f in before_path.glob("*.conf"))
        after_files = set(f.name for f in after_path.glob("*.conf")) if after_path.exists() else set()

        all_files = before_files | after_files

        for filename in sorted(all_files):
            before_file = before_path / filename
            after_file = after_path / filename if after_path.exists() else None

            file_diff = await self._diff_file(
                before_file if before_file.exists() else None,
                after_file if after_file and after_file.exists() else None,
                filename,
            )

            if file_diff["change_type"] != "unchanged":
                result["files"].append(file_diff)
                result["files_changed"] += 1
                result["total_additions"] += file_diff["additions"]
                result["total_deletions"] += file_diff["deletions"]

        return result

    async def _diff_file(self, before_file: Path | None, after_file: Path | None, filename: str) -> dict[str, Any]:
        """Generate diff for a single file."""
        before_lines = []
        after_lines = []

        if before_file and before_file.exists():
            before_lines = before_file.read_text().splitlines(keepends=True)

        if after_file and after_file.exists():
            after_lines = after_file.read_text().splitlines(keepends=True)

        # Determine change type
        if not before_lines and after_lines:
            change_type = "added"
        elif before_lines and not after_lines:
            change_type = "deleted"
        elif before_lines == after_lines:
            change_type = "unchanged"
        else:
            change_type = "modified"

        # Generate unified diff
        diff_lines = list(
            difflib.unified_diff(before_lines, after_lines, fromfile=f"a/{filename}", tofile=f"b/{filename}")
        )

        # Count additions and deletions
        additions = sum(1 for line in diff_lines if line.startswith("+") and not line.startswith("+++"))
        deletions = sum(1 for line in diff_lines if line.startswith("-") and not line.startswith("---"))

        return {
            "file_path": filename,
            "change_type": change_type,
            "additions": additions,
            "deletions": deletions,
            "diff_content": "".join(diff_lines) if diff_lines else None,
        }

    async def get_snapshot_info(self, transaction_id: str, stage: str) -> SnapshotInfo | None:
        """Get metadata about a snapshot."""
        snapshot_path = self._get_snapshot_path(transaction_id, stage)

        if not snapshot_path.exists():
            return None

        files = [f.name for f in snapshot_path.glob("*.conf")]
        total_size = sum(f.stat().st_size for f in snapshot_path.glob("*.conf"))

        # Get creation time from directory
        created_at = datetime.fromtimestamp(snapshot_path.stat().st_ctime)

        return SnapshotInfo(
            transaction_id=transaction_id,
            stage=stage,
            path=str(snapshot_path),
            files=files,
            total_size=total_size,
            created_at=created_at,
        )

    async def snapshot_exists(self, transaction_id: str, stage: str = "before") -> bool:
        """Check if a snapshot exists."""
        return self._get_snapshot_path(transaction_id, stage).exists()

    async def cleanup_old_snapshots(self, retention_days: int | None = None) -> int:
        """
        Remove snapshots older than retention period.

        Args:
            retention_days: Days to retain (default from settings)

        Returns:
            Number of snapshots deleted
        """
        days = retention_days or settings.snapshot_retention_days
        cutoff = datetime.utcnow().timestamp() - (days * 24 * 60 * 60)

        deleted = 0

        if not self.snapshot_dir.exists():
            return deleted

        for transaction_dir in self.snapshot_dir.iterdir():
            if not transaction_dir.is_dir():
                continue

            # Check if directory is older than cutoff
            if transaction_dir.stat().st_mtime < cutoff:
                try:
                    shutil.rmtree(transaction_dir)
                    deleted += 1
                    logger.debug(f"Deleted old snapshot: {transaction_dir.name}")
                except Exception as e:
                    logger.error(f"Failed to delete snapshot {transaction_dir}: {e}")

        if deleted > 0:
            logger.info(f"Retention cleanup: deleted {deleted} snapshots older than {days} days")

        return deleted

    async def get_snapshot_size(self, transaction_id: str) -> int:
        """Get total size of snapshot files in bytes."""
        total = 0

        for stage in ["before", "after"]:
            snapshot_path = self._get_snapshot_path(transaction_id, stage)
            if snapshot_path.exists():
                total += sum(f.stat().st_size for f in snapshot_path.glob("*"))

        return total

    async def delete_snapshot(self, transaction_id: str) -> bool:
        """Delete all snapshots for a transaction."""
        transaction_path = self.snapshot_dir / transaction_id

        if not transaction_path.exists():
            return False

        try:
            shutil.rmtree(transaction_path)
            logger.info(f"Deleted snapshot for transaction {transaction_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete snapshot {transaction_id}: {e}")
            return False

    def _get_snapshot_path(self, transaction_id: str, stage: str) -> Path:
        """Get the path for a snapshot."""
        return self.snapshot_dir / transaction_id / stage


# Singleton instance
_snapshot_service: SnapshotService | None = None


def get_snapshot_service() -> SnapshotService:
    """Get the global snapshot service instance."""
    global _snapshot_service
    if _snapshot_service is None:
        _snapshot_service = SnapshotService()
    return _snapshot_service
