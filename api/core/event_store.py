"""
Event storage and retrieval for the audit log system.

Provides persistent storage of system events in SQLite
with efficient querying and retention management.
"""

import logging
from datetime import datetime
from typing import Optional, List, Dict, Any

from models.event import (
    Event,
    EventSeverity,
    EventFilters,
    EventsListResponse,
    EventCountBySeverity,
)
from core.database import get_database, serialize_json, deserialize_json
from config import settings

logger = logging.getLogger(__name__)


class EventStore:
    """Persistent storage and retrieval of system events."""

    def __init__(self):
        self.db = get_database()

    async def record_event(
        self,
        category: str,
        action: str,
        message: str,
        severity: EventSeverity = EventSeverity.INFO,
        transaction_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        source: str = "api"
    ) -> Event:
        """
        Record a new event to the database.

        Args:
            category: Event category (transaction, health, ssl, system, config)
            action: Specific action (created, completed, failed, etc.)
            message: Human-readable event description
            severity: Event severity level
            transaction_id: Related transaction ID if applicable
            resource_type: Type of affected resource
            resource_id: Identifier of affected resource
            details: Additional structured event data
            source: Component that generated the event

        Returns:
            The created Event object
        """
        event = Event(
            category=category,
            action=action,
            message=message,
            severity=severity,
            transaction_id=transaction_id,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            source=source
        )

        data = {
            "id": event.id,
            "timestamp": event.timestamp.isoformat(),
            "severity": event.severity.value,
            "category": event.category,
            "action": event.action,
            "transaction_id": event.transaction_id,
            "resource_type": event.resource_type,
            "resource_id": event.resource_id,
            "message": event.message,
            "details_json": serialize_json(event.details),
            "source": event.source
        }

        await self.db.insert("events", data)
        logger.debug(f"Recorded event: {event.id} [{event.severity.value}] {event.message}")

        return event

    async def get_event(self, event_id: str) -> Optional[Event]:
        """Get a specific event by ID."""
        row = await self.db.fetch_one(
            "SELECT * FROM events WHERE id = ?",
            (event_id,)
        )

        if not row:
            return None

        return self._row_to_event(row)

    async def list_events(
        self,
        filters: Optional[EventFilters] = None,
        page: int = 1,
        page_size: int = 50
    ) -> EventsListResponse:
        """
        List events with optional filtering and pagination.

        Args:
            filters: Query filters
            page: Page number (1-indexed)
            page_size: Number of events per page

        Returns:
            Paginated list of events
        """
        where_clauses = []
        params: List[Any] = []

        if filters:
            if filters.since:
                where_clauses.append("timestamp >= ?")
                params.append(filters.since.isoformat())

            if filters.until:
                where_clauses.append("timestamp <= ?")
                params.append(filters.until.isoformat())

            if filters.severity:
                placeholders = ", ".join(["?" for _ in filters.severity])
                where_clauses.append(f"severity IN ({placeholders})")
                params.extend([s.value for s in filters.severity])

            if filters.category:
                placeholders = ", ".join(["?" for _ in filters.category])
                where_clauses.append(f"category IN ({placeholders})")
                params.extend(filters.category)

            if filters.resource_type:
                where_clauses.append("resource_type = ?")
                params.append(filters.resource_type)

            if filters.resource_id:
                where_clauses.append("resource_id = ?")
                params.append(filters.resource_id)

            if filters.transaction_id:
                where_clauses.append("transaction_id = ?")
                params.append(filters.transaction_id)

        where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"

        # Get total count
        count_query = f"SELECT COUNT(*) as count FROM events WHERE {where_sql}"
        count_result = await self.db.fetch_one(count_query, tuple(params))
        total = count_result["count"] if count_result else 0

        # Get paginated results
        offset = (page - 1) * page_size
        query = f"""
            SELECT * FROM events
            WHERE {where_sql}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """
        params.extend([page_size, offset])

        rows = await self.db.fetch_all(query, tuple(params))
        events = [self._row_to_event(row) for row in rows]

        return EventsListResponse(
            events=events,
            total=total,
            page=page,
            page_size=page_size,
            has_more=(offset + len(events)) < total
        )

    async def get_transaction_events(
        self,
        transaction_id: str
    ) -> List[Event]:
        """Get all events for a specific transaction."""
        rows = await self.db.fetch_all(
            """
            SELECT * FROM events
            WHERE transaction_id = ?
            ORDER BY timestamp ASC
            """,
            (transaction_id,)
        )

        return [self._row_to_event(row) for row in rows]

    async def get_event_counts_by_severity(
        self,
        since: Optional[datetime] = None
    ) -> EventCountBySeverity:
        """Get event counts grouped by severity."""
        where_clause = ""
        params: tuple = ()

        if since:
            where_clause = "WHERE timestamp >= ?"
            params = (since.isoformat(),)

        query = f"""
            SELECT severity, COUNT(*) as count
            FROM events
            {where_clause}
            GROUP BY severity
        """

        rows = await self.db.fetch_all(query, params)

        counts = EventCountBySeverity()
        for row in rows:
            severity = row["severity"]
            count = row["count"]
            if severity == "info":
                counts.info = count
            elif severity == "warning":
                counts.warning = count
            elif severity == "error":
                counts.error = count
            elif severity == "critical":
                counts.critical = count
            counts.total += count

        return counts

    async def enforce_retention(
        self,
        retention_days: Optional[int] = None
    ) -> int:
        """
        Delete events older than retention period.

        Args:
            retention_days: Days to retain (default from settings)

        Returns:
            Number of events deleted
        """
        days = retention_days or settings.event_retention_days

        deleted = await self.db.delete_older_than(
            "events",
            "timestamp",
            days
        )

        if deleted > 0:
            logger.info(f"Retention cleanup: deleted {deleted} events older than {days} days")

        return deleted

    def _row_to_event(self, row: Dict[str, Any]) -> Event:
        """Convert a database row to an Event object."""
        return Event(
            id=row["id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            severity=EventSeverity(row["severity"]),
            category=row["category"],
            action=row["action"],
            transaction_id=row.get("transaction_id"),
            resource_type=row.get("resource_type"),
            resource_id=row.get("resource_id"),
            message=row["message"],
            details=deserialize_json(row.get("details_json")),
            source=row.get("source", "api")
        )


# Singleton instance
_event_store: Optional[EventStore] = None


def get_event_store() -> EventStore:
    """Get the global event store instance."""
    global _event_store
    if _event_store is None:
        _event_store = EventStore()
    return _event_store
