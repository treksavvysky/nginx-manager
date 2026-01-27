"""
Event and audit log endpoints.

Provides access to the system event log for reviewing
recent activity and monitoring system health.
"""

import logging
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, HTTPException, Query

from models.event import (
    Event,
    EventSeverity,
    EventFilters,
    EventsListResponse,
    EventCountBySeverity,
)
from core.event_store import get_event_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/events", tags=["Events & Audit Log"])


@router.get(
    "/",
    response_model=EventsListResponse,
    summary="List Recent Events",
    description="""
Retrieve recent system events with optional filtering.

**Use Cases for AI Agents:**
- Review what changed recently before making modifications
- Verify operations completed successfully
- Diagnose issues by reviewing error events
- Audit trail for compliance

**Filtering Options:**
- `since/until`: Time range filtering
- `severity`: Filter by event severity (info, warning, error, critical)
- `category`: Filter by category (transaction, health, ssl, system, config)
- `resource_type/resource_id`: Filter by affected resource
- `transaction_id`: Filter by transaction

**Pagination:**
- Default 50 events per page
- Use `page` parameter to navigate
"""
)
async def list_events(
    since: Optional[datetime] = Query(
        None,
        description="Return events after this timestamp"
    ),
    until: Optional[datetime] = Query(
        None,
        description="Return events before this timestamp"
    ),
    severity: Optional[List[EventSeverity]] = Query(
        None,
        description="Filter by severity levels"
    ),
    category: Optional[List[str]] = Query(
        None,
        description="Filter by categories (transaction, health, ssl, system, config)"
    ),
    resource_type: Optional[str] = Query(
        None,
        description="Filter by resource type"
    ),
    resource_id: Optional[str] = Query(
        None,
        description="Filter by resource ID"
    ),
    transaction_id: Optional[str] = Query(
        None,
        description="Filter by transaction ID"
    ),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=200, description="Events per page")
) -> EventsListResponse:
    """List events with filtering and pagination."""
    event_store = get_event_store()

    filters = EventFilters(
        since=since,
        until=until,
        severity=severity,
        category=category,
        resource_type=resource_type,
        resource_id=resource_id,
        transaction_id=transaction_id
    )

    return await event_store.list_events(
        filters=filters,
        page=page,
        page_size=page_size
    )


@router.get(
    "/counts",
    response_model=EventCountBySeverity,
    summary="Get Event Counts by Severity",
    description="""
Get counts of events grouped by severity level.

Useful for monitoring dashboards and health indicators.
Optionally filter to events since a specific timestamp.
"""
)
async def get_event_counts(
    since: Optional[datetime] = Query(
        None,
        description="Only count events after this timestamp"
    )
) -> EventCountBySeverity:
    """Get event counts by severity."""
    event_store = get_event_store()
    return await event_store.get_event_counts_by_severity(since=since)


@router.get(
    "/{event_id}",
    response_model=Event,
    summary="Get Event Details",
    description="""
Retrieve full details for a specific event.

Returns complete event information including all metadata
and the `details` field with structured context.
"""
)
async def get_event(event_id: str) -> Event:
    """Get a specific event by ID."""
    event_store = get_event_store()

    event = await event_store.get_event(event_id)
    if not event:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "event_not_found",
                "message": f"Event '{event_id}' not found",
                "suggestion": "Check the event ID and try again"
            }
        )

    return event
