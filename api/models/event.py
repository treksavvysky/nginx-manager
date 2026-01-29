"""
Event models for the audit log system.

Events provide a complete audit trail of all significant
actions in the system for AI agents and administrators.
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EventSeverity(str, Enum):
    """Event severity levels."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class EventCategory(str, Enum):
    """Event categories for filtering."""

    TRANSACTION = "transaction"
    HEALTH = "health"
    SSL = "ssl"
    SYSTEM = "system"
    CONFIG = "config"


class Event(BaseModel):
    """
    Represents a system event for the activity log.

    Events are generated for all significant actions, providing
    a complete audit trail for AI agents and administrators.
    """

    id: str = Field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:12]}", description="Unique event identifier")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="When the event occurred")
    severity: EventSeverity = Field(default=EventSeverity.INFO, description="Event severity level")

    # Classification
    category: str = Field(..., description="Event category (transaction, health, ssl, system, config)")
    action: str = Field(..., description="Specific action (created, completed, failed, etc.)")

    # Context
    transaction_id: str | None = Field(None, description="Related transaction ID if applicable")
    resource_type: str | None = Field(None, description="Type of affected resource")
    resource_id: str | None = Field(None, description="Identifier of affected resource")

    # Details
    message: str = Field(..., description="Human-readable event description")
    details: dict[str, Any] | None = Field(None, description="Additional structured event data")

    # Source
    source: str = Field(default="api", description="Component that generated the event")

    # Audit fields (Phase 5)
    client_ip: str | None = Field(None, description="IP address of the client that triggered the event")
    user_id: str | None = Field(None, description="User ID if authenticated via user login")
    api_key_id: str | None = Field(None, description="API key ID if authenticated via API key")


class EventFilters(BaseModel):
    """Query filters for event listing."""

    since: datetime | None = Field(None, description="Return events after this timestamp")
    until: datetime | None = Field(None, description="Return events before this timestamp")
    severity: list[EventSeverity] | None = Field(None, description="Filter by severity levels")
    category: list[str] | None = Field(None, description="Filter by categories")
    resource_type: str | None = Field(None, description="Filter by resource type")
    resource_id: str | None = Field(None, description="Filter by resource ID")
    transaction_id: str | None = Field(None, description="Filter by transaction ID")


class EventsListResponse(BaseModel):
    """Paginated list of events."""

    events: list[Event] = Field(default_factory=list, description="List of events")
    total: int = Field(..., description="Total number of matching events")
    page: int = Field(default=1, description="Current page number")
    page_size: int = Field(default=50, description="Events per page")
    has_more: bool = Field(default=False, description="More events available")


class EventCountBySeverity(BaseModel):
    """Event counts grouped by severity."""

    info: int = 0
    warning: int = 0
    error: int = 0
    critical: int = 0
    total: int = 0
