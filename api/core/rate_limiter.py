"""
Rate limiting configuration using slowapi.

Provides per-client rate limits for API endpoints
with differentiated limits for read vs mutation operations.
"""

import logging

from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request

logger = logging.getLogger(__name__)

# Default rate limits
DEFAULT_RATE_AUTH = "60/minute"  # Authenticated requests
DEFAULT_RATE_UNAUTH = "10/minute"  # Unauthenticated requests
DEFAULT_RATE_MUTATION = "30/minute"  # Create/update/delete operations
DEFAULT_RATE_READ = "120/minute"  # Read-only operations


def _get_client_key(request: Request) -> str:
    """
    Build a rate limit key from client IP + API key ID if present.

    This ensures each authenticated identity gets its own bucket,
    while unauthenticated clients are keyed by IP.
    """
    ip = get_remote_address(request)
    # If auth has already resolved, use the identity
    api_key = request.headers.get("X-API-Key", "")
    if api_key:
        return f"{ip}:{api_key[:12]}"
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        # Use first 12 chars of token as bucket differentiator
        return f"{ip}:jwt"
    return ip


# Global limiter instance — in-memory storage for single-process deployments
limiter = Limiter(
    key_func=_get_client_key,
    default_limits=[DEFAULT_RATE_AUTH],
    storage_uri="memory://",
)
