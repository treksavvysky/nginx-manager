"""
Request logging middleware.

Logs HTTP method, path, status code, duration, client IP,
and authenticated identity for audit purposes.
"""

import logging
import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("nginx_manager.access")

# Paths excluded from access logging to reduce noise
_EXCLUDED_PATHS = {"/health", "/docs", "/redoc", "/openapi.json", "/"}


class RequestLoggerMiddleware(BaseHTTPMiddleware):
    """Middleware that logs every HTTP request with timing and identity."""

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        # Skip noisy endpoints
        if path in _EXCLUDED_PATHS:
            return await call_next(request)

        start = time.monotonic()
        client_ip = request.client.host if request.client else "unknown"

        response: Response = await call_next(request)

        duration_ms = (time.monotonic() - start) * 1000

        # Extract auth identity if present (set by auth dependency)
        auth_id = request.state.auth_id if hasattr(request.state, "auth_id") else "-"

        logger.info(
            "%s %s %d %.1fms client=%s auth=%s",
            request.method,
            path,
            response.status_code,
            duration_ms,
            client_ip,
            auth_id,
        )

        return response
