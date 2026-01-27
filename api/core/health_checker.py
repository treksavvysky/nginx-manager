"""
Health verification for NGINX after operations.

Provides HTTP-based health checking with retries to verify
NGINX is responding correctly after reload/restart operations.
"""

import asyncio
import logging
from typing import Optional

import httpx

from config import settings

logger = logging.getLogger(__name__)


class HealthCheckError(Exception):
    """Health check failed after all retries."""

    def __init__(self, message: str, attempts: int, last_error: Optional[str] = None):
        self.message = message
        self.attempts = attempts
        self.last_error = last_error
        super().__init__(message)


class HealthChecker:
    """Verify NGINX health via HTTP endpoint."""

    async def verify_health(
        self,
        retries: Optional[int] = None,
        interval: Optional[float] = None,
        timeout: float = 5.0
    ) -> bool:
        """
        Verify NGINX is healthy by checking the health endpoint.

        Args:
            retries: Number of retry attempts (default from settings)
            interval: Seconds between retries (default from settings)
            timeout: HTTP request timeout per attempt

        Returns:
            True if health check passes

        Raises:
            HealthCheckError if all retries fail
        """
        retries = retries if retries is not None else settings.nginx_health_check_retries
        interval = interval if interval is not None else settings.nginx_health_check_interval
        endpoint = settings.nginx_health_endpoint

        last_error = None

        for attempt in range(1, retries + 1):
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.get(
                        endpoint,
                        timeout=timeout
                    )

                    if response.status_code == 200:
                        logger.info(
                            f"Health check passed on attempt {attempt}/{retries}"
                        )
                        return True

                    last_error = f"HTTP {response.status_code}"
                    logger.warning(
                        f"Health check attempt {attempt}/{retries} returned "
                        f"status {response.status_code}"
                    )

            except httpx.ConnectError as e:
                last_error = f"Connection error: {e}"
                logger.warning(
                    f"Health check attempt {attempt}/{retries} connection failed: {e}"
                )

            except httpx.TimeoutException as e:
                last_error = f"Timeout: {e}"
                logger.warning(
                    f"Health check attempt {attempt}/{retries} timed out"
                )

            except httpx.RequestError as e:
                last_error = str(e)
                logger.warning(
                    f"Health check attempt {attempt}/{retries} failed: {e}"
                )

            # Wait before retry (except on last attempt)
            if attempt < retries:
                await asyncio.sleep(interval)

        raise HealthCheckError(
            f"Health check failed after {retries} attempts",
            attempts=retries,
            last_error=last_error
        )

    async def check_health_once(self, timeout: float = 5.0) -> tuple[bool, Optional[str]]:
        """
        Single health check without retries.

        Args:
            timeout: HTTP request timeout

        Returns:
            Tuple of (is_healthy, error_message)
        """
        endpoint = settings.nginx_health_endpoint

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(endpoint, timeout=timeout)

                if response.status_code == 200:
                    return True, None
                return False, f"HTTP {response.status_code}"

        except httpx.RequestError as e:
            return False, str(e)


# Singleton instance
health_checker = HealthChecker()
