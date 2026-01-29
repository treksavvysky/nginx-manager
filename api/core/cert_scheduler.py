"""
Certificate renewal scheduler.

Background task scheduler for automatic certificate renewal
and expiry monitoring using APScheduler.
"""

import logging
from datetime import datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from config import settings
from core.cert_manager import CertificateError, CertManager, get_cert_manager
from core.docker_service import docker_service
from core.event_store import EventStore, get_event_store
from models.certificate import CertificateType
from models.event import EventCategory, EventSeverity

logger = logging.getLogger(__name__)


class CertScheduler:
    """
    Background certificate renewal and monitoring scheduler.

    Runs periodic jobs to:
    - Check and renew certificates expiring soon
    - Generate warning events for expiring certificates
    """

    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self.cert_manager: CertManager = get_cert_manager()
        self.event_store: EventStore = get_event_store()
        self._started = False

    async def start(self) -> None:
        """Start the renewal scheduler."""
        if self._started:
            logger.warning("Certificate scheduler already started")
            return

        # Check renewals daily at 3 AM
        self.scheduler.add_job(
            self._check_renewals,
            CronTrigger(hour=3, minute=0),
            id="cert_renewal_check",
            name="Certificate Renewal Check",
            replace_existing=True,
        )

        # Check expiry warnings every 6 hours
        self.scheduler.add_job(
            self._check_expiry_warnings,
            IntervalTrigger(hours=6),
            id="cert_expiry_check",
            name="Certificate Expiry Warning Check",
            replace_existing=True,
        )

        # Run initial check in 1 minute after startup
        self.scheduler.add_job(
            self._initial_check,
            "date",
            run_date=datetime.utcnow().replace(second=0, microsecond=0),
            id="cert_initial_check",
            name="Initial Certificate Check",
        )

        self.scheduler.start()
        self._started = True
        logger.info("Certificate renewal scheduler started")

    async def stop(self) -> None:
        """Stop the renewal scheduler."""
        if self._started:
            self.scheduler.shutdown(wait=False)
            self._started = False
            logger.info("Certificate renewal scheduler stopped")

    async def _initial_check(self) -> None:
        """Run initial certificate check on startup."""
        logger.info("Running initial certificate check")
        await self._check_expiry_warnings()

    async def _check_renewals(self) -> None:
        """
        Check and renew certificates expiring soon.

        Automatically renews Let's Encrypt certificates that:
        - Have auto_renew enabled
        - Expire within the configured renewal window
        """
        logger.info("Starting certificate renewal check")

        try:
            # Get certificates expiring within renewal window
            expiring = await self.cert_manager.get_expiring_soon(days=settings.cert_renewal_days)

            renewed_count = 0
            failed_count = 0

            for cert in expiring:
                # Only auto-renew Let's Encrypt certs with auto_renew enabled
                if not cert.auto_renew:
                    logger.debug(f"Skipping {cert.domain}: auto_renew disabled")
                    continue

                if cert.certificate_type != CertificateType.LETSENCRYPT:
                    logger.debug(f"Skipping {cert.domain}: not a Let's Encrypt cert")
                    continue

                logger.info(f"Auto-renewing certificate for {cert.domain}")

                try:
                    await self.cert_manager.renew_certificate(domain=cert.domain, force=False)

                    # Record success event
                    await self.event_store.record_event(
                        category=EventCategory.SSL,
                        action="auto_renewed",
                        message=f"Certificate for {cert.domain} auto-renewed successfully",
                        severity=EventSeverity.INFO,
                        resource_type="certificate",
                        resource_id=cert.domain,
                        details={"days_until_expiry": cert.days_until_expiry, "auto_renewal": True},
                    )

                    renewed_count += 1

                    # Reload NGINX after successful renewal
                    try:
                        await docker_service.reload_nginx()
                        logger.info(f"NGINX reloaded after renewing {cert.domain}")
                    except Exception as e:
                        logger.warning(f"Failed to reload NGINX after renewal: {e}")

                except CertificateError as e:
                    logger.error(f"Failed to renew {cert.domain}: {e.message}")

                    # Record failure event
                    await self.event_store.record_event(
                        category=EventCategory.SSL,
                        action="auto_renewal_failed",
                        message=f"Auto-renewal failed for {cert.domain}: {e.message}",
                        severity=EventSeverity.ERROR,
                        resource_type="certificate",
                        resource_id=cert.domain,
                        details={
                            "error": e.message,
                            "suggestion": e.suggestion,
                            "days_until_expiry": cert.days_until_expiry,
                        },
                    )

                    failed_count += 1

                except Exception as e:
                    logger.exception(f"Unexpected error renewing {cert.domain}: {e}")
                    failed_count += 1

            logger.info(f"Certificate renewal check complete: {renewed_count} renewed, {failed_count} failed")

        except Exception as e:
            logger.exception(f"Error in renewal check: {e}")

    async def _check_expiry_warnings(self) -> None:
        """
        Generate warning events for certificates expiring soon.

        Creates events for certificates expiring within the warning window
        to alert operators and AI agents.
        """
        logger.info("Checking certificate expiry warnings")

        try:
            # Get all certificates
            certs = await self.cert_manager.list_certificates()

            warning_count = 0

            for cert in certs:
                if not cert.not_after:
                    continue

                days_left = cert.days_until_expiry

                if days_left is None:
                    continue

                # Generate warnings for different thresholds
                if days_left < 0:
                    # Already expired
                    await self.event_store.record_event(
                        category=EventCategory.SSL,
                        action="certificate_expired",
                        message=f"Certificate for {cert.domain} has EXPIRED ({abs(days_left)} days ago)",
                        severity=EventSeverity.CRITICAL,
                        resource_type="certificate",
                        resource_id=cert.domain,
                        details={
                            "days_expired": abs(days_left),
                            "expiry_date": cert.not_after.isoformat(),
                            "auto_renew": cert.auto_renew,
                        },
                    )
                    warning_count += 1

                elif days_left <= 7:
                    # Critical: expiring within 7 days
                    await self.event_store.record_event(
                        category=EventCategory.SSL,
                        action="expiry_critical",
                        message=f"Certificate for {cert.domain} expires in {days_left} days (CRITICAL)",
                        severity=EventSeverity.CRITICAL,
                        resource_type="certificate",
                        resource_id=cert.domain,
                        details={
                            "days_until_expiry": days_left,
                            "expiry_date": cert.not_after.isoformat(),
                            "auto_renew": cert.auto_renew,
                        },
                    )
                    warning_count += 1

                elif days_left <= settings.cert_expiry_warning_days:
                    # Warning: expiring soon
                    await self.event_store.record_event(
                        category=EventCategory.SSL,
                        action="expiry_warning",
                        message=f"Certificate for {cert.domain} expires in {days_left} days",
                        severity=EventSeverity.WARNING,
                        resource_type="certificate",
                        resource_id=cert.domain,
                        details={
                            "days_until_expiry": days_left,
                            "expiry_date": cert.not_after.isoformat(),
                            "auto_renew": cert.auto_renew,
                        },
                    )
                    warning_count += 1

            logger.info(f"Expiry warning check complete: {warning_count} warnings generated")

        except Exception as e:
            logger.exception(f"Error in expiry warning check: {e}")

    async def trigger_renewal_check(self) -> dict:
        """
        Manually trigger a renewal check.

        Returns summary of actions taken.
        """
        logger.info("Manual renewal check triggered")
        await self._check_renewals()
        return {"status": "completed", "message": "Renewal check completed"}

    async def trigger_expiry_check(self) -> dict:
        """
        Manually trigger an expiry warning check.

        Returns summary of warnings generated.
        """
        logger.info("Manual expiry check triggered")
        await self._check_expiry_warnings()
        return {"status": "completed", "message": "Expiry check completed"}

    def get_next_run_times(self) -> dict:
        """Get next scheduled run times for all jobs."""
        jobs = {}
        for job in self.scheduler.get_jobs():
            jobs[job.id] = {"name": job.name, "next_run": job.next_run_time.isoformat() if job.next_run_time else None}
        return jobs


# Singleton instance
_cert_scheduler: CertScheduler | None = None


def get_cert_scheduler() -> CertScheduler:
    """Get the global certificate scheduler instance."""
    global _cert_scheduler
    if _cert_scheduler is None:
        _cert_scheduler = CertScheduler()
    return _cert_scheduler
