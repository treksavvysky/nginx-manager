"""
MCP Resources for NGINX Manager.

Resources provide read-only data that AI models can fetch for context.
Each resource has a URI pattern and returns structured data.
"""

import logging
from typing import Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


async def get_sites_resource() -> dict:
    """
    Get all site configurations.

    URI: nginx://sites

    Returns:
        dict: List of sites with summary statistics
    """
    from config import get_nginx_conf_path
    from core.config_manager import nginx_parser, ConfigAdapter

    conf_dir = get_nginx_conf_path()

    if not conf_dir.exists():
        return {
            "sites": [],
            "total": 0,
            "enabled_count": 0,
            "disabled_count": 0,
            "ssl_enabled_count": 0
        }

    # Find all .conf and .conf.disabled files
    conf_files = list(conf_dir.glob("*.conf"))
    disabled_files = list(conf_dir.glob("*.conf.disabled"))

    sites = []
    ssl_enabled_count = 0

    for conf_file in conf_files + disabled_files:
        try:
            parsed_config = nginx_parser.parse_config_file(conf_file)
            if parsed_config:
                rich_dict = ConfigAdapter.to_rich_dict(parsed_config)

                # Determine site type
                site_type = "reverse_proxy" if rich_dict.get("proxy_pass") else "static"

                site_data = {
                    "name": rich_dict.get("name"),
                    "server_names": rich_dict.get("server_names", []),
                    "listen_ports": rich_dict.get("listen_ports", [80]),
                    "ssl_enabled": rich_dict.get("ssl_enabled", False),
                    "site_type": site_type,
                    "proxy_pass": rich_dict.get("proxy_pass"),
                    "root_path": rich_dict.get("root_path"),
                    "enabled": rich_dict.get("enabled", True),
                    "status": rich_dict.get("status", "unknown"),
                    "certificate": None
                }

                if site_data["ssl_enabled"]:
                    ssl_enabled_count += 1

                sites.append(site_data)
        except Exception as e:
            logger.warning(f"Failed to parse {conf_file}: {e}")
            continue

    # Enrich with certificate data
    cert_count = 0
    try:
        from core.cert_helpers import get_certificate_map, match_certificate
        cert_map = await get_certificate_map()
        for site_data in sites:
            cert = match_certificate(site_data.get("server_names", []), cert_map)
            if cert:
                site_data["certificate"] = cert
                cert_count += 1
    except Exception as e:
        logger.warning(f"Failed to load certificate data for sites: {e}")

    return {
        "sites": sites,
        "total": len(sites),
        "enabled_count": len([s for s in sites if s["enabled"]]),
        "disabled_count": len([s for s in sites if not s["enabled"]]),
        "ssl_enabled_count": ssl_enabled_count,
        "certificate_count": cert_count
    }


async def get_site_resource(name: str) -> dict:
    """
    Get detailed configuration for a specific site.

    URI: nginx://sites/{name}

    Args:
        name: Site name (without .conf extension)

    Returns:
        dict: Detailed site configuration or error
    """
    from config import get_nginx_conf_path
    from core.config_manager import nginx_parser, ConfigAdapter

    conf_dir = get_nginx_conf_path()
    conf_file = conf_dir / f"{name}.conf"
    disabled_file = conf_dir / f"{name}.conf.disabled"

    target_file = None
    enabled = True

    if conf_file.exists():
        target_file = conf_file
        enabled = True
    elif disabled_file.exists():
        target_file = disabled_file
        enabled = False
    else:
        return {
            "error": f"Site '{name}' not found",
            "suggestions": [
                f"Create the site with: create_site(name='{name}', ...)",
                "List available sites with: nginx://sites"
            ]
        }

    try:
        parsed_config = nginx_parser.parse_config_file(target_file)
        if not parsed_config:
            return {
                "error": f"Failed to parse configuration for '{name}'",
                "suggestions": [
                    "Check the configuration file for syntax errors",
                    "Use nginx_test tool to validate configuration"
                ]
            }

        rich_dict = ConfigAdapter.to_rich_dict(parsed_config)
        rich_dict["enabled"] = enabled

        # Enrich with certificate data
        rich_dict["certificate"] = None
        try:
            from core.cert_helpers import get_certificate_map, match_certificate
            cert_map = await get_certificate_map()
            server_names = rich_dict.get("server_names", [])
            cert = match_certificate(server_names, cert_map)
            if cert:
                rich_dict["certificate"] = cert
        except Exception as e:
            logger.warning(f"Failed to load certificate data for site {name}: {e}")

        # Add suggestions based on current state
        suggestions = []
        if not rich_dict.get("ssl_enabled"):
            suggestions.append(f"Add SSL with: request_certificate(domain='{name}')")
        if not enabled:
            suggestions.append(f"Enable this site with: enable_site(name='{name}')")

        cert_info = rich_dict.get("certificate")
        if cert_info:
            days = cert_info.get("days_until_expiry")
            if days is not None and days <= 30:
                suggestions.append(f"Certificate expires in {days} days — renew with: renew_certificate(domain='{name}')")

        rich_dict["suggestions"] = suggestions
        return rich_dict

    except Exception as e:
        logger.error(f"Error parsing site {name}: {e}")
        return {
            "error": f"Error reading site configuration: {str(e)}",
            "suggestions": ["Check file permissions", "Verify configuration syntax"]
        }


async def get_certificates_resource(status_filter: Optional[str] = None) -> dict:
    """
    Get all SSL certificates with status.

    URI: nginx://certificates
    URI with filter: nginx://certificates?status=expiring_soon

    Args:
        status_filter: Optional status filter (valid, expiring_soon, expired)

    Returns:
        dict: List of certificates with summary statistics
    """
    from core.cert_manager import get_cert_manager
    from models.certificate import CertificateStatus

    try:
        cert_manager = get_cert_manager()

        # Convert string filter to enum if provided
        status_enum = None
        if status_filter:
            try:
                status_enum = CertificateStatus(status_filter.lower())
            except ValueError:
                pass

        certs = await cert_manager.list_certificates(status=status_enum)

        cert_list = []
        valid_count = 0
        expiring_soon_count = 0
        expired_count = 0

        for cert in certs:
            cert_data = {
                "domain": cert.domain,
                "alt_names": cert.alt_names,
                "type": cert.certificate_type.value if cert.certificate_type else "unknown",
                "status": cert.status.value if cert.status else "unknown",
                "issuer": cert.issuer,
                "not_after": cert.not_after.isoformat() if cert.not_after else None,
                "days_until_expiry": cert.days_until_expiry,
                "auto_renew": cert.auto_renew
            }
            cert_list.append(cert_data)

            if cert.status == CertificateStatus.VALID:
                valid_count += 1
            elif cert.status == CertificateStatus.EXPIRING_SOON:
                expiring_soon_count += 1
            elif cert.status == CertificateStatus.EXPIRED:
                expired_count += 1

        # Generate suggestions
        suggestions = []
        if expired_count > 0:
            suggestions.append(f"URGENT: {expired_count} certificate(s) have expired - renew immediately")
        if expiring_soon_count > 0:
            suggestions.append(f"{expiring_soon_count} certificate(s) expiring soon - consider renewing")
        if len(cert_list) == 0:
            suggestions.append("No certificates configured - use request_certificate to add SSL")

        return {
            "certificates": cert_list,
            "total": len(cert_list),
            "valid_count": valid_count,
            "expiring_soon_count": expiring_soon_count,
            "expired_count": expired_count,
            "suggestions": suggestions
        }

    except Exception as e:
        logger.error(f"Error listing certificates: {e}")
        return {
            "certificates": [],
            "total": 0,
            "error": str(e),
            "suggestions": ["Check database connection", "Verify SSL directory permissions"]
        }


async def get_certificate_resource(domain: str) -> dict:
    """
    Get detailed certificate information for a domain.

    URI: nginx://certificates/{domain}

    Args:
        domain: Domain name

    Returns:
        dict: Detailed certificate information or error
    """
    from core.cert_manager import get_cert_manager

    try:
        cert_manager = get_cert_manager()
        cert = await cert_manager.get_certificate(domain)

        if not cert:
            return {
                "error": f"No certificate found for '{domain}'",
                "suggestions": [
                    f"Request a certificate with: request_certificate(domain='{domain}')",
                    f"Check DNS configuration with: diagnose_ssl(domain='{domain}')",
                    "List all certificates with: nginx://certificates"
                ]
            }

        # Generate suggestions based on certificate state
        suggestions = []
        warnings = []

        if cert.is_expired:
            warnings.append("Certificate has EXPIRED - site visitors will see security warnings")
            suggestions.append(f"Renew immediately with: renew_certificate(domain='{domain}', force=true)")
        elif cert.is_expiring_soon:
            warnings.append(f"Certificate expires in {cert.days_until_expiry} days")
            suggestions.append(f"Renew with: renew_certificate(domain='{domain}')")

        if not cert.auto_renew:
            suggestions.append("Enable auto-renewal to prevent expiration issues")

        return {
            "domain": cert.domain,
            "alt_names": cert.alt_names,
            "type": cert.certificate_type.value if cert.certificate_type else "unknown",
            "status": cert.status.value if cert.status else "unknown",
            "issuer": cert.issuer,
            "serial_number": cert.serial_number,
            "not_before": cert.not_before.isoformat() if cert.not_before else None,
            "not_after": cert.not_after.isoformat() if cert.not_after else None,
            "days_until_expiry": cert.days_until_expiry,
            "fingerprint_sha256": cert.fingerprint_sha256,
            "cert_path": cert.cert_path,
            "key_path": cert.key_path,
            "auto_renew": cert.auto_renew,
            "last_renewed": cert.last_renewed.isoformat() if cert.last_renewed else None,
            "suggestions": suggestions,
            "warnings": warnings
        }

    except Exception as e:
        logger.error(f"Error getting certificate for {domain}: {e}")
        return {
            "error": f"Error retrieving certificate: {str(e)}",
            "domain": domain,
            "suggestions": ["Check certificate database", "Verify domain spelling"]
        }


async def get_health_resource() -> dict:
    """
    Get system health and status summary.

    URI: nginx://health

    Returns:
        dict: Comprehensive system health information
    """
    from core.docker_service import docker_service, DockerServiceError
    from core.cert_manager import get_cert_manager
    from core.event_store import get_event_store
    from config import get_nginx_conf_path
    from models.certificate import CertificateStatus
    from models.event import EventFilters

    # Get NGINX status
    nginx_status = {
        "status": "unknown",
        "container_id": None,
        "uptime_seconds": None,
        "worker_count": None,
        "active_connections": None,
        "config_valid": None
    }

    try:
        container_status = await docker_service.get_container_status()
        if container_status.get("running"):
            nginx_status.update({
                "status": "running",
                "container_id": container_status.get("container_id"),
                "uptime_seconds": container_status.get("uptime_seconds"),
                "worker_count": container_status.get("worker_count"),
                "active_connections": container_status.get("active_connections"),
                "health_status": container_status.get("health_status", "unknown")
            })

            # Test config validity
            success, _, _ = await docker_service.test_config()
            nginx_status["config_valid"] = success
        else:
            nginx_status["status"] = "stopped"
    except DockerServiceError as e:
        nginx_status["status"] = "error"
        nginx_status["error"] = e.message

    # Get sites summary
    conf_dir = get_nginx_conf_path()
    enabled_sites = len(list(conf_dir.glob("*.conf"))) if conf_dir.exists() else 0
    disabled_sites = len(list(conf_dir.glob("*.conf.disabled"))) if conf_dir.exists() else 0

    # Get certificate summary
    cert_summary = {
        "total": 0,
        "valid": 0,
        "expiring_soon": 0,
        "expired": 0
    }

    try:
        cert_manager = get_cert_manager()
        certs = await cert_manager.list_certificates()
        cert_summary["total"] = len(certs)
        cert_summary["valid"] = len([c for c in certs if c.status == CertificateStatus.VALID])
        cert_summary["expiring_soon"] = len([c for c in certs if c.status == CertificateStatus.EXPIRING_SOON])
        cert_summary["expired"] = len([c for c in certs if c.status == CertificateStatus.EXPIRED])
    except Exception as e:
        logger.warning(f"Failed to get certificate summary: {e}")

    # Get recent events summary
    recent_events = {"errors": 0, "warnings": 0}
    try:
        event_store = get_event_store()
        since = datetime.utcnow() - timedelta(hours=24)
        counts = await event_store.get_event_counts_by_severity(since=since)
        recent_events["errors"] = counts.error + counts.critical
        recent_events["warnings"] = counts.warning
    except Exception as e:
        logger.warning(f"Failed to get event counts: {e}")

    # Determine overall health status
    overall_status = "healthy"
    if nginx_status["status"] != "running":
        overall_status = "unhealthy"
    elif cert_summary["expired"] > 0 or recent_events["errors"] > 0:
        overall_status = "degraded"
    elif nginx_status.get("config_valid") is False:
        overall_status = "degraded"

    # Generate suggestions based on state
    suggestions = []
    warnings = []

    if nginx_status["status"] != "running":
        suggestions.append("Start NGINX container to serve traffic")
    if nginx_status.get("config_valid") is False:
        warnings.append("NGINX configuration has errors - run nginx_test for details")
    if cert_summary["expired"] > 0:
        warnings.append(f"{cert_summary['expired']} certificate(s) have expired")
        suggestions.append("View expired certificates: nginx://certificates?status=expired")
    if cert_summary["expiring_soon"] > 0:
        warnings.append(f"{cert_summary['expiring_soon']} certificate(s) expiring soon")
    if enabled_sites == 0:
        suggestions.append("No sites configured - create one with: create_site(...)")
    if recent_events["errors"] > 0:
        warnings.append(f"{recent_events['errors']} error(s) in the last 24 hours")
        suggestions.append("Review errors: nginx://events?severity=error")

    return {
        "status": overall_status,
        "timestamp": datetime.utcnow().isoformat(),
        "nginx": nginx_status,
        "sites": {
            "total": enabled_sites + disabled_sites,
            "enabled": enabled_sites,
            "disabled": disabled_sites
        },
        "certificates": cert_summary,
        "recent_events": recent_events,
        "suggestions": suggestions,
        "warnings": warnings
    }


async def get_events_resource(
    severity: Optional[str] = None,
    limit: int = 50
) -> dict:
    """
    Get recent system events.

    URI: nginx://events
    URI with filter: nginx://events?severity=error&limit=50

    Args:
        severity: Optional severity filter (info, warning, error, critical)
        limit: Maximum number of events to return

    Returns:
        dict: List of recent events
    """
    from core.event_store import get_event_store
    from models.event import EventFilters, EventSeverity
    from datetime import datetime, timedelta

    try:
        event_store = get_event_store()

        # Build filters
        filters = EventFilters(
            since=datetime.utcnow() - timedelta(hours=24)
        )

        if severity:
            try:
                filters.severity = EventSeverity(severity.lower())
            except ValueError:
                pass

        result = await event_store.list_events(filters=filters, page=1, page_size=limit)

        events = []
        for event in result.events:
            events.append({
                "id": event.id,
                "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                "severity": event.severity.value if event.severity else "info",
                "category": event.category.value if event.category else "system",
                "action": event.action,
                "resource_type": event.resource_type,
                "resource_id": event.resource_id,
                "message": event.message,
                "transaction_id": event.transaction_id
            })

        return {
            "events": events,
            "total": result.total,
            "filtered_by": {"severity": severity} if severity else None
        }

    except Exception as e:
        logger.error(f"Error listing events: {e}")
        return {
            "events": [],
            "total": 0,
            "error": str(e)
        }


async def get_transactions_resource(
    status: Optional[str] = None,
    limit: int = 20
) -> dict:
    """
    Get recent transactions with rollback capability.

    URI: nginx://transactions
    URI with filter: nginx://transactions?status=completed&limit=10

    Args:
        status: Optional status filter (pending, completed, failed, rolled_back)
        limit: Maximum number of transactions to return

    Returns:
        dict: List of recent transactions
    """
    from core.transaction_manager import get_transaction_manager
    from models.transaction import TransactionStatus

    try:
        txn_manager = get_transaction_manager()

        # Convert string status to enum if provided
        status_enum = None
        if status:
            try:
                status_enum = TransactionStatus(status.lower())
            except ValueError:
                pass

        result = await txn_manager.list_transactions(
            limit=limit,
            offset=0,
            status=status_enum
        )

        transactions = []
        for txn in result.transactions:
            can_rollback, rollback_reason = await txn_manager.can_rollback(txn.id)

            transactions.append({
                "id": txn.id,
                "operation": txn.operation.value if txn.operation else None,
                "status": txn.status.value if txn.status else None,
                "resource_type": txn.resource_type,
                "resource_id": txn.resource_id,
                "created_at": txn.created_at.isoformat() if txn.created_at else None,
                "completed_at": txn.completed_at.isoformat() if txn.completed_at else None,
                "duration_ms": txn.duration_ms,
                "can_rollback": can_rollback,
                "rollback_reason": rollback_reason if not can_rollback else None
            })

        return {
            "transactions": transactions,
            "total": result.total,
            "filtered_by": {"status": status} if status else None
        }

    except Exception as e:
        logger.error(f"Error listing transactions: {e}")
        return {
            "transactions": [],
            "total": 0,
            "error": str(e)
        }


async def get_transaction_resource(transaction_id: str) -> dict:
    """
    Get detailed transaction information with diff.

    URI: nginx://transactions/{id}

    Args:
        transaction_id: Transaction ID

    Returns:
        dict: Detailed transaction information or error
    """
    from core.transaction_manager import get_transaction_manager

    try:
        txn_manager = get_transaction_manager()
        detail = await txn_manager.get_transaction_detail(transaction_id)

        if not detail:
            return {
                "error": f"Transaction '{transaction_id}' not found",
                "suggestions": [
                    "List recent transactions: nginx://transactions",
                    "Check the transaction ID for typos"
                ]
            }

        can_rollback, rollback_reason = await txn_manager.can_rollback(transaction_id)

        result = {
            "id": detail.id,
            "operation": detail.operation.value if detail.operation else None,
            "status": detail.status.value if detail.status else None,
            "resource_type": detail.resource_type,
            "resource_id": detail.resource_id,
            "created_at": detail.created_at.isoformat() if detail.created_at else None,
            "started_at": detail.started_at.isoformat() if detail.started_at else None,
            "completed_at": detail.completed_at.isoformat() if detail.completed_at else None,
            "duration_ms": detail.duration_ms,
            "error_message": detail.error_message,
            "can_rollback": can_rollback,
            "rollback_reason": rollback_reason if not can_rollback else None
        }

        if detail.diff:
            result["diff"] = {
                "files_changed": detail.diff.files_changed,
                "total_additions": detail.diff.total_additions,
                "total_deletions": detail.diff.total_deletions
            }

        # Add suggestions
        suggestions = []
        if can_rollback:
            suggestions.append(f"Rollback this transaction: rollback_transaction(transaction_id='{transaction_id}')")
        if detail.resource_type == "site" and detail.resource_id:
            suggestions.append(f"View affected site: nginx://sites/{detail.resource_id}")

        result["suggestions"] = suggestions

        return result

    except Exception as e:
        logger.error(f"Error getting transaction {transaction_id}: {e}")
        return {
            "error": f"Error retrieving transaction: {str(e)}",
            "transaction_id": transaction_id
        }
