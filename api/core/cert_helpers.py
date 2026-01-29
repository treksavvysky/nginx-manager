"""
Certificate lookup helpers for enriching site responses.

Provides efficient domain-to-certificate matching so site endpoints
can include certificate status without N+1 database queries.
"""

import logging

logger = logging.getLogger(__name__)


async def get_certificate_map() -> dict[str, dict]:
    """
    Load all certificates and build a domain → cert summary lookup.

    Returns a dict keyed by every domain (primary + alt_names) that maps
    to a certificate summary dict. Querying once and building a map
    avoids repeated database hits when listing multiple sites.
    """
    from core.cert_manager import get_cert_manager

    cert_manager = get_cert_manager()
    certs = await cert_manager.list_certificates()

    cert_map: dict[str, dict] = {}
    for cert in certs:
        summary = {
            "domain": cert.domain,
            "status": cert.status.value if cert.status else "unknown",
            "type": cert.certificate_type.value if cert.certificate_type else "unknown",
            "issuer": cert.issuer,
            "not_after": cert.not_after.isoformat() if cert.not_after else None,
            "days_until_expiry": cert.days_until_expiry,
            "auto_renew": cert.auto_renew,
        }

        # Index by primary domain
        cert_map[cert.domain] = summary

        # Index by alt names
        if cert.alt_names:
            for alt in cert.alt_names:
                if alt not in cert_map:
                    cert_map[alt] = summary

    return cert_map


def match_certificate(server_names: list[str], cert_map: dict[str, dict]) -> dict | None:
    """
    Find a matching certificate for a list of server names.

    Args:
        server_names: Domain names from the site's server_name directive
        cert_map: Domain → cert summary map from get_certificate_map()

    Returns:
        Certificate summary dict if a match is found, None otherwise
    """
    for name in server_names:
        if name in cert_map:
            return cert_map[name]
    return None
