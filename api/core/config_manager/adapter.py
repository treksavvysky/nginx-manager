"""
Adapter to convert rich ParsedNginxConfig to API response formats.

Ensures backward compatibility with existing API consumers while
enabling access to rich nested data for new consumers.
"""

from pathlib import Path
from typing import Dict, Any, Optional, List

from models.nginx import ParsedNginxConfig, ServerBlock, LocationBlock, UpstreamBlock


class ConfigAdapter:
    """Converts between parser output and API response formats."""

    @staticmethod
    def to_legacy_dict(parsed: ParsedNginxConfig) -> Dict[str, Any]:
        """
        Convert ParsedNginxConfig to legacy flat dictionary format.

        This maintains backward compatibility with existing SiteConfigResponse
        consumers by extracting primary values from the first server block.

        Args:
            parsed: Full parsed configuration

        Returns:
            Dictionary compatible with SiteConfigResponse(**dict)
        """
        # Find the best primary server: prefer SSL-enabled block, otherwise first
        primary_server = None
        ssl_server = None
        for server in parsed.server_blocks:
            if primary_server is None:
                primary_server = server
            if server.ssl.enabled and ssl_server is None:
                ssl_server = server

        # Extract first server_name
        server_name = None
        if primary_server and primary_server.server_names:
            server_name = " ".join(primary_server.server_names)

        # Extract all unique ports from ALL server blocks
        listen_ports = []
        ports_set = set()
        for server in parsed.server_blocks:
            for port in ConfigAdapter._extract_ports(server):
                if port not in ports_set:
                    ports_set.add(port)
                    listen_ports.append(port)
        listen_ports.sort()

        # Determine SSL status - check ALL server blocks
        ssl_enabled = ssl_server is not None
        has_ssl_cert = bool(ssl_server.ssl.certificate) if ssl_server else False

        # Find root path (server level or first location)
        root_path = ConfigAdapter._find_root(primary_server)

        # Find proxy_pass (first one found in locations)
        proxy_pass = ConfigAdapter._find_proxy_pass(primary_server)

        # Determine enabled status from file extension
        file_path = Path(parsed.file_path)
        is_enabled = not file_path.name.endswith('.disabled')

        # Get site name (strip .disabled if present)
        name = file_path.stem
        if name.endswith('.conf'):
            name = name[:-5]  # Remove .conf from name like "site.conf.disabled"

        return {
            "name": name,
            "file_path": parsed.file_path,
            "file_size": parsed.file_size,
            "created_at": parsed.created_at,
            "updated_at": parsed.updated_at,
            "server_name": server_name,
            "listen_ports": listen_ports,
            "ssl_enabled": ssl_enabled,
            "root_path": root_path,
            "proxy_pass": proxy_pass,
            "has_ssl_cert": has_ssl_cert,
            "enabled": is_enabled,
        }

    @staticmethod
    def _extract_ports(server: Optional[ServerBlock]) -> List[int]:
        """Extract all unique listen ports from a server block."""
        if not server:
            return []

        ports = set()
        for listen in server.listen:
            if listen.port > 0:
                ports.add(listen.port)

        return sorted(list(ports))

    @staticmethod
    def _find_root(server: Optional[ServerBlock]) -> Optional[str]:
        """Find the root path from server or location blocks."""
        if not server:
            return None

        # Check server-level root first
        if server.root:
            return server.root

        # Check locations for root
        for location in server.locations:
            if location.root:
                return location.root

        return None

    @staticmethod
    def _find_proxy_pass(server: Optional[ServerBlock]) -> Optional[str]:
        """Find the first proxy_pass from location blocks."""
        if not server:
            return None

        for location in server.locations:
            if location.proxy_pass:
                return location.proxy_pass

        return None

    @staticmethod
    def to_rich_dict(parsed: ParsedNginxConfig) -> Dict[str, Any]:
        """
        Convert to dictionary with both legacy and rich fields.

        This provides all the data needed for SiteConfigResponse including
        the new optional rich fields.

        Args:
            parsed: Full parsed configuration

        Returns:
            Dictionary with legacy + rich fields
        """
        # Start with legacy format
        result = ConfigAdapter.to_legacy_dict(parsed)

        # Find servers: prefer SSL-enabled for SSL config, use first for general config
        primary_server = parsed.server_blocks[0] if parsed.server_blocks else None
        ssl_server = None
        for server in parsed.server_blocks:
            if server.ssl.enabled:
                ssl_server = server
                break

        if primary_server:
            # All server names as list
            result["server_names"] = primary_server.server_names

            # Location blocks - use SSL server if available for richer content
            content_server = ssl_server if ssl_server else primary_server
            result["locations"] = [
                ConfigAdapter._location_to_dict(loc)
                for loc in content_server.locations
            ]

            # SSL config - use SSL server if available
            ssl_source = ssl_server if ssl_server else primary_server
            result["ssl_config"] = {
                "enabled": ssl_source.ssl.enabled,
                "certificate": ssl_source.ssl.certificate,
                "certificate_key": ssl_source.ssl.certificate_key,
                "protocols": ssl_source.ssl.protocols,
                "ciphers": ssl_source.ssl.ciphers,
            }

        # Upstreams (file-level, not server-level)
        result["upstreams"] = [
            ConfigAdapter._upstream_to_dict(up)
            for up in parsed.upstreams
        ]

        # Parse errors if any
        if parsed.errors:
            result["parse_errors"] = parsed.errors

        return result

    @staticmethod
    def _location_to_dict(location: LocationBlock) -> Dict[str, Any]:
        """Convert LocationBlock to dictionary."""
        return {
            "modifier": location.modifier,
            "path": location.path,
            "proxy_pass": location.proxy_pass,
            "root": location.root,
            "alias": location.alias,
            "try_files": location.try_files,
            "headers": location.headers,
            "line": location.line,
        }

    @staticmethod
    def _upstream_to_dict(upstream: UpstreamBlock) -> Dict[str, Any]:
        """Convert UpstreamBlock to dictionary."""
        return {
            "name": upstream.name,
            "servers": [
                {
                    "address": s.address,
                    "weight": s.weight,
                    "backup": s.backup,
                    "down": s.down,
                }
                for s in upstream.servers
            ],
            "load_balancing": upstream.load_balancing,
            "keepalive": upstream.keepalive,
        }
