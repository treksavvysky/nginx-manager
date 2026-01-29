"""
Lightweight NGINX configuration parser.

Extracts basic information from NGINX server blocks without
full parsing complexity. Focuses on key directives needed
for management operations.
"""

import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class NginxConfigParser:
    """Lightweight parser for NGINX configuration files."""

    def __init__(self):
        # Regex patterns for common directives
        self.server_name_pattern = re.compile(r"server_name\s+([^;]+);", re.IGNORECASE)
        self.listen_pattern = re.compile(r"listen\s+([^;]+);", re.IGNORECASE)
        self.root_pattern = re.compile(r"root\s+([^;]+);", re.IGNORECASE)
        self.proxy_pass_pattern = re.compile(r"proxy_pass\s+([^;]+);", re.IGNORECASE)
        self.ssl_certificate_pattern = re.compile(r"ssl_certificate\s+([^;]+);", re.IGNORECASE)

    def parse_config_file(self, file_path: Path) -> dict[str, Any] | None:
        """
        Parse a single NGINX configuration file.

        Args:
            file_path: Path to the .conf file

        Returns:
            Dictionary containing parsed configuration data or None if parsing fails
        """
        try:
            if not file_path.exists():
                logger.warning(f"Config file not found: {file_path}")
                return None

            content = file_path.read_text(encoding="utf-8")

            # Extract basic file metadata
            stat = file_path.stat()
            config_data = {
                "name": file_path.stem,  # filename without .conf extension
                "file_path": str(file_path),
                "file_size": stat.st_size,
                "created_at": datetime.fromtimestamp(stat.st_ctime),
                "updated_at": datetime.fromtimestamp(stat.st_mtime),
                "server_name": self._extract_server_name(content),
                "listen_ports": self._extract_listen_ports(content),
                "ssl_enabled": self._detect_ssl(content),
                "root_path": self._extract_root(content),
                "proxy_pass": self._extract_proxy_pass(content),
                "has_ssl_cert": self._has_ssl_certificate(content),
            }

            return config_data

        except Exception as e:
            logger.error(f"Error parsing config file {file_path}: {e}")
            return None

    def _extract_server_name(self, content: str) -> str | None:
        """Extract server_name directive."""
        match = self.server_name_pattern.search(content)
        return match.group(1).strip() if match else None

    def _extract_listen_ports(self, content: str) -> list[int]:
        """Extract all listen ports from the configuration."""
        matches = self.listen_pattern.findall(content)
        ports = []

        for match in matches:
            # Handle different listen directive formats
            # listen 80; listen 443 ssl; listen [::]:80;
            port_str = match.strip().split()[0]  # Get first part

            # Remove IPv6 brackets and extract port
            if ":" in port_str and not port_str.startswith("["):
                port_str = port_str.split(":")[-1]
            elif port_str.startswith("["):
                # IPv6 format [::]:80
                port_str = port_str.split("]:")[-1] if "]:" in port_str else "80"

            try:
                port = int(port_str)
                if port not in ports:  # Avoid duplicates
                    ports.append(port)
            except ValueError:
                logger.warning(f"Could not parse port from: {match}")

        return sorted(ports)

    def _detect_ssl(self, content: str) -> bool:
        """Detect if SSL is enabled."""
        # Look for ssl in listen directive or ssl directives
        ssl_indicators = ["listen.*ssl", "ssl_certificate", "ssl_certificate_key", "listen.*443"]

        for indicator in ssl_indicators:
            if re.search(indicator, content, re.IGNORECASE):
                return True
        return False

    def _extract_root(self, content: str) -> str | None:
        """Extract root directive."""
        match = self.root_pattern.search(content)
        return match.group(1).strip() if match else None

    def _extract_proxy_pass(self, content: str) -> str | None:
        """Extract proxy_pass directive."""
        match = self.proxy_pass_pattern.search(content)
        return match.group(1).strip() if match else None

    def _has_ssl_certificate(self, content: str) -> bool:
        """Check if SSL certificate is configured."""
        return bool(self.ssl_certificate_pattern.search(content))


# Global parser instance
nginx_parser = NginxConfigParser()
