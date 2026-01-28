"""
NGINX configuration generator using Jinja2 templates.

Converts structured site configuration requests into valid
NGINX configuration file content.
"""

import logging
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, TemplateNotFound

from models.site_requests import SiteCreateRequest, SiteType

logger = logging.getLogger(__name__)

# Default template directory
DEFAULT_TEMPLATE_DIR = Path(__file__).parent / "templates"


class ConfigGeneratorError(Exception):
    """Base exception for config generator errors."""

    def __init__(self, message: str, site_name: Optional[str] = None):
        self.message = message
        self.site_name = site_name
        super().__init__(message)


class TemplateNotFoundError(ConfigGeneratorError):
    """Template file not found."""
    pass


class ConfigGenerator:
    """
    Generates NGINX configuration files from structured data.

    Uses Jinja2 templates to produce valid NGINX config syntax
    for different site types (static, reverse proxy).
    """

    def __init__(self, template_dir: Optional[Path] = None):
        """
        Initialize the config generator.

        Args:
            template_dir: Path to template directory. Uses default if not specified.
        """
        self.template_dir = template_dir or DEFAULT_TEMPLATE_DIR

        if not self.template_dir.exists():
            raise ConfigGeneratorError(
                f"Template directory not found: {self.template_dir}"
            )

        self.env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=False,  # NGINX configs don't need HTML escaping
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True
        )

        logger.info(f"ConfigGenerator initialized with templates from {self.template_dir}")

    def generate(self, request: SiteCreateRequest) -> str:
        """
        Generate NGINX config based on site type.

        Args:
            request: Site creation request with all config details

        Returns:
            Generated NGINX configuration as string

        Raises:
            ConfigGeneratorError: If generation fails
        """
        if request.site_type == SiteType.STATIC:
            return self.generate_static_site(request)
        elif request.site_type == SiteType.REVERSE_PROXY:
            return self.generate_reverse_proxy(request)
        else:
            raise ConfigGeneratorError(
                f"Unknown site type: {request.site_type}",
                site_name=request.name
            )

    def generate_static_site(self, request: SiteCreateRequest) -> str:
        """
        Generate configuration for a static file serving site.

        Args:
            request: Site creation request

        Returns:
            Generated NGINX configuration
        """
        try:
            template = self.env.get_template("static_site.conf.j2")
        except TemplateNotFound:
            raise TemplateNotFoundError(
                "Static site template not found",
                site_name=request.name
            )

        config = template.render(
            listen_port=request.listen_port,
            server_names=" ".join(request.server_names),
            root_path=request.root_path,
            index_files=" ".join(request.index_files)
        )

        logger.debug(f"Generated static site config for {request.name}")
        return config

    def generate_reverse_proxy(self, request: SiteCreateRequest) -> str:
        """
        Generate configuration for a reverse proxy site.

        Args:
            request: Site creation request

        Returns:
            Generated NGINX configuration
        """
        try:
            template = self.env.get_template("reverse_proxy.conf.j2")
        except TemplateNotFound:
            raise TemplateNotFoundError(
                "Reverse proxy template not found",
                site_name=request.name
            )

        config = template.render(
            listen_port=request.listen_port,
            server_names=" ".join(request.server_names),
            proxy_pass=request.proxy_pass
        )

        logger.debug(f"Generated reverse proxy config for {request.name}")
        return config

    def generate_ssl_static_site(
        self,
        server_names: str,
        root_path: str,
        ssl_cert_path: str,
        ssl_key_path: str,
        acme_challenge_dir: str,
        index_files: str = "index.html index.htm"
    ) -> str:
        """Generate SSL-enabled static site configuration."""
        try:
            template = self.env.get_template("ssl_static_site.conf.j2")
        except TemplateNotFound:
            raise TemplateNotFoundError("SSL static site template not found")

        config = template.render(
            server_names=server_names,
            root_path=root_path,
            index_files=index_files,
            ssl_cert_path=ssl_cert_path,
            ssl_key_path=ssl_key_path,
            acme_challenge_dir=acme_challenge_dir
        )
        logger.debug(f"Generated SSL static site config for {server_names}")
        return config

    def generate_ssl_reverse_proxy(
        self,
        server_names: str,
        proxy_pass: str,
        ssl_cert_path: str,
        ssl_key_path: str,
        acme_challenge_dir: str
    ) -> str:
        """Generate SSL-enabled reverse proxy configuration."""
        try:
            template = self.env.get_template("ssl_reverse_proxy.conf.j2")
        except TemplateNotFound:
            raise TemplateNotFoundError("SSL reverse proxy template not found")

        config = template.render(
            server_names=server_names,
            proxy_pass=proxy_pass,
            ssl_cert_path=ssl_cert_path,
            ssl_key_path=ssl_key_path,
            acme_challenge_dir=acme_challenge_dir
        )
        logger.debug(f"Generated SSL reverse proxy config for {server_names}")
        return config

    def validate_template(self, template_name: str) -> bool:
        """
        Check if a template exists and is valid.

        Args:
            template_name: Name of the template file

        Returns:
            True if template exists and can be loaded
        """
        try:
            self.env.get_template(template_name)
            return True
        except TemplateNotFound:
            return False


# Singleton instance
_config_generator: Optional[ConfigGenerator] = None


def get_config_generator() -> ConfigGenerator:
    """
    Get the global config generator instance.

    Returns:
        ConfigGenerator singleton instance
    """
    global _config_generator
    if _config_generator is None:
        _config_generator = ConfigGenerator()
    return _config_generator
