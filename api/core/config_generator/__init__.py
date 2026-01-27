"""
NGINX configuration generator.

Generates valid NGINX configuration files from structured request data
using Jinja2 templates.
"""

from .generator import ConfigGenerator, ConfigGeneratorError, get_config_generator

__all__ = ["ConfigGenerator", "ConfigGeneratorError", "get_config_generator"]
