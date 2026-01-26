# NGINX configuration management module

from .crossplane_parser import CrossplaneParser, nginx_parser
from .adapter import ConfigAdapter

__all__ = ["CrossplaneParser", "ConfigAdapter", "nginx_parser"]
