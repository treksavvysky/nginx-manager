"""
Configuration utilities and settings management.

Handles environment variables, path resolution, and application settings.
"""

import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # API Configuration
    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_port: int = Field(default=8000, alias="API_PORT")
    api_debug: bool = Field(default=True, alias="API_DEBUG")
    
    # NGINX Paths
    nginx_conf_dir: str = Field(default="/etc/nginx/conf.d", alias="NGINX_CONF_DIR")
    nginx_main_conf: str = Field(default="/etc/nginx/nginx.conf", alias="NGINX_MAIN_CONF")
    nginx_binary: str = Field(default="/usr/sbin/nginx", alias="NGINX_BINARY")
    nginx_backup_dir: str = Field(default="/var/backups/nginx", alias="NGINX_BACKUP_DIR")

    # NGINX Container Configuration
    nginx_container_name: str = Field(
        default="nginx-manager-nginx",
        alias="NGINX_CONTAINER_NAME",
        description="Docker container name for NGINX"
    )
    nginx_health_endpoint: str = Field(
        default="http://nginx-manager-nginx/health",
        alias="NGINX_HEALTH_ENDPOINT",
        description="HTTP endpoint to verify NGINX health"
    )
    nginx_operation_timeout: int = Field(
        default=30,
        alias="NGINX_OPERATION_TIMEOUT",
        description="Timeout in seconds for NGINX operations"
    )
    nginx_health_check_retries: int = Field(
        default=5,
        alias="NGINX_HEALTH_CHECK_RETRIES",
        description="Number of health check retry attempts"
    )
    nginx_health_check_interval: float = Field(
        default=1.0,
        alias="NGINX_HEALTH_CHECK_INTERVAL",
        description="Seconds between health check retries"
    )
    
    # SSL Configuration
    letsencrypt_dir: str = Field(default="/etc/letsencrypt", alias="LETSENCRYPT_DIR")
    ssl_cert_dir: str = Field(default="/etc/ssl/certs", alias="SSL_CERT_DIR")
    
    # Safety Settings
    validate_before_deploy: bool = Field(default=True, alias="VALIDATE_BEFORE_DEPLOY")
    auto_backup: bool = Field(default=True, alias="AUTO_BACKUP")
    
    # Logging
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    
    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "ignore"  # Ignore extra fields in .env file


# Global settings instance
settings = Settings()


def get_nginx_conf_path() -> Path:
    """Get the NGINX configuration directory path."""
    return Path(settings.nginx_conf_dir)


def ensure_directories():
    """Ensure required directories exist (for development/testing)."""
    dirs_to_create = [
        settings.nginx_backup_dir,
    ]
    
    for dir_path in dirs_to_create:
        Path(dir_path).mkdir(parents=True, exist_ok=True)


def is_nginx_available() -> bool:
    """Check if NGINX is available and accessible."""
    return Path(settings.nginx_binary).exists()


def is_development_mode() -> bool:
    """Check if we're running in development mode."""
    return settings.api_debug
