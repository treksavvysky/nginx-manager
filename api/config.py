"""
Configuration utilities and settings management.

Handles environment variables, path resolution, and application settings.
"""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings


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
        default="nginx-manager-nginx", alias="NGINX_CONTAINER_NAME", description="Docker container name for NGINX"
    )
    nginx_health_endpoint: str = Field(
        default="http://nginx-manager-nginx/health",
        alias="NGINX_HEALTH_ENDPOINT",
        description="HTTP endpoint to verify NGINX health",
    )
    nginx_operation_timeout: int = Field(
        default=30, alias="NGINX_OPERATION_TIMEOUT", description="Timeout in seconds for NGINX operations"
    )
    nginx_health_check_retries: int = Field(
        default=5, alias="NGINX_HEALTH_CHECK_RETRIES", description="Number of health check retry attempts"
    )
    nginx_health_check_interval: float = Field(
        default=1.0, alias="NGINX_HEALTH_CHECK_INTERVAL", description="Seconds between health check retries"
    )

    # SSL Configuration
    letsencrypt_dir: str = Field(default="/etc/letsencrypt", alias="LETSENCRYPT_DIR")
    ssl_cert_dir: str = Field(default="/etc/ssl/certs", alias="SSL_CERT_DIR")

    # ACME/Let's Encrypt Configuration
    acme_directory_url: str = Field(
        default="https://acme-v02.api.letsencrypt.org/directory",
        alias="ACME_DIRECTORY_URL",
        description="ACME directory URL (production Let's Encrypt)",
    )
    acme_staging_url: str = Field(
        default="https://acme-staging-v02.api.letsencrypt.org/directory",
        alias="ACME_STAGING_URL",
        description="ACME staging directory URL for testing",
    )
    acme_use_staging: bool = Field(
        default=False,
        alias="ACME_USE_STAGING",
        description="Use staging environment to avoid rate limits during testing",
    )
    acme_account_email: str = Field(
        default="", alias="ACME_ACCOUNT_EMAIL", description="Email for Let's Encrypt account registration"
    )
    acme_challenge_dir: str = Field(
        default="/var/www/.well-known/acme-challenge",
        alias="ACME_CHALLENGE_DIR",
        description="Directory for ACME HTTP-01 challenge files",
    )
    cert_renewal_days: int = Field(
        default=30, alias="CERT_RENEWAL_DAYS", description="Days before expiry to trigger automatic renewal"
    )
    cert_expiry_warning_days: int = Field(
        default=14, alias="CERT_EXPIRY_WARNING_DAYS", description="Days before expiry to generate warning events"
    )

    # Safety Settings
    validate_before_deploy: bool = Field(default=True, alias="VALIDATE_BEFORE_DEPLOY")
    auto_backup: bool = Field(default=True, alias="AUTO_BACKUP")

    # Transaction & Event Settings
    transaction_db_path: str = Field(
        default="/var/backups/nginx/transactions.db",
        alias="TRANSACTION_DB_PATH",
        description="Path to SQLite database for transactions/events",
    )
    snapshot_dir: str = Field(
        default="/var/backups/nginx/snapshots",
        alias="SNAPSHOT_DIR",
        description="Directory for configuration snapshots",
    )
    snapshot_retention_days: int = Field(
        default=30, alias="SNAPSHOT_RETENTION_DAYS", description="Days to retain transaction snapshots"
    )
    event_retention_days: int = Field(
        default=90, alias="EVENT_RETENTION_DAYS", description="Days to retain event history"
    )
    auto_rollback_on_failure: bool = Field(
        default=True, alias="AUTO_ROLLBACK_ON_FAILURE", description="Automatically rollback on operation failure"
    )
    max_snapshots: int = Field(default=100, alias="MAX_SNAPSHOTS", description="Maximum number of snapshots to retain")

    # Workflow Configuration (Phase 4)
    workflow_step_timeout: int = Field(
        default=120, alias="WORKFLOW_STEP_TIMEOUT", description="Timeout in seconds for individual workflow steps"
    )
    workflow_auto_rollback: bool = Field(
        default=True,
        alias="WORKFLOW_AUTO_ROLLBACK",
        description="Automatically rollback checkpoint steps on workflow failure",
    )

    # Authentication (Phase 5)
    auth_enabled: bool = Field(default=False, alias="AUTH_ENABLED", description="Enable API key authentication")
    auth_master_key: str | None = Field(
        default=None, alias="AUTH_MASTER_KEY", description="Master key for bootstrapping the first admin API key"
    )
    jwt_secret_key: str | None = Field(
        default=None,
        alias="JWT_SECRET_KEY",
        description="Secret key for signing JWT tokens (required when AUTH_ENABLED=true)",
    )
    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM", description="Algorithm for JWT signing")
    jwt_expiry_minutes: int = Field(
        default=60, alias="JWT_EXPIRY_MINUTES", description="JWT token expiration time in minutes"
    )

    # MCP Authentication (Phase 5.3)
    mcp_api_key: str | None = Field(
        default=None, alias="MCP_API_KEY", description="API key for MCP server authentication (stdio transport)"
    )
    mcp_require_auth: bool = Field(
        default=True, alias="MCP_REQUIRE_AUTH", description="Require authentication for MCP connections"
    )

    # CORS & Security (Phase 5.3)
    cors_allowed_origins: str = Field(
        default="",
        alias="CORS_ALLOWED_ORIGINS",
        description="Comma-separated list of allowed CORS origins (empty = wildcard in debug mode only)",
    )

    # Private Key Encryption (Phase 3.4 carry-over)
    encrypt_private_keys: bool = Field(
        default=False, alias="ENCRYPT_PRIVATE_KEYS", description="Encrypt SSL private keys at rest using Fernet"
    )
    private_key_encryption_key: str | None = Field(
        default=None,
        alias="PRIVATE_KEY_ENCRYPTION_KEY",
        description="Passphrase for private key encryption (min 16 chars recommended)",
    )

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
        settings.snapshot_dir,
    ]

    for dir_path in dirs_to_create:
        Path(dir_path).mkdir(parents=True, exist_ok=True)


def is_nginx_available() -> bool:
    """Check if NGINX is available and accessible."""
    return Path(settings.nginx_binary).exists()


def is_development_mode() -> bool:
    """Check if we're running in development mode."""
    return settings.api_debug
