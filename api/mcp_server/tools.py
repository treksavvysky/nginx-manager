"""
MCP Tools for NGINX Manager.

Tools enable AI models to perform actions with side effects.
All mutation tools support dry_run parameter for previewing changes.
"""

import logging
from typing import Optional, List

logger = logging.getLogger(__name__)


# =============================================================================
# Site Management Tools
# =============================================================================

async def create_site(
    name: str,
    server_names: List[str],
    site_type: str,
    listen_port: int = 80,
    root_path: Optional[str] = None,
    proxy_pass: Optional[str] = None,
    auto_reload: bool = True,
    dry_run: bool = False
) -> dict:
    """
    Create a new NGINX site configuration.

    Args:
        name: Site name (used as filename and identifier)
        server_names: Domain names for this site
        site_type: Type of site - "static" or "reverse_proxy"
        listen_port: Port to listen on (default: 80)
        root_path: Document root for static sites
        proxy_pass: Backend URL for reverse proxy sites
        auto_reload: Reload NGINX after creating site (default: True)
        dry_run: Preview changes without applying (default: False)

    Returns:
        dict: Operation result with transaction_id and suggestions
    """
    from pathlib import Path
    from config import get_nginx_conf_path, settings
    from core.config_generator import get_config_generator, ConfigGeneratorError
    from core.docker_service import docker_service, DockerServiceError
    from core.transaction_context import transactional_operation
    from core.context_helpers import get_site_create_suggestions, get_config_warnings
    from models.site_requests import SiteCreateRequest, SiteType
    from models.transaction import OperationType
    import tempfile
    import shutil

    conf_dir = get_nginx_conf_path()
    conf_file = conf_dir / f"{name}.conf"
    disabled_file = conf_dir / f"{name}.conf.disabled"

    # Check if site already exists
    if conf_file.exists():
        return {
            "success": False,
            "message": f"Site '{name}' already exists",
            "suggestions": [
                f"Update with: update_site(name='{name}', ...)",
                f"View current config: nginx://sites/{name}"
            ]
        }

    if disabled_file.exists():
        return {
            "success": False,
            "message": f"Site '{name}' exists but is disabled",
            "suggestions": [
                f"Enable it: enable_site(name='{name}')",
                f"Delete first: delete_site(name='{name}')"
            ]
        }

    # Validate site_type
    try:
        site_type_enum = SiteType(site_type.lower())
    except ValueError:
        return {
            "success": False,
            "message": f"Invalid site_type '{site_type}'. Must be 'static' or 'reverse_proxy'",
            "suggestions": ["Use site_type='static' for serving files", "Use site_type='reverse_proxy' for proxying to backend"]
        }

    # Create request model
    request = SiteCreateRequest(
        name=name,
        server_names=server_names,
        site_type=site_type_enum,
        listen_port=listen_port,
        root_path=root_path,
        proxy_pass=proxy_pass,
        auto_reload=auto_reload
    )

    # Generate configuration
    try:
        generator = get_config_generator()
        config_content = generator.generate(request)
    except ConfigGeneratorError as e:
        return {
            "success": False,
            "message": f"Failed to generate configuration: {e.message}",
            "suggestions": ["Check required fields for your site_type"]
        }

    # Validate configuration
    validation_passed = True
    validation_output = None

    if settings.validate_before_deploy:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as tmp_file:
            tmp_file.write(config_content)
            tmp_path = Path(tmp_file.name)

        try:
            shutil.copy(tmp_path, conf_file)
            success, stdout, stderr = await docker_service.test_config()
            validation_output = stderr or stdout
            if not success:
                validation_passed = False
                conf_file.unlink(missing_ok=True)
        finally:
            tmp_path.unlink(missing_ok=True)
            if dry_run:
                conf_file.unlink(missing_ok=True)

    # If dry_run, return preview result
    if dry_run:
        lines = config_content.count('\n') + 1
        return {
            "dry_run": True,
            "would_succeed": validation_passed,
            "operation": "create_site",
            "message": f"Would create site '{name}' with {lines} lines of configuration",
            "validation_passed": validation_passed,
            "validation_output": validation_output,
            "generated_config": config_content,
            "file_path": str(conf_file),
            "reload_required": True,
            "warnings": [] if validation_passed else ["Configuration validation failed"]
        }

    # Actual creation (not dry run)
    if not validation_passed:
        return {
            "success": False,
            "message": f"Configuration validation failed: {validation_output}",
            "suggestions": ["Review the generated configuration", "Check NGINX syntax requirements"]
        }

    async with transactional_operation(
        operation=OperationType.SITE_CREATE,
        resource_type="site",
        resource_id=name
    ) as ctx:
        try:
            conf_file.write_text(config_content)
            logger.info(f"Created site configuration: {conf_file}")

            reloaded = False
            if auto_reload:
                try:
                    await docker_service.reload_nginx()
                    reloaded = True
                except DockerServiceError as e:
                    logger.warning(f"Failed to reload NGINX: {e.message}")

            suggestions = get_site_create_suggestions(
                site_name=name,
                site_type=site_type,
                reloaded=reloaded,
                enabled=True
            )
            warnings = get_config_warnings(
                ssl_enabled=False,
                has_ssl_cert=False,
                listen_ports=[listen_port],
                proxy_pass=proxy_pass,
                root_path=root_path
            )

            return {
                "success": True,
                "message": f"Site '{name}' created successfully",
                "site_name": name,
                "transaction_id": ctx.id,
                "file_path": str(conf_file),
                "reload_required": not reloaded,
                "reloaded": reloaded,
                "enabled": True,
                "suggestions": suggestions,
                "warnings": warnings
            }

        except Exception as e:
            logger.error(f"Error creating site: {e}")
            return {
                "success": False,
                "message": f"Failed to create site: {str(e)}",
                "suggestions": ["Check file permissions", "Verify NGINX configuration directory"]
            }


async def update_site(
    name: str,
    server_names: Optional[List[str]] = None,
    listen_port: Optional[int] = None,
    root_path: Optional[str] = None,
    proxy_pass: Optional[str] = None,
    auto_reload: bool = True,
    dry_run: bool = False
) -> dict:
    """
    Update an existing site configuration.

    Args:
        name: Site name to update
        server_names: Updated domain names (optional)
        listen_port: Updated listen port (optional)
        root_path: Updated document root (optional)
        proxy_pass: Updated backend URL (optional)
        auto_reload: Reload NGINX after update (default: True)
        dry_run: Preview changes without applying (default: False)

    Returns:
        dict: Operation result with transaction_id and suggestions
    """
    from config import get_nginx_conf_path, settings
    from core.config_manager import nginx_parser, ConfigAdapter
    from core.config_generator import get_config_generator
    from core.docker_service import docker_service, DockerServiceError
    from core.transaction_context import transactional_operation
    from core.context_helpers import get_site_update_suggestions, get_config_warnings
    from models.site_requests import SiteCreateRequest, SiteType
    from models.transaction import OperationType
    import shutil

    conf_dir = get_nginx_conf_path()
    conf_file = conf_dir / f"{name}.conf"

    if not conf_file.exists():
        disabled_file = conf_dir / f"{name}.conf.disabled"
        if disabled_file.exists():
            return {
                "success": False,
                "message": f"Site '{name}' is disabled. Enable it before updating.",
                "suggestions": [f"Enable first: enable_site(name='{name}')"]
            }
        return {
            "success": False,
            "message": f"Site '{name}' not found",
            "suggestions": [
                f"Create it: create_site(name='{name}', ...)",
                "List available sites: nginx://sites"
            ]
        }

    # Parse existing configuration
    parsed_config = nginx_parser.parse_config_file(conf_file)
    if not parsed_config:
        return {
            "success": False,
            "message": f"Failed to parse existing configuration for '{name}'",
            "suggestions": ["Check configuration syntax", "Consider recreating the site"]
        }

    current_content = conf_file.read_text()
    existing = ConfigAdapter.to_rich_dict(parsed_config)

    # Determine site type from existing config
    site_type = SiteType.REVERSE_PROXY if existing.get("proxy_pass") else SiteType.STATIC

    # Merge existing with updates
    merged_server_names = server_names or existing.get("server_names") or [name]
    merged_listen_port = listen_port or (existing.get("listen_ports", [80])[0] if existing.get("listen_ports") else 80)
    merged_root_path = root_path if root_path is not None else existing.get("root_path")
    merged_proxy_pass = proxy_pass if proxy_pass is not None else existing.get("proxy_pass")

    # Generate new configuration
    create_request = SiteCreateRequest(
        name=name,
        server_names=merged_server_names,
        site_type=site_type,
        listen_port=merged_listen_port,
        root_path=merged_root_path,
        proxy_pass=merged_proxy_pass,
        auto_reload=auto_reload
    )

    generator = get_config_generator()
    config_content = generator.generate(create_request)

    # Validate configuration
    validation_passed = True
    validation_output = None

    if settings.validate_before_deploy:
        backup_path = conf_file.with_suffix('.conf.bak')
        shutil.copy(conf_file, backup_path)
        try:
            conf_file.write_text(config_content)
            success, stdout, stderr = await docker_service.test_config()
            validation_output = stderr or stdout
            if not success:
                validation_passed = False
            shutil.copy(backup_path, conf_file)
        finally:
            backup_path.unlink(missing_ok=True)

    # If dry_run, return preview result
    if dry_run:
        return {
            "dry_run": True,
            "would_succeed": validation_passed,
            "operation": "update_site",
            "message": f"Would update site '{name}'",
            "validation_passed": validation_passed,
            "validation_output": validation_output,
            "current_content": current_content,
            "new_content": config_content,
            "file_path": str(conf_file),
            "reload_required": True
        }

    if not validation_passed:
        return {
            "success": False,
            "message": f"Configuration validation failed: {validation_output}",
            "suggestions": ["Review the changes", "Check NGINX syntax"]
        }

    async with transactional_operation(
        operation=OperationType.SITE_UPDATE,
        resource_type="site",
        resource_id=name
    ) as ctx:
        try:
            conf_file.write_text(config_content)
            logger.info(f"Updated site configuration: {conf_file}")

            reloaded = False
            if auto_reload:
                try:
                    await docker_service.reload_nginx()
                    reloaded = True
                except DockerServiceError as e:
                    logger.warning(f"Failed to reload NGINX: {e.message}")

            suggestions = get_site_update_suggestions(
                site_name=name,
                reloaded=reloaded,
                changes_made=[]
            )
            warnings = get_config_warnings(
                ssl_enabled=False,
                has_ssl_cert=False,
                listen_ports=[merged_listen_port],
                proxy_pass=merged_proxy_pass,
                root_path=merged_root_path
            )

            return {
                "success": True,
                "message": f"Site '{name}' updated successfully",
                "site_name": name,
                "transaction_id": ctx.id,
                "file_path": str(conf_file),
                "reload_required": not reloaded,
                "reloaded": reloaded,
                "suggestions": suggestions,
                "warnings": warnings
            }

        except Exception as e:
            logger.error(f"Error updating site: {e}")
            return {
                "success": False,
                "message": f"Failed to update site: {str(e)}"
            }


async def delete_site(
    name: str,
    auto_reload: bool = False,
    dry_run: bool = False
) -> dict:
    """
    Delete a site configuration.

    Args:
        name: Site name to delete
        auto_reload: Reload NGINX after deletion (default: False)
        dry_run: Preview changes without applying (default: False)

    Returns:
        dict: Operation result with transaction_id
    """
    from config import get_nginx_conf_path
    from core.docker_service import docker_service, DockerServiceError
    from core.transaction_context import transactional_operation
    from core.context_helpers import get_site_delete_suggestions
    from models.transaction import OperationType

    conf_dir = get_nginx_conf_path()
    conf_file = conf_dir / f"{name}.conf"
    disabled_file = conf_dir / f"{name}.conf.disabled"

    target_file = None
    was_enabled = False

    if conf_file.exists():
        target_file = conf_file
        was_enabled = True
    elif disabled_file.exists():
        target_file = disabled_file
        was_enabled = False
    else:
        return {
            "success": False,
            "message": f"Site '{name}' not found",
            "suggestions": ["List available sites: nginx://sites"]
        }

    if dry_run:
        current_content = target_file.read_text()
        lines = current_content.count('\n') + 1
        return {
            "dry_run": True,
            "would_succeed": True,
            "operation": "delete_site",
            "message": f"Would delete site '{name}' ({lines} lines)",
            "file_path": str(target_file),
            "reload_required": was_enabled
        }

    async with transactional_operation(
        operation=OperationType.SITE_DELETE,
        resource_type="site",
        resource_id=name
    ) as ctx:
        try:
            target_file.unlink()
            logger.info(f"Deleted site configuration: {target_file}")

            reloaded = False
            if auto_reload and was_enabled:
                try:
                    await docker_service.reload_nginx()
                    reloaded = True
                except DockerServiceError as e:
                    logger.warning(f"Failed to reload NGINX: {e.message}")

            suggestions = get_site_delete_suggestions(
                site_name=name,
                reloaded=reloaded,
                was_enabled=was_enabled
            )

            return {
                "success": True,
                "message": f"Site '{name}' deleted successfully",
                "site_name": name,
                "transaction_id": ctx.id,
                "reload_required": was_enabled and not reloaded,
                "reloaded": reloaded,
                "suggestions": suggestions
            }

        except Exception as e:
            logger.error(f"Error deleting site: {e}")
            return {
                "success": False,
                "message": f"Failed to delete site: {str(e)}"
            }


async def enable_site(
    name: str,
    auto_reload: bool = True,
    dry_run: bool = False
) -> dict:
    """
    Enable a disabled site.

    Args:
        name: Site name to enable
        auto_reload: Reload NGINX after enabling (default: True)
        dry_run: Preview changes without applying (default: False)

    Returns:
        dict: Operation result with transaction_id
    """
    from config import get_nginx_conf_path, settings
    from core.docker_service import docker_service, DockerServiceError
    from core.transaction_context import transactional_operation
    from core.context_helpers import get_site_enable_suggestions
    from models.transaction import OperationType

    conf_dir = get_nginx_conf_path()
    conf_file = conf_dir / f"{name}.conf"
    disabled_file = conf_dir / f"{name}.conf.disabled"

    if conf_file.exists():
        return {
            "success": False,
            "message": f"Site '{name}' is already enabled",
            "suggestions": [f"View site: nginx://sites/{name}"]
        }

    if not disabled_file.exists():
        return {
            "success": False,
            "message": f"Site '{name}' not found",
            "suggestions": [
                f"Create it: create_site(name='{name}', ...)",
                "List available sites: nginx://sites"
            ]
        }

    if dry_run:
        validation_passed = True
        validation_output = None

        if settings.validate_before_deploy:
            disabled_file.rename(conf_file)
            try:
                success, stdout, stderr = await docker_service.test_config()
                validation_output = stderr or stdout
                validation_passed = success
            finally:
                conf_file.rename(disabled_file)

        return {
            "dry_run": True,
            "would_succeed": validation_passed,
            "operation": "enable_site",
            "message": f"Would enable site '{name}'",
            "validation_passed": validation_passed,
            "validation_output": validation_output,
            "reload_required": True
        }

    async with transactional_operation(
        operation=OperationType.SITE_ENABLE,
        resource_type="site",
        resource_id=name
    ) as ctx:
        try:
            disabled_file.rename(conf_file)
            logger.info(f"Enabled site: {name}")

            if settings.validate_before_deploy:
                success, stdout, stderr = await docker_service.test_config()
                if not success:
                    conf_file.rename(disabled_file)
                    return {
                        "success": False,
                        "message": f"Configuration validation failed: {stderr}",
                        "suggestions": ["Fix configuration errors before enabling"]
                    }

            reloaded = False
            if auto_reload:
                try:
                    await docker_service.reload_nginx()
                    reloaded = True
                except DockerServiceError as e:
                    logger.warning(f"Failed to reload NGINX: {e.message}")

            suggestions = get_site_enable_suggestions(
                site_name=name,
                reloaded=reloaded
            )

            return {
                "success": True,
                "message": f"Site '{name}' enabled successfully",
                "site_name": name,
                "transaction_id": ctx.id,
                "file_path": str(conf_file),
                "reload_required": not reloaded,
                "reloaded": reloaded,
                "enabled": True,
                "suggestions": suggestions
            }

        except Exception as e:
            logger.error(f"Error enabling site: {e}")
            return {
                "success": False,
                "message": f"Failed to enable site: {str(e)}"
            }


async def disable_site(
    name: str,
    auto_reload: bool = True,
    dry_run: bool = False
) -> dict:
    """
    Disable a site without deleting it.

    Args:
        name: Site name to disable
        auto_reload: Reload NGINX after disabling (default: True)
        dry_run: Preview changes without applying (default: False)

    Returns:
        dict: Operation result with transaction_id
    """
    from config import get_nginx_conf_path
    from core.docker_service import docker_service, DockerServiceError
    from core.transaction_context import transactional_operation
    from core.context_helpers import get_site_disable_suggestions
    from models.transaction import OperationType

    conf_dir = get_nginx_conf_path()
    conf_file = conf_dir / f"{name}.conf"
    disabled_file = conf_dir / f"{name}.conf.disabled"

    if disabled_file.exists():
        return {
            "success": False,
            "message": f"Site '{name}' is already disabled",
            "suggestions": [f"Enable it: enable_site(name='{name}')"]
        }

    if not conf_file.exists():
        return {
            "success": False,
            "message": f"Site '{name}' not found",
            "suggestions": ["List available sites: nginx://sites"]
        }

    if dry_run:
        return {
            "dry_run": True,
            "would_succeed": True,
            "operation": "disable_site",
            "message": f"Would disable site '{name}'",
            "reload_required": True
        }

    async with transactional_operation(
        operation=OperationType.SITE_DISABLE,
        resource_type="site",
        resource_id=name
    ) as ctx:
        try:
            conf_file.rename(disabled_file)
            logger.info(f"Disabled site: {name}")

            reloaded = False
            if auto_reload:
                try:
                    await docker_service.reload_nginx()
                    reloaded = True
                except DockerServiceError as e:
                    logger.warning(f"Failed to reload NGINX: {e.message}")

            suggestions = get_site_disable_suggestions(
                site_name=name,
                reloaded=reloaded
            )

            return {
                "success": True,
                "message": f"Site '{name}' disabled successfully",
                "site_name": name,
                "transaction_id": ctx.id,
                "file_path": str(disabled_file),
                "reload_required": not reloaded,
                "reloaded": reloaded,
                "enabled": False,
                "suggestions": suggestions
            }

        except Exception as e:
            logger.error(f"Error disabling site: {e}")
            return {
                "success": False,
                "message": f"Failed to disable site: {str(e)}"
            }


# =============================================================================
# NGINX Control Tools
# =============================================================================

async def nginx_reload(dry_run: bool = False) -> dict:
    """
    Gracefully reload NGINX configuration.

    Args:
        dry_run: Preview what would happen (default: False)

    Returns:
        dict: Operation result with health status
    """
    from datetime import datetime
    from core.docker_service import docker_service, DockerServiceError
    from core.transaction_context import transactional_operation
    from core.health_checker import health_checker, HealthCheckError
    from models.transaction import OperationType

    if dry_run:
        try:
            status = await docker_service.get_container_status()
            success, stdout, stderr = await docker_service.test_config()

            return {
                "dry_run": True,
                "would_succeed": success and status.get("running", False),
                "operation": "nginx_reload",
                "message": "Would gracefully reload NGINX",
                "container_running": status.get("running", False),
                "config_valid": success,
                "config_test_output": stderr or stdout,
                "would_drop_connections": False,
                "warnings": [] if success else ["Configuration has errors"]
            }
        except DockerServiceError as e:
            return {
                "dry_run": True,
                "would_succeed": False,
                "operation": "nginx_reload",
                "message": f"Would fail: {e.message}",
                "warnings": [e.message]
            }

    start_time = datetime.utcnow()

    async with transactional_operation(
        operation=OperationType.NGINX_RELOAD,
        resource_type="nginx",
        resource_id="reload"
    ) as ctx:
        try:
            # Get initial state
            initial_status = await docker_service.get_container_status()

            # Perform reload
            success, stdout, stderr = await docker_service.reload_nginx()

            if not success:
                return {
                    "success": False,
                    "operation": "reload",
                    "message": f"Reload failed: {stderr}",
                    "transaction_id": ctx.id,
                    "suggestions": ["Check configuration: nginx_test()", "View config errors"]
                }

            # Verify health
            health_verified = False
            try:
                await health_checker.verify_health()
                health_verified = True
            except HealthCheckError as e:
                logger.warning(f"Health check failed after reload: {e}")

            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

            return {
                "success": True,
                "operation": "reload",
                "message": "NGINX reloaded successfully",
                "timestamp": datetime.utcnow().isoformat(),
                "duration_ms": duration_ms,
                "health_verified": health_verified,
                "transaction_id": ctx.id,
                "suggestions": ["Check site accessibility", "Monitor logs for errors"]
            }

        except DockerServiceError as e:
            return {
                "success": False,
                "operation": "reload",
                "message": e.message,
                "suggestion": e.suggestion,
                "transaction_id": ctx.id
            }


async def nginx_restart(dry_run: bool = False) -> dict:
    """
    Full NGINX container restart (disruptive).

    Args:
        dry_run: Preview what would happen (default: False)

    Returns:
        dict: Operation result with health status
    """
    from datetime import datetime
    from core.docker_service import docker_service, DockerServiceError
    from core.transaction_context import transactional_operation
    from core.health_checker import health_checker, HealthCheckError
    from models.transaction import OperationType

    if dry_run:
        try:
            status = await docker_service.get_container_status()

            return {
                "dry_run": True,
                "would_succeed": True,
                "operation": "nginx_restart",
                "message": "Would restart NGINX container (disruptive)",
                "container_running": status.get("running", False),
                "would_drop_connections": True,
                "estimated_downtime_ms": 2000,
                "warnings": ["This will drop all active connections"]
            }
        except DockerServiceError as e:
            return {
                "dry_run": True,
                "would_succeed": False,
                "operation": "nginx_restart",
                "message": f"Would fail: {e.message}"
            }

    start_time = datetime.utcnow()

    async with transactional_operation(
        operation=OperationType.NGINX_RESTART,
        resource_type="nginx",
        resource_id="restart"
    ) as ctx:
        try:
            await docker_service.restart_container()

            # Verify health
            health_verified = False
            try:
                await health_checker.verify_health()
                health_verified = True
            except HealthCheckError as e:
                logger.warning(f"Health check failed after restart: {e}")

            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

            return {
                "success": True,
                "operation": "restart",
                "message": "NGINX restarted successfully",
                "timestamp": datetime.utcnow().isoformat(),
                "duration_ms": duration_ms,
                "health_verified": health_verified,
                "transaction_id": ctx.id,
                "suggestions": ["Verify sites are accessible", "Check for connection errors in logs"]
            }

        except DockerServiceError as e:
            return {
                "success": False,
                "operation": "restart",
                "message": e.message,
                "suggestion": e.suggestion,
                "transaction_id": ctx.id
            }


async def nginx_test() -> dict:
    """
    Validate NGINX configuration without applying.

    Returns:
        dict: Validation result with details
    """
    from datetime import datetime
    from core.docker_service import docker_service, DockerServiceError

    try:
        success, stdout, stderr = await docker_service.test_config()

        return {
            "success": success,
            "message": "Configuration is valid" if success else "Configuration has errors",
            "stdout": stdout,
            "stderr": stderr,
            "tested_at": datetime.utcnow().isoformat(),
            "suggestions": [] if success else ["Review the error messages", "Check syntax in affected files"]
        }

    except DockerServiceError as e:
        return {
            "success": False,
            "message": e.message,
            "suggestion": e.suggestion
        }


# =============================================================================
# Certificate Management Tools
# =============================================================================

async def request_certificate(
    domain: str,
    alt_names: Optional[List[str]] = None,
    auto_renew: bool = True,
    auto_reload: bool = True,
    dry_run: bool = False
) -> dict:
    """
    Request a Let's Encrypt SSL certificate.

    Args:
        domain: Primary domain for the certificate
        alt_names: Additional domain names (SANs)
        auto_renew: Enable automatic renewal (default: True)
        auto_reload: Reload NGINX after installation (default: True)
        dry_run: Check prerequisites without requesting (default: False)

    Returns:
        dict: Operation result with certificate details
    """
    from core.cert_manager import get_cert_manager, CertificateError

    try:
        cert_manager = get_cert_manager()

        if dry_run:
            result = await cert_manager.request_certificate(
                domain=domain,
                alt_names=alt_names or [],
                auto_renew=auto_renew,
                dry_run=True
            )
            return {
                "dry_run": True,
                "would_succeed": result.would_succeed,
                "operation": "request_certificate",
                "message": result.message,
                "domain": domain,
                "domain_resolves": result.domain_resolves,
                "domain_points_to_server": result.domain_points_to_server,
                "port_80_accessible": result.port_80_accessible,
                "warnings": result.warnings,
                "suggestions": result.suggestions if hasattr(result, 'suggestions') else []
            }

        result = await cert_manager.request_certificate(
            domain=domain,
            alt_names=alt_names or [],
            auto_renew=auto_renew,
            dry_run=False
        )

        cert_data = None
        if result.certificate:
            cert_data = {
                "domain": result.certificate.domain,
                "status": result.certificate.status.value if result.certificate.status else None,
                "not_after": result.certificate.not_after.isoformat() if result.certificate.not_after else None,
                "days_until_expiry": result.certificate.days_until_expiry
            }

        return {
            "success": result.success,
            "message": result.message,
            "domain": result.domain,
            "transaction_id": result.transaction_id,
            "certificate": cert_data,
            "reload_required": result.reload_required,
            "reloaded": result.reloaded,
            "suggestions": result.suggestions,
            "warnings": result.warnings
        }

    except CertificateError as e:
        return {
            "success": False,
            "message": e.message,
            "domain": e.domain,
            "suggestion": e.suggestion
        }
    except Exception as e:
        logger.error(f"Error requesting certificate: {e}")
        return {
            "success": False,
            "message": f"Failed to request certificate: {str(e)}",
            "domain": domain
        }


async def upload_certificate(
    domain: str,
    certificate_pem: str,
    private_key_pem: str,
    chain_pem: Optional[str] = None,
    auto_reload: bool = True,
    dry_run: bool = False
) -> dict:
    """
    Upload a custom SSL certificate.

    Args:
        domain: Domain for the certificate
        certificate_pem: Certificate in PEM format
        private_key_pem: Private key in PEM format
        chain_pem: Optional certificate chain in PEM format
        auto_reload: Reload NGINX after installation (default: True)
        dry_run: Validate without uploading (default: False)

    Returns:
        dict: Operation result with certificate details
    """
    from core.cert_manager import get_cert_manager, CertificateError

    try:
        cert_manager = get_cert_manager()

        result = await cert_manager.upload_custom_certificate(
            domain=domain,
            cert_pem=certificate_pem,
            key_pem=private_key_pem,
            chain_pem=chain_pem,
            dry_run=dry_run
        )

        if dry_run:
            return {
                "dry_run": True,
                "would_succeed": result.would_succeed,
                "operation": "upload_certificate",
                "message": result.message,
                "domain": domain,
                "warnings": result.warnings if hasattr(result, 'warnings') else []
            }

        cert_data = None
        if result.certificate:
            cert_data = {
                "domain": result.certificate.domain,
                "status": result.certificate.status.value if result.certificate.status else None,
                "not_after": result.certificate.not_after.isoformat() if result.certificate.not_after else None,
                "days_until_expiry": result.certificate.days_until_expiry
            }

        return {
            "success": result.success,
            "message": result.message,
            "domain": result.domain,
            "transaction_id": result.transaction_id,
            "certificate": cert_data,
            "suggestions": result.suggestions,
            "warnings": result.warnings
        }

    except CertificateError as e:
        return {
            "success": False,
            "message": e.message,
            "domain": e.domain,
            "suggestion": e.suggestion
        }
    except Exception as e:
        logger.error(f"Error uploading certificate: {e}")
        return {
            "success": False,
            "message": f"Failed to upload certificate: {str(e)}",
            "domain": domain
        }


async def renew_certificate(
    domain: str,
    force: bool = False,
    auto_reload: bool = True,
    dry_run: bool = False
) -> dict:
    """
    Manually trigger certificate renewal.

    Args:
        domain: Domain to renew
        force: Force renewal even if not expiring soon (default: False)
        auto_reload: Reload NGINX after renewal (default: True)
        dry_run: Check renewal status without renewing (default: False)

    Returns:
        dict: Operation result with certificate details
    """
    from core.cert_manager import get_cert_manager, CertificateError

    try:
        cert_manager = get_cert_manager()

        result = await cert_manager.renew_certificate(
            domain=domain,
            force=force,
            dry_run=dry_run
        )

        if dry_run:
            return {
                "dry_run": True,
                "would_succeed": result.would_succeed,
                "operation": "renew_certificate",
                "message": result.message,
                "domain": domain,
                "warnings": result.warnings if hasattr(result, 'warnings') else []
            }

        cert_data = None
        if result.certificate:
            cert_data = {
                "domain": result.certificate.domain,
                "status": result.certificate.status.value if result.certificate.status else None,
                "not_after": result.certificate.not_after.isoformat() if result.certificate.not_after else None,
                "days_until_expiry": result.certificate.days_until_expiry
            }

        return {
            "success": result.success,
            "message": result.message,
            "domain": result.domain,
            "transaction_id": result.transaction_id,
            "certificate": cert_data,
            "suggestions": result.suggestions,
            "warnings": result.warnings
        }

    except CertificateError as e:
        return {
            "success": False,
            "message": e.message,
            "domain": e.domain,
            "suggestion": e.suggestion
        }
    except Exception as e:
        logger.error(f"Error renewing certificate: {e}")
        return {
            "success": False,
            "message": f"Failed to renew certificate: {str(e)}",
            "domain": domain
        }


async def revoke_certificate(
    domain: str,
    auto_reload: bool = True,
    dry_run: bool = False
) -> dict:
    """
    Revoke and remove a certificate.

    Args:
        domain: Domain to revoke certificate for
        auto_reload: Reload NGINX after revocation (default: True)
        dry_run: Preview revocation without executing (default: False)

    Returns:
        dict: Operation result
    """
    from core.cert_manager import get_cert_manager, CertificateError

    try:
        cert_manager = get_cert_manager()

        result = await cert_manager.revoke_certificate(
            domain=domain,
            dry_run=dry_run
        )

        if dry_run:
            return {
                "dry_run": True,
                "would_succeed": result.would_succeed,
                "operation": "revoke_certificate",
                "message": result.message,
                "domain": domain,
                "warnings": result.warnings if hasattr(result, 'warnings') else []
            }

        return {
            "success": result.success,
            "message": result.message,
            "domain": result.domain,
            "transaction_id": result.transaction_id,
            "suggestions": result.suggestions,
            "warnings": result.warnings
        }

    except CertificateError as e:
        return {
            "success": False,
            "message": e.message,
            "domain": e.domain,
            "suggestion": e.suggestion
        }
    except Exception as e:
        logger.error(f"Error revoking certificate: {e}")
        return {
            "success": False,
            "message": f"Failed to revoke certificate: {str(e)}",
            "domain": domain
        }


async def diagnose_ssl(domain: str) -> dict:
    """
    Run comprehensive SSL diagnostic.

    Args:
        domain: Domain to diagnose

    Returns:
        dict: Diagnostic results with issues and suggestions
    """
    from core.cert_manager import get_cert_manager

    try:
        cert_manager = get_cert_manager()
        result = await cert_manager.diagnose_ssl(domain)

        return {
            "domain": result.domain,
            "dns_resolves": result.dns_resolves,
            "dns_ip_addresses": result.dns_ip_addresses,
            "points_to_this_server": result.points_to_this_server,
            "port_80_open": result.port_80_open,
            "port_443_open": result.port_443_open,
            "has_certificate": result.has_certificate,
            "certificate_valid": result.certificate_valid,
            "certificate_expiry": result.certificate_expiry.isoformat() if result.certificate_expiry else None,
            "certificate_issuer": result.certificate_issuer,
            "chain_valid": result.chain_valid,
            "chain_issues": result.chain_issues,
            "ready_for_ssl": result.ready_for_ssl,
            "issues": result.issues,
            "suggestions": result.suggestions
        }

    except Exception as e:
        logger.error(f"Error diagnosing SSL for {domain}: {e}")
        return {
            "domain": domain,
            "ready_for_ssl": False,
            "issues": [f"Diagnostic failed: {str(e)}"],
            "suggestions": ["Check DNS configuration", "Verify domain spelling"]
        }


# =============================================================================
# Transaction Management Tools
# =============================================================================

async def rollback_transaction(
    transaction_id: str,
    reason: Optional[str] = None
) -> dict:
    """
    Rollback a transaction to restore previous state.

    Args:
        transaction_id: Transaction ID to rollback
        reason: Reason for rollback (optional)

    Returns:
        dict: Rollback result
    """
    from core.transaction_manager import get_transaction_manager

    try:
        txn_manager = get_transaction_manager()

        # Check if rollback is possible
        can_rollback, rollback_reason = await txn_manager.can_rollback(transaction_id)
        if not can_rollback:
            return {
                "success": False,
                "message": f"Cannot rollback transaction: {rollback_reason}",
                "original_transaction_id": transaction_id,
                "suggestions": ["View transaction details: nginx://transactions/" + transaction_id]
            }

        result = await txn_manager.rollback_transaction(
            transaction_id=transaction_id,
            reason=reason
        )

        return {
            "success": result.success,
            "rollback_transaction_id": result.rollback_transaction_id,
            "original_transaction_id": result.original_transaction_id,
            "message": result.message,
            "warnings": result.warnings
        }

    except Exception as e:
        logger.error(f"Error rolling back transaction {transaction_id}: {e}")
        return {
            "success": False,
            "message": f"Failed to rollback: {str(e)}",
            "original_transaction_id": transaction_id
        }
