"""
Site configuration endpoints.

REST API endpoints for managing NGINX server block configurations.
Supports full CRUD operations with transaction support for rollback.
"""

import logging
import shutil
import tempfile
from pathlib import Path
from typing import Union

from fastapi import APIRouter, Depends, HTTPException, Query

from config import get_nginx_conf_path, settings
from core.auth_dependency import require_role
from core.config_generator import ConfigGeneratorError, get_config_generator
from core.config_manager import ConfigAdapter, nginx_parser
from core.context_helpers import (
    get_config_warnings,
    get_site_create_suggestions,
    get_site_delete_suggestions,
    get_site_disable_suggestions,
    get_site_enable_suggestions,
    get_site_update_suggestions,
)
from core.docker_service import DockerServiceError, docker_service
from core.transaction_context import transactional_operation
from models.auth import AuthContext, Role
from models.config import SiteConfigResponse
from models.site_requests import (
    DryRunDiff,
    DryRunResult,
    SiteCreateRequest,
    SiteDeleteResponse,
    SiteEnableDisableRequest,
    SiteMutationResponse,
    SiteType,
    SiteUpdateRequest,
    ValidationWarning,
)
from models.transaction import OperationType

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sites", tags=["Site Configuration"])


@router.get(
    "/",
    response_model=list[SiteConfigResponse],
    summary="List All Site Configurations",
    description="""
    Retrieve all NGINX server block configurations from the conf.d directory.

    This endpoint scans the NGINX configuration directory and parses each .conf file
    to extract key information about server blocks. Perfect for AI agents to get
    an overview of all configured sites.

    **What gets parsed:**
    - Server names (domains)
    - Listen ports
    - SSL status
    - Root paths or proxy destinations
    - File metadata (size, timestamps)

    **Safe Operation**: This is a read-only operation that doesn't modify any configurations.
    """,
    responses={
        200: {
            "description": "List of site configurations successfully retrieved",
            "content": {
                "application/json": {
                    "example": [
                        {
                            "name": "example.com",
                            "server_name": "example.com www.example.com",
                            "listen_port": 80,
                            "ssl_enabled": True,
                            "root_path": "/var/www/example",
                            "proxy_pass": None,
                            "status": "valid",
                            "file_path": "/etc/nginx/conf.d/example.com.conf",
                            "file_size": 1024,
                            "created_at": "2024-01-15T10:30:00",
                            "updated_at": "2024-01-20T14:45:00",
                        }
                    ]
                }
            },
        },
        404: {"description": "NGINX configuration directory not found"},
        500: {"description": "Internal server error during configuration parsing"},
    },
)
async def list_sites(
    auth: AuthContext = Depends(require_role(Role.VIEWER)),
) -> list[SiteConfigResponse]:
    """
    List all NGINX site configurations.

    Scans the NGINX conf.d directory and parses all .conf files to extract
    server block information. Returns detailed metadata about each configured site.

    Returns:
        List[SiteConfigResponse]: List of parsed site configurations

    Raises:
        HTTPException: If conf.d directory is not accessible or parsing fails
    """
    try:
        conf_dir = get_nginx_conf_path()

        # Check if configuration directory exists
        if not conf_dir.exists():
            logger.warning(f"NGINX conf directory not found: {conf_dir}")
            raise HTTPException(status_code=404, detail=f"NGINX configuration directory not found: {conf_dir}")

        # Find all .conf and .conf.disabled files
        conf_files = list(conf_dir.glob("*.conf"))
        disabled_files = list(conf_dir.glob("*.conf.disabled"))
        all_files = conf_files + disabled_files

        if not all_files:
            logger.info(f"No .conf files found in {conf_dir}")
            return []

        sites = []
        for conf_file in all_files:
            try:
                parsed_config = nginx_parser.parse_config_file(conf_file)
                if parsed_config:
                    # Convert to response model via adapter
                    rich_dict = ConfigAdapter.to_rich_dict(parsed_config)
                    site_response = SiteConfigResponse(**rich_dict)
                    sites.append(site_response)
                else:
                    logger.warning(f"Failed to parse config file: {conf_file}")

            except Exception as e:
                logger.error(f"Error processing {conf_file}: {e}")
                # Continue processing other files instead of failing completely
                continue

        # Enrich with certificate data
        try:
            from core.cert_helpers import get_certificate_map, match_certificate

            cert_map = await get_certificate_map()
            for site in sites:
                if site.server_names:
                    site.certificate = match_certificate(site.server_names, cert_map)
        except Exception as e:
            logger.warning(f"Failed to load certificate data for sites: {e}")

        logger.info(f"Successfully parsed {len(sites)} site configurations")
        return sites

    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Unexpected error listing sites: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error while listing sites: {e!s}")


@router.get(
    "/{site_name}",
    response_model=SiteConfigResponse,
    summary="Get Specific Site Configuration",
    description="""
    Retrieve detailed configuration for a specific NGINX site by name.

    This endpoint fetches and parses a single NGINX configuration file,
    providing detailed information about the server block configuration.
    Perfect for AI agents that need to examine or modify specific sites.

    **Parameters:**
    - `site_name`: The name of the site configuration (filename without .conf extension)

    **What you get:**
    - Complete server block details
    - SSL configuration status
    - Proxy or static file serving setup
    - File metadata and timestamps
    - Configuration validation status

    **Use Cases:**
    - Before modifying a site configuration
    - Checking SSL certificate status
    - Verifying proxy backend settings
    - Troubleshooting site issues
    """,
    responses={
        200: {
            "description": "Site configuration retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "name": "api.example.com",
                        "server_name": "api.example.com",
                        "listen_ports": [80, 443],
                        "ssl_enabled": True,
                        "root_path": None,
                        "proxy_pass": "http://localhost:3000",
                        "has_ssl_cert": True,
                        "status": "untested",
                        "file_path": "/etc/nginx/conf.d/api.example.com.conf",
                        "file_size": 856,
                        "created_at": "2024-01-15T10:30:00",
                        "updated_at": "2024-01-20T14:45:00",
                        "last_validated": None,
                    }
                }
            },
        },
        404: {"description": "Site configuration not found"},
        500: {"description": "Error parsing configuration file"},
    },
)
async def get_site(
    site_name: str,
    auth: AuthContext = Depends(require_role(Role.VIEWER)),
) -> SiteConfigResponse:
    """
    Get detailed configuration for a specific site.

    Args:
        site_name: Name of the site (without .conf extension)

    Returns:
        SiteConfigResponse: Detailed site configuration

    Raises:
        HTTPException: If site not found or parsing fails
    """
    try:
        conf_dir = get_nginx_conf_path()
        conf_file = conf_dir / f"{site_name}.conf"

        # Check if the specific config file exists
        if not conf_file.exists():
            logger.warning(f"Site configuration not found: {conf_file}")
            raise HTTPException(status_code=404, detail=f"Site configuration '{site_name}' not found")

        # Parse the configuration file
        parsed_config = nginx_parser.parse_config_file(conf_file)

        if not parsed_config:
            logger.error(f"Failed to parse configuration file: {conf_file}")
            raise HTTPException(status_code=500, detail=f"Failed to parse configuration file for site '{site_name}'")

        # Convert to response model via adapter
        rich_dict = ConfigAdapter.to_rich_dict(parsed_config)
        site_response = SiteConfigResponse(**rich_dict)

        # Enrich with certificate data
        try:
            from core.cert_helpers import get_certificate_map, match_certificate

            cert_map = await get_certificate_map()
            if site_response.server_names:
                site_response.certificate = match_certificate(site_response.server_names, cert_map)
        except Exception as e:
            logger.warning(f"Failed to load certificate data for site {site_name}: {e}")

        logger.info(f"Successfully retrieved configuration for site: {site_name}")
        return site_response

    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Unexpected error getting site {site_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error while retrieving site '{site_name}': {e!s}")


@router.post(
    "/",
    response_model=Union[SiteMutationResponse, DryRunResult],
    status_code=201,
    summary="Create New Site Configuration",
    description="""
    Create a new NGINX site configuration.

    This endpoint generates a valid NGINX server block configuration based on
    the provided parameters and writes it to the conf.d directory.

    **Site Types:**
    - `static`: Serves static files from a root directory
    - `reverse_proxy`: Proxies requests to a backend server

    **Dry Run Mode:**
    Add `?dry_run=true` to preview the operation without making changes.
    Returns the generated config, validation result, and what would change.

    **Transaction Support:**
    All changes are wrapped in a transaction for potential rollback.
    A snapshot is automatically created before writing the new configuration.

    **Auto-reload:**
    Set `auto_reload: true` to automatically reload NGINX after creation.
    Default is `false` to allow batching multiple changes.
    """,
    responses={
        200: {"description": "Dry run result (when dry_run=true)"},
        201: {"description": "Site created successfully"},
        400: {"description": "Invalid configuration or validation failed"},
        409: {"description": "Site with this name already exists"},
        500: {"description": "Internal server error during creation"},
    },
)
async def create_site(
    request: SiteCreateRequest,
    dry_run: bool = Query(default=False, description="Preview the operation without making changes"),
    auth: AuthContext = Depends(require_role(Role.OPERATOR)),
) -> SiteMutationResponse | DryRunResult:
    """
    Create a new NGINX site configuration.

    Args:
        request: Site creation request with configuration details
        dry_run: If True, preview the operation without making changes

    Returns:
        SiteMutationResponse or DryRunResult depending on dry_run flag

    Raises:
        HTTPException: If creation fails for any reason
    """
    conf_dir = get_nginx_conf_path()
    conf_file = conf_dir / f"{request.name}.conf"

    # Check if site already exists
    if conf_file.exists():
        if dry_run:
            return DryRunResult(
                would_succeed=False,
                operation="create",
                message=f"Site '{request.name}' already exists",
                validation_passed=False,
                affected_sites=[request.name],
            )
        raise HTTPException(status_code=409, detail=f"Site '{request.name}' already exists")

    # Also check for disabled version
    disabled_file = conf_dir / f"{request.name}.conf.disabled"
    if disabled_file.exists():
        if dry_run:
            return DryRunResult(
                would_succeed=False,
                operation="create",
                message=f"Site '{request.name}' exists but is disabled. Enable it or delete it first.",
                validation_passed=False,
                affected_sites=[request.name],
            )
        raise HTTPException(
            status_code=409, detail=f"Site '{request.name}' exists but is disabled. Enable it or delete it first."
        )

    # Generate configuration
    try:
        generator = get_config_generator()
        config_content = generator.generate(request)
    except ConfigGeneratorError as e:
        if dry_run:
            return DryRunResult(
                would_succeed=False,
                operation="create",
                message=f"Failed to generate configuration: {e.message}",
                validation_passed=False,
                affected_sites=[request.name],
            )
        raise HTTPException(status_code=400, detail=f"Failed to generate configuration: {e.message}")

    # Validate configuration
    validation_passed = True
    validation_output = None
    warnings: list[ValidationWarning] = []

    if settings.validate_before_deploy:
        # Write to temp file and validate
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as tmp_file:
            tmp_file.write(config_content)
            tmp_path = Path(tmp_file.name)

        try:
            # Copy to conf.d temporarily for validation
            shutil.copy(tmp_path, conf_file)
            success, stdout, stderr = await docker_service.test_config()
            validation_output = stderr or stdout
            if not success:
                validation_passed = False
                # Remove temporary config
                conf_file.unlink(missing_ok=True)
        finally:
            tmp_path.unlink(missing_ok=True)
            if dry_run:
                # Clean up the temp config we created for validation
                conf_file.unlink(missing_ok=True)

    # Generate warnings
    if request.site_type == SiteType.STATIC and not request.root_path:
        warnings.append(
            ValidationWarning(
                code="missing_root",
                message="Static site without root_path specified",
                suggestion="Set root_path to the document root directory",
            )
        )

    # If dry_run, return preview result
    if dry_run:
        lines = config_content.count("\n") + 1
        return DryRunResult(
            would_succeed=validation_passed,
            operation="create",
            message=f"Would create site '{request.name}' with {lines} lines of configuration",
            validation_passed=validation_passed,
            validation_output=validation_output,
            warnings=warnings,
            diff=DryRunDiff(
                operation="create",
                file_path=str(conf_file),
                current_content=None,
                new_content=config_content,
                lines_added=lines,
                lines_removed=0,
            ),
            affected_sites=[request.name],
            reload_required=True,
            generated_config=config_content,
        )

    # Actual creation (not dry run)
    if not validation_passed:
        raise HTTPException(status_code=400, detail=f"Configuration validation failed: {validation_output}")

    async with transactional_operation(
        operation=OperationType.SITE_CREATE, resource_type="site", resource_id=request.name
    ) as ctx:
        try:
            # Write the config (already validated above)
            conf_file.write_text(config_content)
            logger.info(f"Created site configuration: {conf_file}")

            # Optionally reload NGINX
            reloaded = False
            if request.auto_reload:
                try:
                    await docker_service.reload_nginx()
                    reloaded = True
                    logger.info(f"NGINX reloaded after creating site: {request.name}")
                except DockerServiceError as e:
                    logger.warning(f"Failed to reload NGINX: {e.message}")

            # Generate suggestions and warnings
            suggestions = get_site_create_suggestions(
                site_name=request.name, site_type=request.site_type.value, reloaded=reloaded, enabled=True
            )
            config_warnings = get_config_warnings(
                ssl_enabled=False,
                has_ssl_cert=False,
                listen_ports=[request.listen_port],
                proxy_pass=request.proxy_pass,
                root_path=request.root_path,
            )

            return SiteMutationResponse(
                success=True,
                message=f"Site '{request.name}' created successfully",
                site_name=request.name,
                transaction_id=ctx.id,
                file_path=str(conf_file),
                reload_required=not reloaded,
                reloaded=reloaded,
                enabled=True,
                suggestions=suggestions,
                warnings=config_warnings,
            )

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Unexpected error creating site: {e}")
            raise HTTPException(status_code=500, detail=f"Internal server error while creating site: {e!s}")


@router.put(
    "/{site_name}",
    response_model=Union[SiteMutationResponse, DryRunResult],
    summary="Update Site Configuration",
    description="""
    Update an existing NGINX site configuration.

    This endpoint modifies the configuration for an existing site.
    Only provided fields will be updated; others remain unchanged.

    **Dry Run Mode:**
    Add `?dry_run=true` to preview the changes without applying them.

    **Transaction Support:**
    A snapshot of the current configuration is created before modification.
    If the update fails validation, the original configuration is restored.

    **Auto-reload:**
    Set `auto_reload: true` to automatically reload NGINX after update.
    """,
    responses={
        200: {"description": "Site updated successfully (or dry run result)"},
        400: {"description": "Invalid configuration or validation failed"},
        404: {"description": "Site not found"},
        500: {"description": "Internal server error during update"},
    },
)
async def update_site(
    site_name: str,
    request: SiteUpdateRequest,
    dry_run: bool = Query(default=False, description="Preview the operation without making changes"),
    auth: AuthContext = Depends(require_role(Role.OPERATOR)),
) -> SiteMutationResponse | DryRunResult:
    """
    Update an existing site configuration.

    Args:
        site_name: Name of the site to update
        request: Update request with new configuration values
        dry_run: If True, preview the operation without making changes

    Returns:
        SiteMutationResponse or DryRunResult depending on dry_run flag
    """
    conf_dir = get_nginx_conf_path()
    conf_file = conf_dir / f"{site_name}.conf"

    # Check if site exists
    if not conf_file.exists():
        disabled_file = conf_dir / f"{site_name}.conf.disabled"
        if disabled_file.exists():
            if dry_run:
                return DryRunResult(
                    would_succeed=False,
                    operation="update",
                    message=f"Site '{site_name}' is disabled. Enable it before updating.",
                    validation_passed=False,
                    affected_sites=[site_name],
                )
            raise HTTPException(status_code=400, detail=f"Site '{site_name}' is disabled. Enable it before updating.")
        if dry_run:
            return DryRunResult(
                would_succeed=False,
                operation="update",
                message=f"Site '{site_name}' not found",
                validation_passed=False,
                affected_sites=[site_name],
            )
        raise HTTPException(status_code=404, detail=f"Site '{site_name}' not found")

    # Parse existing configuration to get current values
    parsed_config = nginx_parser.parse_config_file(conf_file)
    if not parsed_config:
        if dry_run:
            return DryRunResult(
                would_succeed=False,
                operation="update",
                message=f"Failed to parse existing configuration for '{site_name}'",
                validation_passed=False,
                affected_sites=[site_name],
            )
        raise HTTPException(status_code=500, detail=f"Failed to parse existing configuration for '{site_name}'")

    # Get current content for diff
    current_content = conf_file.read_text()

    # Use adapter to get flattened values
    existing = ConfigAdapter.to_rich_dict(parsed_config)

    # Determine site type from existing config
    if existing.get("proxy_pass"):
        site_type = SiteType.REVERSE_PROXY
    else:
        site_type = SiteType.STATIC

    # Merge existing with updates
    server_names = request.server_names or existing.get("server_names") or [site_name]
    listen_port = request.listen_port or (existing.get("listen_ports", [80])[0] if existing.get("listen_ports") else 80)

    # Create a new config request with merged values
    create_request = SiteCreateRequest(
        name=site_name,
        server_names=server_names,
        site_type=site_type,
        listen_port=listen_port,
        root_path=request.root_path or existing.get("root_path"),
        proxy_pass=request.proxy_pass or existing.get("proxy_pass"),
        auto_reload=request.auto_reload,
    )

    # Generate new configuration
    generator = get_config_generator()
    config_content = generator.generate(create_request)

    # Validate configuration
    validation_passed = True
    validation_output = None

    if settings.validate_before_deploy:
        # Backup and write for validation
        backup_path = conf_file.with_suffix(".conf.bak")
        shutil.copy(conf_file, backup_path)
        try:
            conf_file.write_text(config_content)
            success, stdout, stderr = await docker_service.test_config()
            validation_output = stderr or stdout
            if not success:
                validation_passed = False
            # Restore original for now
            shutil.copy(backup_path, conf_file)
        finally:
            backup_path.unlink(missing_ok=True)

    # Calculate diff
    current_lines = current_content.count("\n") + 1
    new_lines = config_content.count("\n") + 1

    # If dry_run, return preview result
    if dry_run:
        return DryRunResult(
            would_succeed=validation_passed,
            operation="update",
            message=f"Would update site '{site_name}'",
            validation_passed=validation_passed,
            validation_output=validation_output,
            warnings=[],
            diff=DryRunDiff(
                operation="update",
                file_path=str(conf_file),
                current_content=current_content,
                new_content=config_content,
                lines_added=max(0, new_lines - current_lines),
                lines_removed=max(0, current_lines - new_lines),
            ),
            affected_sites=[site_name],
            reload_required=True,
            generated_config=config_content,
        )

    # Actual update
    if not validation_passed:
        raise HTTPException(status_code=400, detail=f"Configuration validation failed: {validation_output}")

    async with transactional_operation(
        operation=OperationType.SITE_UPDATE, resource_type="site", resource_id=site_name
    ) as ctx:
        try:
            # Write the new config
            conf_file.write_text(config_content)
            logger.info(f"Updated site configuration: {conf_file}")

            # Optionally reload NGINX
            reloaded = False
            if request.auto_reload:
                try:
                    await docker_service.reload_nginx()
                    reloaded = True
                except DockerServiceError as e:
                    logger.warning(f"Failed to reload NGINX: {e.message}")

            # Generate suggestions and warnings
            suggestions = get_site_update_suggestions(
                site_name=site_name,
                reloaded=reloaded,
                changes_made=[],  # Could track specific changes
            )
            config_warnings = get_config_warnings(
                ssl_enabled=False,
                has_ssl_cert=False,
                listen_ports=[create_request.listen_port],
                proxy_pass=create_request.proxy_pass,
                root_path=create_request.root_path,
            )

            return SiteMutationResponse(
                success=True,
                message=f"Site '{site_name}' updated successfully",
                site_name=site_name,
                transaction_id=ctx.id,
                file_path=str(conf_file),
                reload_required=not reloaded,
                reloaded=reloaded,
                enabled=True,
                suggestions=suggestions,
                warnings=config_warnings,
            )

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Unexpected error updating site: {e}")
            raise HTTPException(status_code=500, detail=f"Internal server error while updating site: {e!s}")


@router.delete(
    "/{site_name}",
    response_model=Union[SiteDeleteResponse, DryRunResult],
    summary="Delete Site Configuration",
    description="""
    Delete an NGINX site configuration.

    This endpoint removes the site configuration file from the conf.d directory.
    The deletion is wrapped in a transaction and a snapshot is created for rollback.

    **Dry Run Mode:**
    Add `?dry_run=true` to preview the deletion without making changes.

    **Warning:** This operation removes the configuration file permanently.
    Use disable instead if you want to keep the configuration for later.

    **Auto-reload:**
    Set `auto_reload: true` to automatically reload NGINX after deletion.
    """,
    responses={
        200: {"description": "Site deleted successfully (or dry run result)"},
        404: {"description": "Site not found"},
        500: {"description": "Internal server error during deletion"},
    },
)
async def delete_site(
    site_name: str,
    auto_reload: bool = Query(default=False, description="Reload NGINX after deletion"),
    dry_run: bool = Query(default=False, description="Preview the operation without making changes"),
    auth: AuthContext = Depends(require_role(Role.OPERATOR)),
) -> SiteDeleteResponse | DryRunResult:
    """
    Delete a site configuration.

    Args:
        site_name: Name of the site to delete
        auto_reload: Whether to reload NGINX after deletion
        dry_run: If True, preview the operation without making changes

    Returns:
        SiteDeleteResponse or DryRunResult depending on dry_run flag
    """
    conf_dir = get_nginx_conf_path()
    conf_file = conf_dir / f"{site_name}.conf"
    disabled_file = conf_dir / f"{site_name}.conf.disabled"

    # Check if site exists (enabled or disabled)
    target_file = None
    was_enabled = False

    if conf_file.exists():
        target_file = conf_file
        was_enabled = True
    elif disabled_file.exists():
        target_file = disabled_file
        was_enabled = False
    else:
        if dry_run:
            return DryRunResult(
                would_succeed=False,
                operation="delete",
                message=f"Site '{site_name}' not found",
                validation_passed=False,
                affected_sites=[site_name],
            )
        raise HTTPException(status_code=404, detail=f"Site '{site_name}' not found")

    # If dry_run, return preview result
    if dry_run:
        current_content = target_file.read_text()
        lines = current_content.count("\n") + 1
        return DryRunResult(
            would_succeed=True,
            operation="delete",
            message=f"Would delete site '{site_name}' ({lines} lines of configuration)",
            validation_passed=True,
            warnings=[],
            diff=DryRunDiff(
                operation="delete",
                file_path=str(target_file),
                current_content=current_content,
                new_content=None,
                lines_added=0,
                lines_removed=lines,
            ),
            affected_sites=[site_name],
            reload_required=was_enabled,
        )

    async with transactional_operation(
        operation=OperationType.SITE_DELETE, resource_type="site", resource_id=site_name
    ) as ctx:
        try:
            # Remove the file
            target_file.unlink()
            logger.info(f"Deleted site configuration: {target_file}")

            # Optionally reload NGINX (only needed if was enabled)
            reloaded = False
            if auto_reload and was_enabled:
                try:
                    await docker_service.reload_nginx()
                    reloaded = True
                except DockerServiceError as e:
                    logger.warning(f"Failed to reload NGINX: {e.message}")

            # Generate suggestions
            suggestions = get_site_delete_suggestions(site_name=site_name, reloaded=reloaded, was_enabled=was_enabled)

            return SiteDeleteResponse(
                success=True,
                message=f"Site '{site_name}' deleted successfully",
                site_name=site_name,
                transaction_id=ctx.id,
                file_path=str(target_file),
                reload_required=was_enabled and not reloaded,
                reloaded=reloaded,
                suggestions=suggestions,
            )

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Unexpected error deleting site: {e}")
            raise HTTPException(status_code=500, detail=f"Internal server error while deleting site: {e!s}")


@router.post(
    "/{site_name}/enable",
    response_model=Union[SiteMutationResponse, DryRunResult],
    summary="Enable Site",
    description="""
    Enable a disabled site configuration.

    This endpoint renames a `.conf.disabled` file back to `.conf`,
    making the site active in NGINX.

    **Dry Run Mode:**
    Add `?dry_run=true` to preview the operation without making changes.

    **Auto-reload:**
    Set `auto_reload: true` to automatically reload NGINX after enabling.
    """,
    responses={
        200: {"description": "Site enabled successfully (or dry run result)"},
        400: {"description": "Site is already enabled"},
        404: {"description": "Site not found"},
        500: {"description": "Internal server error"},
    },
)
async def enable_site(
    site_name: str,
    request: SiteEnableDisableRequest = None,
    dry_run: bool = Query(default=False, description="Preview the operation without making changes"),
    auth: AuthContext = Depends(require_role(Role.OPERATOR)),
) -> SiteMutationResponse | DryRunResult:
    """
    Enable a disabled site.

    Args:
        site_name: Name of the site to enable
        request: Optional request body with auto_reload setting
        dry_run: If True, preview the operation without making changes

    Returns:
        SiteMutationResponse or DryRunResult depending on dry_run flag
    """
    auto_reload = request.auto_reload if request else False

    conf_dir = get_nginx_conf_path()
    conf_file = conf_dir / f"{site_name}.conf"
    disabled_file = conf_dir / f"{site_name}.conf.disabled"

    # Check current state
    if conf_file.exists():
        if dry_run:
            return DryRunResult(
                would_succeed=False,
                operation="enable",
                message=f"Site '{site_name}' is already enabled",
                validation_passed=False,
                affected_sites=[site_name],
            )
        raise HTTPException(status_code=400, detail=f"Site '{site_name}' is already enabled")

    if not disabled_file.exists():
        if dry_run:
            return DryRunResult(
                would_succeed=False,
                operation="enable",
                message=f"Site '{site_name}' not found",
                validation_passed=False,
                affected_sites=[site_name],
            )
        raise HTTPException(status_code=404, detail=f"Site '{site_name}' not found")

    # If dry_run, validate config and return preview result
    if dry_run:
        current_content = disabled_file.read_text()
        validation_passed = True
        validation_output = None

        if settings.validate_before_deploy:
            # Temporarily enable for validation
            disabled_file.rename(conf_file)
            try:
                success, stdout, stderr = await docker_service.test_config()
                validation_output = stderr or stdout
                validation_passed = success
            finally:
                # Restore disabled state
                conf_file.rename(disabled_file)

        return DryRunResult(
            would_succeed=validation_passed,
            operation="enable",
            message=f"Would enable site '{site_name}'",
            validation_passed=validation_passed,
            validation_output=validation_output,
            warnings=[],
            diff=DryRunDiff(
                operation="enable",
                file_path=str(conf_file),
                current_content=None,
                new_content=current_content,
                lines_added=0,
                lines_removed=0,
            ),
            affected_sites=[site_name],
            reload_required=True,
            generated_config=current_content,
        )

    async with transactional_operation(
        operation=OperationType.SITE_UPDATE, resource_type="site", resource_id=site_name
    ) as ctx:
        try:
            # Rename disabled file to enabled
            disabled_file.rename(conf_file)
            logger.info(f"Enabled site: {site_name}")

            # Validate configuration
            if settings.validate_before_deploy:
                success, stdout, stderr = await docker_service.test_config()
                if not success:
                    # Revert the rename
                    conf_file.rename(disabled_file)
                    raise HTTPException(status_code=400, detail=f"Configuration validation failed: {stderr}")

            # Optionally reload NGINX
            reloaded = False
            if auto_reload:
                try:
                    await docker_service.reload_nginx()
                    reloaded = True
                except DockerServiceError as e:
                    logger.warning(f"Failed to reload NGINX: {e.message}")

            # Generate suggestions
            suggestions = get_site_enable_suggestions(site_name=site_name, reloaded=reloaded)

            return SiteMutationResponse(
                success=True,
                message=f"Site '{site_name}' enabled successfully",
                site_name=site_name,
                transaction_id=ctx.id,
                file_path=str(conf_file),
                reload_required=not reloaded,
                reloaded=reloaded,
                enabled=True,
                suggestions=suggestions,
            )

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Unexpected error enabling site: {e}")
            raise HTTPException(status_code=500, detail=f"Internal server error while enabling site: {e!s}")


@router.post(
    "/{site_name}/disable",
    response_model=Union[SiteMutationResponse, DryRunResult],
    summary="Disable Site",
    description="""
    Disable a site configuration without deleting it.

    This endpoint renames the `.conf` file to `.conf.disabled`,
    preventing NGINX from loading it while preserving the configuration.

    **Dry Run Mode:**
    Add `?dry_run=true` to preview the operation without making changes.

    **Auto-reload:**
    Set `auto_reload: true` to automatically reload NGINX after disabling.
    """,
    responses={
        200: {"description": "Site disabled successfully (or dry run result)"},
        400: {"description": "Site is already disabled"},
        404: {"description": "Site not found"},
        500: {"description": "Internal server error"},
    },
)
async def disable_site(
    site_name: str,
    request: SiteEnableDisableRequest = None,
    dry_run: bool = Query(default=False, description="Preview the operation without making changes"),
    auth: AuthContext = Depends(require_role(Role.OPERATOR)),
) -> SiteMutationResponse | DryRunResult:
    """
    Disable a site without deleting its configuration.

    Args:
        site_name: Name of the site to disable
        request: Optional request body with auto_reload setting
        dry_run: If True, preview the operation without making changes

    Returns:
        SiteMutationResponse or DryRunResult depending on dry_run flag
    """
    auto_reload = request.auto_reload if request else False

    conf_dir = get_nginx_conf_path()
    conf_file = conf_dir / f"{site_name}.conf"
    disabled_file = conf_dir / f"{site_name}.conf.disabled"

    # Check current state
    if disabled_file.exists():
        if dry_run:
            return DryRunResult(
                would_succeed=False,
                operation="disable",
                message=f"Site '{site_name}' is already disabled",
                validation_passed=False,
                affected_sites=[site_name],
            )
        raise HTTPException(status_code=400, detail=f"Site '{site_name}' is already disabled")

    if not conf_file.exists():
        if dry_run:
            return DryRunResult(
                would_succeed=False,
                operation="disable",
                message=f"Site '{site_name}' not found",
                validation_passed=False,
                affected_sites=[site_name],
            )
        raise HTTPException(status_code=404, detail=f"Site '{site_name}' not found")

    # If dry_run, return preview result
    if dry_run:
        current_content = conf_file.read_text()
        return DryRunResult(
            would_succeed=True,
            operation="disable",
            message=f"Would disable site '{site_name}'",
            validation_passed=True,
            warnings=[],
            diff=DryRunDiff(
                operation="disable",
                file_path=str(disabled_file),
                current_content=current_content,
                new_content=None,
                lines_added=0,
                lines_removed=0,
            ),
            affected_sites=[site_name],
            reload_required=True,
        )

    async with transactional_operation(
        operation=OperationType.SITE_UPDATE, resource_type="site", resource_id=site_name
    ) as ctx:
        try:
            # Rename enabled file to disabled
            conf_file.rename(disabled_file)
            logger.info(f"Disabled site: {site_name}")

            # Optionally reload NGINX
            reloaded = False
            if auto_reload:
                try:
                    await docker_service.reload_nginx()
                    reloaded = True
                except DockerServiceError as e:
                    logger.warning(f"Failed to reload NGINX: {e.message}")

            # Generate suggestions
            suggestions = get_site_disable_suggestions(site_name=site_name, reloaded=reloaded)

            return SiteMutationResponse(
                success=True,
                message=f"Site '{site_name}' disabled successfully",
                site_name=site_name,
                transaction_id=ctx.id,
                file_path=str(disabled_file),
                reload_required=not reloaded,
                reloaded=reloaded,
                enabled=False,
                suggestions=suggestions,
            )

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Unexpected error disabling site: {e}")
            raise HTTPException(status_code=500, detail=f"Internal server error while disabling site: {e!s}")
