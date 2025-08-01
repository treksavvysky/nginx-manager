"""
Site configuration endpoints.

REST API endpoints for managing NGINX server block configurations.
"""

from fastapi import APIRouter, HTTPException, Depends
from pathlib import Path
from typing import List, Dict, Any
import logging

from config import get_nginx_conf_path, settings
from core.config_manager.parser import nginx_parser
from models.config import SiteConfigResponse, ApiResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sites", tags=["Site Configuration"])


@router.get(
    "/",
    response_model=List[SiteConfigResponse],
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
                            "updated_at": "2024-01-20T14:45:00"
                        }
                    ]
                }
            }
        },
        404: {"description": "NGINX configuration directory not found"},
        500: {"description": "Internal server error during configuration parsing"}
    }
)
async def list_sites() -> List[SiteConfigResponse]:
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
            raise HTTPException(
                status_code=404,
                detail=f"NGINX configuration directory not found: {conf_dir}"
            )
        
        # Find all .conf files
        conf_files = list(conf_dir.glob("*.conf"))
        
        if not conf_files:
            logger.info(f"No .conf files found in {conf_dir}")
            return []
        
        sites = []
        for conf_file in conf_files:
            try:
                parsed_config = nginx_parser.parse_config_file(conf_file)
                if parsed_config:
                    # Convert to response model
                    site_response = SiteConfigResponse(**parsed_config)
                    sites.append(site_response)
                else:
                    logger.warning(f"Failed to parse config file: {conf_file}")
            
            except Exception as e:
                logger.error(f"Error processing {conf_file}: {e}")
                # Continue processing other files instead of failing completely
                continue
        
        logger.info(f"Successfully parsed {len(sites)} site configurations")
        return sites
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Unexpected error listing sites: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error while listing sites: {str(e)}"
        )


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
                        "last_validated": None
                    }
                }
            }
        },
        404: {"description": "Site configuration not found"},
        500: {"description": "Error parsing configuration file"}
    }
)
async def get_site(site_name: str) -> SiteConfigResponse:
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
            raise HTTPException(
                status_code=404,
                detail=f"Site configuration '{site_name}' not found"
            )
        
        # Parse the configuration file
        parsed_config = nginx_parser.parse_config_file(conf_file)
        
        if not parsed_config:
            logger.error(f"Failed to parse configuration file: {conf_file}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to parse configuration file for site '{site_name}'"
            )
        
        # Convert to response model
        site_response = SiteConfigResponse(**parsed_config)
        
        logger.info(f"Successfully retrieved configuration for site: {site_name}")
        return site_response
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Unexpected error getting site {site_name}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error while retrieving site '{site_name}': {str(e)}"
        )
