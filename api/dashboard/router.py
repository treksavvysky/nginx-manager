"""
Dashboard view routes.

All routes serve HTML — full pages for direct navigation,
HTML fragments for HTMX requests.
"""

import logging

from fastapi import APIRouter, Request
from starlette.responses import HTMLResponse, RedirectResponse

from dashboard import templates
from dashboard.context import base_context
from dashboard.dependencies import get_dashboard_auth, is_htmx

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------


@router.get("/", response_class=HTMLResponse)
@router.get("/sites", response_class=HTMLResponse)
async def site_list_page(request: Request):
    """Site list page — the dashboard home."""
    auth = await get_dashboard_auth(request)
    if isinstance(auth, RedirectResponse) or auth is None:
        from config import settings

        if settings.auth_enabled:
            return RedirectResponse(url="/dashboard/login", status_code=302)

    ctx = await base_context(request, auth)
    ctx["sites"] = await _get_all_sites()

    if is_htmx(request):
        return templates.TemplateResponse(request, "fragments/site_table.html", ctx)

    return templates.TemplateResponse(request, "pages/site_list.html", ctx)


@router.get("/sites/new", response_class=HTMLResponse)
async def site_create_page(request: Request):
    """Site creation form."""
    auth = await get_dashboard_auth(request)
    if isinstance(auth, RedirectResponse) or auth is None:
        from config import settings

        if settings.auth_enabled:
            return RedirectResponse(url="/dashboard/login", status_code=302)

    ctx = await base_context(request, auth)
    ctx["edit_mode"] = False
    ctx["site"] = None
    return templates.TemplateResponse(request, "pages/site_form.html", ctx)


@router.get("/sites/{site_name}", response_class=HTMLResponse)
async def site_detail_page(request: Request, site_name: str):
    """Site detail page with config viewer and actions."""
    auth = await get_dashboard_auth(request)
    if isinstance(auth, RedirectResponse) or auth is None:
        from config import settings

        if settings.auth_enabled:
            return RedirectResponse(url="/dashboard/login", status_code=302)

    ctx = await base_context(request, auth)

    site = await _get_site(site_name)
    if site is None:
        ctx["error"] = f"Site '{site_name}' not found"
        return templates.TemplateResponse(request, "pages/site_detail.html", ctx, status_code=404)

    ctx["site"] = site
    ctx["raw_config"] = _read_raw_config(site_name)
    return templates.TemplateResponse(request, "pages/site_detail.html", ctx)


@router.get("/sites/{site_name}/edit", response_class=HTMLResponse)
async def site_edit_page(request: Request, site_name: str):
    """Site edit form, pre-populated with current config."""
    auth = await get_dashboard_auth(request)
    if isinstance(auth, RedirectResponse) or auth is None:
        from config import settings

        if settings.auth_enabled:
            return RedirectResponse(url="/dashboard/login", status_code=302)

    ctx = await base_context(request, auth)

    site = await _get_site(site_name)
    if site is None:
        return RedirectResponse(url="/dashboard/sites", status_code=302)

    ctx["edit_mode"] = True
    ctx["site"] = site
    return templates.TemplateResponse(request, "pages/site_form.html", ctx)


# ---------------------------------------------------------------------------
# Monitoring page routes
# ---------------------------------------------------------------------------


@router.get("/health", response_class=HTMLResponse)
async def health_page(request: Request):
    """System health dashboard."""
    auth = await get_dashboard_auth(request)
    if isinstance(auth, RedirectResponse) or auth is None:
        from config import settings

        if settings.auth_enabled:
            return RedirectResponse(url="/dashboard/login", status_code=302)

    ctx = await base_context(request, auth)
    ctx["health_detail"] = await _get_health_detail()

    if is_htmx(request):
        return templates.TemplateResponse(request, "fragments/health_cards.html", ctx)

    return templates.TemplateResponse(request, "pages/health.html", ctx)


@router.get("/certificates", response_class=HTMLResponse)
async def certificates_page(request: Request):
    """SSL certificate overview."""
    auth = await get_dashboard_auth(request)
    if isinstance(auth, RedirectResponse) or auth is None:
        from config import settings

        if settings.auth_enabled:
            return RedirectResponse(url="/dashboard/login", status_code=302)

    ctx = await base_context(request, auth)
    cert_data = await _get_certificates()
    ctx["certificates"] = cert_data["certificates"]
    ctx["cert_summary"] = cert_data["summary"]

    if is_htmx(request):
        return templates.TemplateResponse(request, "fragments/cert_table.html", ctx)

    return templates.TemplateResponse(request, "pages/certificates.html", ctx)


@router.get("/events", response_class=HTMLResponse)
async def events_page(request: Request):
    """Event log viewer with filtering."""
    auth = await get_dashboard_auth(request)
    if isinstance(auth, RedirectResponse) or auth is None:
        from config import settings

        if settings.auth_enabled:
            return RedirectResponse(url="/dashboard/login", status_code=302)

    ctx = await base_context(request, auth)
    event_data = await _get_events(
        severity=request.query_params.get("severity"),
        category=request.query_params.get("category"),
        page=int(request.query_params.get("page", "1")),
    )
    ctx.update(
        {
            "events": event_data["events"],
            "event_total": event_data["total"],
            "event_page": event_data["page"],
            "event_has_more": event_data["has_more"],
            "event_counts": event_data["counts"],
            "event_filters": event_data["filters"],
        }
    )

    if is_htmx(request):
        return templates.TemplateResponse(request, "fragments/event_table.html", ctx)

    return templates.TemplateResponse(request, "pages/events.html", ctx)


@router.get("/transactions", response_class=HTMLResponse)
async def transactions_page(request: Request):
    """Transaction history with filtering."""
    auth = await get_dashboard_auth(request)
    if isinstance(auth, RedirectResponse) or auth is None:
        from config import settings

        if settings.auth_enabled:
            return RedirectResponse(url="/dashboard/login", status_code=302)

    ctx = await base_context(request, auth)
    txn_data = await _get_transactions(
        status=request.query_params.get("status"),
        operation=request.query_params.get("operation"),
        page=int(request.query_params.get("page", "1")),
    )
    ctx.update(
        {
            "transactions": txn_data["transactions"],
            "txn_total": txn_data["total"],
            "txn_page": txn_data["page"],
            "txn_has_more": txn_data["has_more"],
            "txn_filters": txn_data["filters"],
        }
    )

    if is_htmx(request):
        return templates.TemplateResponse(request, "fragments/transaction_table.html", ctx)

    return templates.TemplateResponse(request, "pages/transactions.html", ctx)


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Login page (only relevant when AUTH_ENABLED=true)."""
    from config import settings

    if not settings.auth_enabled:
        return RedirectResponse(url="/dashboard/", status_code=302)

    # Already authenticated?
    auth = await get_dashboard_auth(request)
    if auth is not None:
        return RedirectResponse(url="/dashboard/", status_code=302)

    return templates.TemplateResponse(request, "pages/login.html", {"error": None})


# ---------------------------------------------------------------------------
# HTMX action routes (return fragments)
# ---------------------------------------------------------------------------


@router.post("/sites/{site_name}/enable", response_class=HTMLResponse)
async def enable_site_action(request: Request, site_name: str):
    """Enable a site and return result fragment."""
    auth = await get_dashboard_auth(request)
    if auth is None:
        return HTMLResponse('<div class="toast error">Authentication required</div>', status_code=401)

    result = await _perform_enable_disable(site_name, enable=True)
    ctx = {"result": result, "site_name": site_name}
    return templates.TemplateResponse(request, "fragments/action_result.html", ctx)


@router.post("/sites/{site_name}/disable", response_class=HTMLResponse)
async def disable_site_action(request: Request, site_name: str):
    """Disable a site and return result fragment."""
    auth = await get_dashboard_auth(request)
    if auth is None:
        return HTMLResponse('<div class="toast error">Authentication required</div>', status_code=401)

    result = await _perform_enable_disable(site_name, enable=False)
    ctx = {"result": result, "site_name": site_name}
    return templates.TemplateResponse(request, "fragments/action_result.html", ctx)


@router.delete("/sites/{site_name}", response_class=HTMLResponse)
async def delete_site_action(request: Request, site_name: str):
    """Delete a site and return result fragment."""
    auth = await get_dashboard_auth(request)
    if auth is None:
        return HTMLResponse('<div class="toast error">Authentication required</div>', status_code=401)

    result = await _perform_delete(site_name)
    ctx = {"result": result, "site_name": site_name}

    response = templates.TemplateResponse(request, "fragments/action_result.html", ctx)
    if result.get("success"):
        response.headers["HX-Redirect"] = "/dashboard/sites"
    return response


@router.post("/sites/validate", response_class=HTMLResponse)
async def validate_site_action(request: Request):
    """Dry-run site creation/update and return result fragment."""
    auth = await get_dashboard_auth(request)
    if auth is None:
        return HTMLResponse('<div class="toast error">Authentication required</div>', status_code=401)

    form = await request.form()
    result = await _perform_dry_run(form)
    ctx = {"result": result}
    return templates.TemplateResponse(request, "fragments/dry_run_result.html", ctx)


@router.post("/sites", response_class=HTMLResponse)
async def create_site_action(request: Request):
    """Create a new site and return result fragment."""
    auth = await get_dashboard_auth(request)
    if auth is None:
        return HTMLResponse('<div class="toast error">Authentication required</div>', status_code=401)

    form = await request.form()
    result = await _perform_create(form)
    ctx = {"result": result}

    response = templates.TemplateResponse(request, "fragments/action_result.html", ctx)
    if result.get("success"):
        response.headers["HX-Redirect"] = f"/dashboard/sites/{result.get('site_name', '')}"
    return response


@router.put("/sites/{site_name}", response_class=HTMLResponse)
async def update_site_action(request: Request, site_name: str):
    """Update a site and return result fragment."""
    auth = await get_dashboard_auth(request)
    if auth is None:
        return HTMLResponse('<div class="toast error">Authentication required</div>', status_code=401)

    form = await request.form()
    result = await _perform_update(site_name, form)
    ctx = {"result": result, "site_name": site_name}

    response = templates.TemplateResponse(request, "fragments/action_result.html", ctx)
    if result.get("success"):
        response.headers["HX-Redirect"] = f"/dashboard/sites/{site_name}"
    return response


@router.post("/login", response_class=HTMLResponse)
async def login_action(request: Request):
    """Process login form submission."""
    from config import settings

    if not settings.auth_enabled:
        return RedirectResponse(url="/dashboard/", status_code=302)

    form = await request.form()
    username = form.get("username", "")
    password = form.get("password", "")

    try:
        from core.auth_service import get_auth_service
        from core.user_service import get_user_service

        user_service = get_user_service()
        result = await user_service.authenticate(username, password)

        if result is None:
            return templates.TemplateResponse(
                request, "pages/login.html", {"error": "Invalid username or password"}
            )

        auth_ctx, totp_enabled = result

        if totp_enabled:
            return templates.TemplateResponse(
                request,
                "pages/login.html",
                {"error": "2FA-enabled accounts must log in via the API. Dashboard 2FA support is coming soon."},
            )

        # Create JWT token
        auth_service = get_auth_service()
        token, expires_in = auth_service.create_jwt_token(auth_ctx)

        # Track session
        payload = auth_service.decode_token_payload(token)
        if payload and payload.get("jti"):
            from datetime import datetime, timedelta

            from core.session_service import get_session_service

            session_service = get_session_service()
            await session_service.create_session(
                jti=payload["jti"],
                user_id=auth_ctx.user_id,
                expires_at=datetime.utcnow() + timedelta(seconds=expires_in),
            )

        from dashboard.dependencies import set_auth_cookie

        response = RedirectResponse(url="/dashboard/", status_code=302)
        set_auth_cookie(response, token)
        return response

    except Exception as e:
        logger.error(f"Login error: {e}")
        return templates.TemplateResponse(request, "pages/login.html", {"error": str(e)})


@router.post("/logout")
async def logout_action():
    """Clear auth cookie and redirect to login."""
    from dashboard.dependencies import clear_auth_cookie

    response = RedirectResponse(url="/dashboard/login", status_code=302)
    clear_auth_cookie(response)
    return response


# ---------------------------------------------------------------------------
# Fragment routes (polled by HTMX)
# ---------------------------------------------------------------------------


@router.get("/fragments/status", response_class=HTMLResponse)
async def status_fragment(request: Request):
    """Return the health status indicator fragment."""
    from dashboard.context import _get_health_summary

    health = await _get_health_summary()
    return templates.TemplateResponse(
        request, "fragments/status_badge.html", {"health": health}
    )


@router.get("/fragments/health-cards", response_class=HTMLResponse)
async def health_cards_fragment(request: Request):
    """Return health cards fragment for polling."""
    ctx = {"health_detail": await _get_health_detail()}
    return templates.TemplateResponse(request, "fragments/health_cards.html", ctx)


@router.get("/transactions/{txn_id}/detail", response_class=HTMLResponse)
async def transaction_detail_fragment(request: Request, txn_id: str):
    """Return transaction detail fragment with diff viewer."""
    auth = await get_dashboard_auth(request)
    if auth is None:
        from config import settings

        if settings.auth_enabled:
            return HTMLResponse('<div class="toast error">Authentication required</div>', status_code=401)

    detail = await _get_transaction_detail(txn_id)
    if detail is None:
        return HTMLResponse(f'<div class="toast error">Transaction {txn_id[:8]} not found</div>')

    ctx = {"detail": detail}
    return templates.TemplateResponse(request, "fragments/transaction_detail.html", ctx)


@router.post("/transactions/{txn_id}/rollback", response_class=HTMLResponse)
async def rollback_action(request: Request, txn_id: str):
    """Rollback a transaction and return result fragment."""
    auth = await get_dashboard_auth(request)
    if auth is None:
        from config import settings

        if settings.auth_enabled:
            return HTMLResponse('<div class="toast error">Authentication required</div>', status_code=401)

    result = await _perform_rollback(txn_id)
    ctx = {"result": result}
    return templates.TemplateResponse(request, "fragments/rollback_result.html", ctx)


# ---------------------------------------------------------------------------
# Internal helpers — call the same business logic as the API
# ---------------------------------------------------------------------------


async def _get_all_sites() -> list[dict]:
    """List all sites by parsing config files (same logic as GET /sites/)."""
    from config import get_nginx_conf_path
    from core.config_manager import ConfigAdapter, nginx_parser

    conf_dir = get_nginx_conf_path()
    if not conf_dir.exists():
        return []

    conf_files = list(conf_dir.glob("*.conf")) + list(conf_dir.glob("*.conf.disabled"))
    if not conf_files:
        return []

    sites = []
    for conf_file in sorted(conf_files, key=lambda f: f.stem):
        try:
            parsed = nginx_parser.parse_config_file(conf_file)
            if parsed:
                site = ConfigAdapter.to_rich_dict(parsed)
                sites.append(site)
        except Exception as e:
            logger.warning(f"Failed to parse {conf_file}: {e}")
            continue

    # Enrich with certificate data
    try:
        from core.cert_helpers import get_certificate_map, match_certificate

        cert_map = await get_certificate_map()
        for site in sites:
            server_names = site.get("server_names", [])
            if server_names:
                site["certificate"] = match_certificate(server_names, cert_map)
    except Exception as e:
        logger.warning(f"Failed to load certificate data: {e}")

    return sites


async def _get_site(site_name: str) -> dict | None:
    """Get a single site by name."""
    from config import get_nginx_conf_path
    from core.config_manager import ConfigAdapter, nginx_parser

    conf_dir = get_nginx_conf_path()
    conf_file = conf_dir / f"{site_name}.conf"
    disabled_file = conf_dir / f"{site_name}.conf.disabled"

    target = conf_file if conf_file.exists() else disabled_file if disabled_file.exists() else None
    if target is None:
        return None

    try:
        parsed = nginx_parser.parse_config_file(target)
        if not parsed:
            return None
        site = ConfigAdapter.to_rich_dict(parsed)

        # Enrich with certificate data
        try:
            from core.cert_helpers import get_certificate_map, match_certificate

            cert_map = await get_certificate_map()
            server_names = site.get("server_names", [])
            if server_names:
                site["certificate"] = match_certificate(server_names, cert_map)
        except Exception:
            pass

        return site
    except Exception as e:
        logger.error(f"Failed to parse site {site_name}: {e}")
        return None


def _read_raw_config(site_name: str) -> str:
    """Read the raw config file content for display."""
    from config import get_nginx_conf_path

    conf_dir = get_nginx_conf_path()
    for suffix in (".conf", ".conf.disabled"):
        path = conf_dir / f"{site_name}{suffix}"
        if path.exists():
            return path.read_text()
    return ""


async def _perform_enable_disable(site_name: str, enable: bool) -> dict:
    """Enable or disable a site."""
    from config import get_nginx_conf_path
    from core.docker_service import DockerServiceError, docker_service
    from core.transaction_context import transactional_operation
    from models.transaction import OperationType

    conf_dir = get_nginx_conf_path()
    conf_file = conf_dir / f"{site_name}.conf"
    disabled_file = conf_dir / f"{site_name}.conf.disabled"

    if enable:
        if conf_file.exists():
            return {"success": False, "message": f"Site '{site_name}' is already enabled"}
        if not disabled_file.exists():
            return {"success": False, "message": f"Site '{site_name}' not found"}

        async with transactional_operation(
            operation=OperationType.SITE_UPDATE, resource_type="site", resource_id=site_name
        ) as ctx:
            disabled_file.rename(conf_file)
            reloaded = False
            try:
                await docker_service.reload_nginx()
                reloaded = True
            except DockerServiceError as e:
                logger.warning(f"Failed to reload NGINX: {e.message}")
            return {
                "success": True,
                "message": f"Site '{site_name}' enabled",
                "reloaded": reloaded,
                "transaction_id": ctx.id,
            }
    else:
        if disabled_file.exists():
            return {"success": False, "message": f"Site '{site_name}' is already disabled"}
        if not conf_file.exists():
            return {"success": False, "message": f"Site '{site_name}' not found"}

        async with transactional_operation(
            operation=OperationType.SITE_UPDATE, resource_type="site", resource_id=site_name
        ) as ctx:
            conf_file.rename(disabled_file)
            reloaded = False
            try:
                await docker_service.reload_nginx()
                reloaded = True
            except DockerServiceError as e:
                logger.warning(f"Failed to reload NGINX: {e.message}")
            return {
                "success": True,
                "message": f"Site '{site_name}' disabled",
                "reloaded": reloaded,
                "transaction_id": ctx.id,
            }


async def _perform_delete(site_name: str) -> dict:
    """Delete a site configuration."""
    from config import get_nginx_conf_path
    from core.docker_service import DockerServiceError, docker_service
    from core.transaction_context import transactional_operation
    from models.transaction import OperationType

    conf_dir = get_nginx_conf_path()
    conf_file = conf_dir / f"{site_name}.conf"
    disabled_file = conf_dir / f"{site_name}.conf.disabled"

    target = conf_file if conf_file.exists() else disabled_file if disabled_file.exists() else None
    if target is None:
        return {"success": False, "message": f"Site '{site_name}' not found"}

    was_enabled = target.suffix == ".conf"

    async with transactional_operation(
        operation=OperationType.SITE_DELETE, resource_type="site", resource_id=site_name
    ) as ctx:
        target.unlink()
        reloaded = False
        if was_enabled:
            try:
                await docker_service.reload_nginx()
                reloaded = True
            except DockerServiceError as e:
                logger.warning(f"Failed to reload NGINX: {e.message}")
        return {
            "success": True,
            "message": f"Site '{site_name}' deleted",
            "reloaded": reloaded,
            "transaction_id": ctx.id,
        }


async def _perform_dry_run(form) -> dict:
    """Run a dry-run site creation/update."""
    from config import get_nginx_conf_path
    from core.config_generator import ConfigGeneratorError, get_config_generator
    from models.site_requests import SiteCreateRequest, SiteType

    name = form.get("name", "").strip()
    edit_mode = form.get("edit_mode", "false") == "true"
    site_type_str = form.get("site_type", "static")
    server_names_raw = form.get("server_names", "").strip()
    server_names = [s.strip() for s in server_names_raw.split(",") if s.strip()] if server_names_raw else [name]
    listen_port = int(form.get("listen_port", "80") or "80")
    root_path = form.get("root_path", "").strip() or None
    proxy_pass = form.get("proxy_pass", "").strip() or None

    if not name:
        return {"success": False, "message": "Site name is required"}

    try:
        site_type = SiteType(site_type_str)
    except ValueError:
        return {"success": False, "message": f"Invalid site type: {site_type_str}"}

    try:
        create_req = SiteCreateRequest(
            name=name,
            server_names=server_names,
            site_type=site_type,
            listen_port=listen_port,
            root_path=root_path,
            proxy_pass=proxy_pass,
            auto_reload=False,
        )
    except Exception as e:
        return {"success": False, "message": str(e)}

    try:
        generator = get_config_generator()
        config_content = generator.generate(create_req)
    except ConfigGeneratorError as e:
        return {"success": False, "message": f"Config generation failed: {e.message}"}

    # Check if file already exists (for create mode)
    conf_dir = get_nginx_conf_path()
    if not edit_mode:
        conf_file = conf_dir / f"{name}.conf"
        if conf_file.exists():
            return {"success": False, "message": f"Site '{name}' already exists"}
        disabled_file = conf_dir / f"{name}.conf.disabled"
        if disabled_file.exists():
            return {"success": False, "message": f"Site '{name}' exists but is disabled"}

    return {
        "success": True,
        "message": f"Configuration for '{name}' is valid",
        "generated_config": config_content,
        "lines": config_content.count("\n") + 1,
    }


async def _perform_create(form) -> dict:
    """Create a new site from form data."""
    import shutil
    import tempfile
    from pathlib import Path

    from config import get_nginx_conf_path, settings
    from core.config_generator import ConfigGeneratorError, get_config_generator
    from core.docker_service import DockerServiceError, docker_service
    from core.transaction_context import transactional_operation
    from models.site_requests import SiteCreateRequest, SiteType
    from models.transaction import OperationType

    name = form.get("name", "").strip()
    site_type_str = form.get("site_type", "static")
    server_names_raw = form.get("server_names", "").strip()
    server_names = [s.strip() for s in server_names_raw.split(",") if s.strip()] if server_names_raw else [name]
    listen_port = int(form.get("listen_port", "80") or "80")
    root_path = form.get("root_path", "").strip() or None
    proxy_pass = form.get("proxy_pass", "").strip() or None
    auto_reload = form.get("auto_reload") == "on"

    if not name:
        return {"success": False, "message": "Site name is required"}

    try:
        site_type = SiteType(site_type_str)
        create_req = SiteCreateRequest(
            name=name,
            server_names=server_names,
            site_type=site_type,
            listen_port=listen_port,
            root_path=root_path,
            proxy_pass=proxy_pass,
            auto_reload=auto_reload,
        )
    except Exception as e:
        return {"success": False, "message": str(e), "site_name": name}

    conf_dir = get_nginx_conf_path()
    conf_file = conf_dir / f"{name}.conf"

    if conf_file.exists():
        return {"success": False, "message": f"Site '{name}' already exists", "site_name": name}

    try:
        generator = get_config_generator()
        config_content = generator.generate(create_req)
    except ConfigGeneratorError as e:
        return {"success": False, "message": f"Config generation failed: {e.message}", "site_name": name}

    # Validate
    if settings.validate_before_deploy:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as tmp:
            tmp.write(config_content)
            tmp_path = Path(tmp.name)
        try:
            shutil.copy(tmp_path, conf_file)
            success, stdout, stderr = await docker_service.test_config()
            if not success:
                conf_file.unlink(missing_ok=True)
                return {"success": False, "message": f"Validation failed: {stderr or stdout}", "site_name": name}
            conf_file.unlink(missing_ok=True)
        finally:
            tmp_path.unlink(missing_ok=True)

    # Create within transaction
    async with transactional_operation(
        operation=OperationType.SITE_CREATE, resource_type="site", resource_id=name
    ) as ctx:
        conf_file.write_text(config_content)
        reloaded = False
        if auto_reload:
            try:
                await docker_service.reload_nginx()
                reloaded = True
            except DockerServiceError as e:
                logger.warning(f"Failed to reload NGINX: {e.message}")
        return {
            "success": True,
            "message": f"Site '{name}' created successfully",
            "site_name": name,
            "reloaded": reloaded,
            "transaction_id": ctx.id,
        }


async def _perform_update(site_name: str, form) -> dict:
    """Update an existing site from form data."""
    import shutil

    from config import get_nginx_conf_path, settings
    from core.config_generator import ConfigGeneratorError, get_config_generator
    from core.config_manager import ConfigAdapter, nginx_parser
    from core.docker_service import DockerServiceError, docker_service
    from core.transaction_context import transactional_operation
    from models.site_requests import SiteCreateRequest, SiteType
    from models.transaction import OperationType

    conf_dir = get_nginx_conf_path()
    conf_file = conf_dir / f"{site_name}.conf"

    if not conf_file.exists():
        return {"success": False, "message": f"Site '{site_name}' not found", "site_name": site_name}

    # Parse existing config
    parsed = nginx_parser.parse_config_file(conf_file)
    if not parsed:
        return {"success": False, "message": f"Failed to parse existing config for '{site_name}'", "site_name": site_name}

    existing = ConfigAdapter.to_rich_dict(parsed)

    # Merge form data with existing
    server_names_raw = form.get("server_names", "").strip()
    server_names = (
        [s.strip() for s in server_names_raw.split(",") if s.strip()]
        if server_names_raw
        else existing.get("server_names", [site_name])
    )
    listen_port = int(form.get("listen_port", "80") or "80")
    root_path = form.get("root_path", "").strip() or existing.get("root_path")
    proxy_pass = form.get("proxy_pass", "").strip() or existing.get("proxy_pass")
    auto_reload = form.get("auto_reload") == "on"

    site_type = SiteType.REVERSE_PROXY if existing.get("proxy_pass") else SiteType.STATIC

    try:
        create_req = SiteCreateRequest(
            name=site_name,
            server_names=server_names,
            site_type=site_type,
            listen_port=listen_port,
            root_path=root_path,
            proxy_pass=proxy_pass,
            auto_reload=auto_reload,
        )
    except Exception as e:
        return {"success": False, "message": str(e), "site_name": site_name}

    try:
        generator = get_config_generator()
        config_content = generator.generate(create_req)
    except ConfigGeneratorError as e:
        return {"success": False, "message": f"Config generation failed: {e.message}", "site_name": site_name}

    # Validate
    if settings.validate_before_deploy:
        backup_path = conf_file.with_suffix(".conf.bak")
        shutil.copy(conf_file, backup_path)
        try:
            conf_file.write_text(config_content)
            success, stdout, stderr = await docker_service.test_config()
            if not success:
                shutil.copy(backup_path, conf_file)
                return {
                    "success": False,
                    "message": f"Validation failed: {stderr or stdout}",
                    "site_name": site_name,
                }
            shutil.copy(backup_path, conf_file)
        finally:
            backup_path.unlink(missing_ok=True)

    # Update within transaction
    async with transactional_operation(
        operation=OperationType.SITE_UPDATE, resource_type="site", resource_id=site_name
    ) as ctx:
        conf_file.write_text(config_content)
        reloaded = False
        if auto_reload:
            try:
                await docker_service.reload_nginx()
                reloaded = True
            except DockerServiceError as e:
                logger.warning(f"Failed to reload NGINX: {e.message}")
        return {
            "success": True,
            "message": f"Site '{site_name}' updated successfully",
            "site_name": site_name,
            "reloaded": reloaded,
            "transaction_id": ctx.id,
        }


# ---------------------------------------------------------------------------
# Internal helpers — monitoring
# ---------------------------------------------------------------------------


async def _get_health_detail() -> dict:
    """Get detailed health information for the health dashboard."""
    detail = {
        "nginx": {
            "running": False,
            "status": "unknown",
            "container_id": "",
            "uptime_seconds": 0,
            "uptime_human": "\u2014",
            "health_status": "unknown",
            "pid": None,
            "version": "",
        },
        "sites": {"total": 0, "enabled": 0, "disabled": 0},
        "ssl": {"total": 0, "valid": 0, "expiring_soon": 0, "expired": 0},
        "security_warnings": [],
        "overall_status": "unknown",
    }

    # NGINX container status
    try:
        from core.docker_service import docker_service

        container_status = await docker_service.get_container_status()
        detail["nginx"]["running"] = container_status.get("running", False)
        detail["nginx"]["status"] = container_status.get("status", "unknown")
        detail["nginx"]["container_id"] = container_status.get("container_id", "")
        detail["nginx"]["health_status"] = container_status.get("health_status", "unknown")
        detail["nginx"]["pid"] = container_status.get("pid")
        uptime = container_status.get("uptime_seconds", 0) or 0
        detail["nginx"]["uptime_seconds"] = uptime
        detail["nginx"]["uptime_human"] = _format_uptime(uptime)
    except Exception as e:
        logger.warning(f"Failed to get container status: {e}")

    # NGINX version
    try:
        from core.docker_service import docker_service

        version_info = await docker_service.get_nginx_version()
        detail["nginx"]["version"] = version_info.get("version", "")
    except Exception:
        pass

    # Site counts
    try:
        from config import get_nginx_conf_path

        conf_dir = get_nginx_conf_path()
        if conf_dir.exists():
            detail["sites"]["enabled"] = len(list(conf_dir.glob("*.conf")))
            detail["sites"]["disabled"] = len(list(conf_dir.glob("*.conf.disabled")))
            detail["sites"]["total"] = detail["sites"]["enabled"] + detail["sites"]["disabled"]
    except Exception:
        pass

    # SSL status
    try:
        from core.cert_manager import get_cert_manager
        from models.certificate import CertificateStatus

        cert_manager = get_cert_manager()
        certs = await cert_manager.list_certificates()
        detail["ssl"]["total"] = len(certs)
        detail["ssl"]["valid"] = len([c for c in certs if c.status == CertificateStatus.VALID])
        detail["ssl"]["expiring_soon"] = len([c for c in certs if c.status == CertificateStatus.EXPIRING_SOON])
        detail["ssl"]["expired"] = len([c for c in certs if c.status == CertificateStatus.EXPIRED])
    except Exception:
        pass

    # Security warnings
    try:
        from core.context_helpers import get_security_warnings

        detail["security_warnings"] = get_security_warnings()
    except Exception:
        pass

    # Overall status
    nginx = detail["nginx"]
    if nginx["running"] and nginx["health_status"] == "healthy":
        detail["overall_status"] = "healthy"
    elif nginx["running"]:
        detail["overall_status"] = "degraded"
    else:
        detail["overall_status"] = "unhealthy"

    return detail


def _format_uptime(seconds: int) -> str:
    """Format uptime seconds into human-readable string."""
    if seconds <= 0:
        return "\u2014"
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


async def _get_certificates() -> dict:
    """Get all certificates for the certificate overview."""
    try:
        from core.cert_manager import get_cert_manager

        cert_manager = get_cert_manager()
        certs = await cert_manager.list_certificates()
    except Exception as e:
        logger.warning(f"Failed to list certificates: {e}")
        return {
            "certificates": [],
            "summary": {"total": 0, "valid": 0, "expiring_soon": 0, "expired": 0, "pending": 0, "failed": 0},
        }

    cert_list = []
    summary = {"total": 0, "valid": 0, "expiring_soon": 0, "expired": 0, "pending": 0, "failed": 0}

    for cert in certs:
        cert_dict = {
            "domain": cert.domain,
            "alt_names": cert.alt_names,
            "status": cert.status.value if cert.status else "unknown",
            "certificate_type": cert.certificate_type.value if cert.certificate_type else "unknown",
            "issuer": cert.issuer,
            "not_before": cert.not_before,
            "not_after": cert.not_after,
            "days_until_expiry": cert.days_until_expiry,
            "auto_renew": cert.auto_renew,
            "created_at": cert.created_at,
            "last_renewed": cert.last_renewed,
        }
        cert_list.append(cert_dict)
        summary["total"] += 1
        status_key = cert.status.value if cert.status else None
        if status_key in summary:
            summary[status_key] += 1

    # Sort: expired first, then expiring_soon, then rest
    status_order = {"expired": 0, "expiring_soon": 1, "failed": 2, "pending": 3, "valid": 4, "revoked": 5}
    cert_list.sort(key=lambda c: status_order.get(c["status"], 99))

    return {"certificates": cert_list, "summary": summary}


async def _get_events(severity: str | None = None, category: str | None = None, page: int = 1) -> dict:
    """Get events with optional filtering."""
    try:
        from core.event_store import get_event_store
        from models.event import EventFilters, EventSeverity

        event_store = get_event_store()

        filters = EventFilters()
        if severity:
            try:
                filters.severity = [EventSeverity(severity)]
            except ValueError:
                pass
        if category:
            filters.category = [category]

        result = await event_store.list_events(filters=filters, page=page, page_size=50)
        counts = await event_store.get_event_counts_by_severity()

        events = []
        for evt in result.events:
            events.append(
                {
                    "id": evt.id,
                    "timestamp": evt.timestamp,
                    "severity": evt.severity.value if evt.severity else "info",
                    "category": evt.category,
                    "action": evt.action,
                    "message": evt.message,
                    "resource_type": evt.resource_type,
                    "resource_id": evt.resource_id,
                    "transaction_id": evt.transaction_id,
                    "source": evt.source,
                    "client_ip": evt.client_ip,
                    "user_id": evt.user_id,
                }
            )

        return {
            "events": events,
            "total": result.total,
            "page": result.page,
            "has_more": result.has_more,
            "counts": {
                "info": counts.info,
                "warning": counts.warning,
                "error": counts.error,
                "critical": counts.critical,
                "total": counts.total,
            },
            "filters": {"severity": severity, "category": category},
        }
    except Exception as e:
        logger.warning(f"Failed to get events: {e}")
        return {
            "events": [],
            "total": 0,
            "page": 1,
            "has_more": False,
            "counts": {"info": 0, "warning": 0, "error": 0, "critical": 0, "total": 0},
            "filters": {"severity": severity, "category": category},
        }


async def _get_transactions(status: str | None = None, operation: str | None = None, page: int = 1) -> dict:
    """Get transactions with optional filtering."""
    try:
        from core.transaction_manager import get_transaction_manager
        from models.transaction import OperationType, TransactionStatus

        txn_manager = get_transaction_manager()

        status_filter = None
        if status:
            try:
                status_filter = TransactionStatus(status)
            except ValueError:
                pass

        operation_filter = None
        if operation:
            try:
                operation_filter = OperationType(operation)
            except ValueError:
                pass

        page_size = 30
        offset = (page - 1) * page_size

        result = await txn_manager.list_transactions(
            limit=page_size, offset=offset, status=status_filter, operation=operation_filter
        )

        transactions = []
        for txn in result.transactions:
            transactions.append(
                {
                    "id": txn.id,
                    "operation": txn.operation.value,
                    "status": txn.status.value,
                    "resource_type": txn.resource_type,
                    "resource_id": txn.resource_id,
                    "created_at": txn.created_at,
                    "completed_at": txn.completed_at,
                    "duration_ms": txn.duration_ms,
                    "error_message": txn.error_message,
                }
            )

        return {
            "transactions": transactions,
            "total": result.total,
            "page": page,
            "has_more": result.has_more,
            "filters": {"status": status, "operation": operation},
        }
    except Exception as e:
        logger.warning(f"Failed to get transactions: {e}")
        return {
            "transactions": [],
            "total": 0,
            "page": 1,
            "has_more": False,
            "filters": {"status": status, "operation": operation},
        }


async def _get_transaction_detail(txn_id: str) -> dict | None:
    """Get full transaction detail with diff."""
    try:
        from core.transaction_manager import get_transaction_manager

        txn_manager = get_transaction_manager()
        detail = await txn_manager.get_transaction_detail(txn_id)
        if detail is None:
            return None

        diff_files = []
        if detail.diff and detail.diff.files:
            for f in detail.diff.files:
                diff_files.append(
                    {
                        "file_path": f.file_path,
                        "change_type": f.change_type,
                        "additions": f.additions,
                        "deletions": f.deletions,
                        "diff_content": f.diff_content,
                    }
                )

        return {
            "id": detail.id,
            "operation": detail.operation.value,
            "status": detail.status.value,
            "resource_type": detail.resource_type,
            "resource_id": detail.resource_id,
            "created_at": detail.created_at,
            "completed_at": detail.completed_at,
            "duration_ms": detail.duration_ms,
            "error_message": detail.error_message,
            "nginx_validated": detail.nginx_validated,
            "health_verified": detail.health_verified,
            "can_rollback": detail.can_rollback,
            "rollback_reason": detail.rollback_reason,
            "diff": {
                "files_changed": detail.diff.files_changed if detail.diff else 0,
                "total_additions": detail.diff.total_additions if detail.diff else 0,
                "total_deletions": detail.diff.total_deletions if detail.diff else 0,
                "files": diff_files,
            },
            "affected_files": detail.affected_files,
        }
    except Exception as e:
        logger.warning(f"Failed to get transaction detail: {e}")
        return None


async def _perform_rollback(txn_id: str) -> dict:
    """Perform a transaction rollback."""
    try:
        from core.transaction_manager import get_transaction_manager

        txn_manager = get_transaction_manager()
        result = await txn_manager.rollback_transaction(txn_id)
        return {
            "success": result.success,
            "message": result.message,
            "transaction_id": result.rollback_transaction_id,
            "warnings": result.warnings,
        }
    except Exception as e:
        return {"success": False, "message": str(e)}
