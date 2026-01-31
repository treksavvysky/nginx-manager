"""
Dashboard route tests.

Tests that dashboard pages render correctly and return proper HTML responses.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "api"))

import pytest
from httpx import ASGITransport, AsyncClient

from main import app


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_dashboard_root_returns_html(client):
    """GET /dashboard/ should return an HTML page."""
    resp = await client.get("/dashboard/", follow_redirects=True)
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "NGINX Manager" in resp.text


@pytest.mark.anyio
async def test_dashboard_sites_returns_html(client):
    """GET /dashboard/sites should return the site list page."""
    resp = await client.get("/dashboard/sites", follow_redirects=True)
    assert resp.status_code == 200
    assert "Sites" in resp.text


@pytest.mark.anyio
async def test_dashboard_new_site_form(client):
    """GET /dashboard/sites/new should return the create form."""
    resp = await client.get("/dashboard/sites/new", follow_redirects=True)
    assert resp.status_code == 200
    assert "Create New Site" in resp.text
    assert 'name="site_type"' in resp.text


@pytest.mark.anyio
async def test_dashboard_site_detail_not_found(client):
    """GET /dashboard/sites/nonexistent should return 404."""
    resp = await client.get("/dashboard/sites/nonexistent", follow_redirects=True)
    assert resp.status_code == 404
    assert "not found" in resp.text.lower()


@pytest.mark.anyio
async def test_dashboard_login_redirects_when_auth_disabled(client):
    """GET /dashboard/login should redirect to dashboard when auth is disabled."""
    resp = await client.get("/dashboard/login", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/dashboard/"


# ---------------------------------------------------------------------------
# Fragment routes
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_status_fragment(client):
    """GET /dashboard/fragments/status should return health status HTML."""
    resp = await client.get("/dashboard/fragments/status")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "NGINX" in resp.text


@pytest.mark.anyio
async def test_htmx_site_list_returns_fragment(client):
    """HTMX request to /dashboard/sites should return just the table fragment."""
    resp = await client.get("/dashboard/sites", headers={"HX-Request": "true"}, follow_redirects=True)
    assert resp.status_code == 200
    # Fragment should not include full HTML boilerplate
    # (it may have an empty table or empty state)
    assert "text/html" in resp.headers["content-type"]


# ---------------------------------------------------------------------------
# Static assets
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_static_css(client):
    """Dashboard CSS should be served."""
    resp = await client.get("/dashboard/static/css/dashboard.css")
    assert resp.status_code == 200
    assert "text/css" in resp.headers["content-type"]


@pytest.mark.anyio
async def test_static_js(client):
    """Dashboard JS should be served."""
    resp = await client.get("/dashboard/static/js/dashboard.js")
    assert resp.status_code == 200


@pytest.mark.anyio
async def test_static_htmx_vendor(client):
    """Vendored htmx.js should be served."""
    resp = await client.get("/dashboard/static/vendor/htmx.min.js")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_dashboard_frame_options_sameorigin(client):
    """Dashboard pages should have X-Frame-Options: SAMEORIGIN for HTMX."""
    resp = await client.get("/dashboard/sites", follow_redirects=True)
    assert resp.headers.get("x-frame-options") == "SAMEORIGIN"


@pytest.mark.anyio
async def test_api_frame_options_deny(client):
    """API endpoints should still have X-Frame-Options: DENY."""
    resp = await client.get("/health")
    assert resp.headers.get("x-frame-options") == "DENY"


@pytest.mark.anyio
async def test_static_assets_cached(client):
    """Static assets should have cache headers."""
    resp = await client.get("/dashboard/static/css/dashboard.css")
    assert "public" in resp.headers.get("cache-control", "")
