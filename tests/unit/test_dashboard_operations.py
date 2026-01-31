"""
Dashboard operations tests (Phase 7.3).

Tests for quick actions, workflow UI, admin pages, 2FA login,
and updated navigation.
"""

import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

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
# Navigation
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_nav_contains_workflows_link(client):
    """Navigation should include a Workflows link."""
    resp = await client.get("/dashboard/sites", follow_redirects=True)
    assert resp.status_code == 200
    assert "/dashboard/workflows" in resp.text


@pytest.mark.anyio
async def test_nav_contains_admin_links(client):
    """Navigation should include Users and API Keys links (auth disabled = admin)."""
    resp = await client.get("/dashboard/sites", follow_redirects=True)
    assert resp.status_code == 200
    assert "/dashboard/users" in resp.text
    assert "/dashboard/api-keys" in resp.text


# ---------------------------------------------------------------------------
# Quick Actions — Health page
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_health_page_contains_quick_actions(client):
    """Health page should contain quick action buttons."""
    resp = await client.get("/dashboard/health", follow_redirects=True)
    assert resp.status_code == 200
    assert "Quick Actions" in resp.text
    assert "Reload" in resp.text
    assert "Restart" in resp.text
    assert "Test Config" in resp.text


@pytest.mark.anyio
async def test_nginx_reload_action_returns_toast(client):
    """POST /dashboard/nginx/reload should return an action result toast."""
    with patch("dashboard.router._perform_nginx_reload", new_callable=AsyncMock) as mock_reload:
        mock_reload.return_value = {"success": True, "message": "NGINX reloaded successfully"}
        resp = await client.post("/dashboard/nginx/reload")
        assert resp.status_code == 200
        assert "NGINX reloaded" in resp.text


@pytest.mark.anyio
async def test_nginx_restart_action_returns_toast(client):
    """POST /dashboard/nginx/restart should return an action result toast."""
    with patch("dashboard.router._perform_nginx_restart", new_callable=AsyncMock) as mock_restart:
        mock_restart.return_value = {"success": True, "message": "NGINX container restarted successfully"}
        resp = await client.post("/dashboard/nginx/restart")
        assert resp.status_code == 200
        assert "restarted" in resp.text


@pytest.mark.anyio
async def test_nginx_test_action_returns_toast(client):
    """POST /dashboard/nginx/test should return an action result toast."""
    with patch("dashboard.router._perform_nginx_test", new_callable=AsyncMock) as mock_test:
        mock_test.return_value = {
            "success": True,
            "message": "Configuration syntax is valid",
            "stdout": "",
            "stderr": "",
        }
        resp = await client.post("/dashboard/nginx/test")
        assert resp.status_code == 200
        assert "valid" in resp.text


@pytest.mark.anyio
async def test_nginx_test_failure_returns_error_toast(client):
    """Test config failure should return an error toast."""
    with patch("dashboard.router._perform_nginx_test", new_callable=AsyncMock) as mock_test:
        mock_test.return_value = {
            "success": False,
            "message": "Configuration test failed",
            "stdout": "",
            "stderr": "nginx: [emerg] unexpected end of file",
        }
        resp = await client.post("/dashboard/nginx/test")
        assert resp.status_code == 200
        assert "failed" in resp.text.lower()


# ---------------------------------------------------------------------------
# Workflow UI
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_workflows_page_returns_html(client):
    """GET /dashboard/workflows should return the workflows page."""
    resp = await client.get("/dashboard/workflows", follow_redirects=True)
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "Workflows" in resp.text


@pytest.mark.anyio
async def test_workflows_page_contains_setup_form(client):
    """Workflows page should contain the setup-site form."""
    resp = await client.get("/dashboard/workflows", follow_redirects=True)
    assert resp.status_code == 200
    assert "Setup New Site" in resp.text
    assert 'name="site_type"' in resp.text


@pytest.mark.anyio
async def test_workflows_page_contains_migrate_form(client):
    """Workflows page should contain the migrate-site form."""
    resp = await client.get("/dashboard/workflows", follow_redirects=True)
    assert resp.status_code == 200
    assert "Migrate Existing Site" in resp.text
    assert 'id="migrate-name"' in resp.text


@pytest.mark.anyio
async def test_workflows_page_includes_sse_script(client):
    """Workflows page should include the workflow-sse.js script."""
    resp = await client.get("/dashboard/workflows", follow_redirects=True)
    assert resp.status_code == 200
    assert "workflow-sse.js" in resp.text


# ---------------------------------------------------------------------------
# Admin — Users
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_users_page_returns_html(client):
    """GET /dashboard/users should return the users page."""
    resp = await client.get("/dashboard/users", follow_redirects=True)
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "Users" in resp.text


@pytest.mark.anyio
async def test_users_page_shows_auth_disabled_banner(client):
    """Users page should show info banner when auth is disabled."""
    resp = await client.get("/dashboard/users", follow_redirects=True)
    assert resp.status_code == 200
    assert "Authentication is disabled" in resp.text


@pytest.mark.anyio
async def test_users_new_page_returns_form(client):
    """GET /dashboard/users/new should return the create user form."""
    resp = await client.get("/dashboard/users/new", follow_redirects=True)
    assert resp.status_code == 200
    assert "Create New User" in resp.text
    assert 'name="username"' in resp.text
    assert 'name="password"' in resp.text


@pytest.mark.anyio
async def test_users_page_htmx_returns_fragment(client):
    """HTMX request to /dashboard/users should return just the table fragment."""
    resp = await client.get("/dashboard/users", headers={"HX-Request": "true"}, follow_redirects=True)
    assert resp.status_code == 200
    # Fragment should not have full HTML boilerplate
    assert "<!DOCTYPE" not in resp.text


@pytest.mark.anyio
async def test_create_user_action(client):
    """POST /dashboard/users should create a user and return result."""
    with patch("dashboard.router._perform_create_user", new_callable=AsyncMock) as mock_create:
        mock_create.return_value = {"success": True, "message": "User 'testuser' created"}
        resp = await client.post(
            "/dashboard/users",
            data={"username": "testuser", "password": "SecurePass123!", "role": "operator"},
        )
        assert resp.status_code == 200
        assert "created" in resp.text


@pytest.mark.anyio
async def test_delete_user_action(client):
    """DELETE /dashboard/users/{id} should return result toast."""
    with patch("dashboard.router._perform_delete_user", new_callable=AsyncMock) as mock_delete:
        mock_delete.return_value = {"success": True, "message": "User deleted"}
        resp = await client.delete("/dashboard/users/usr-test123")
        assert resp.status_code == 200
        assert "deleted" in resp.text.lower()


# ---------------------------------------------------------------------------
# Admin — API Keys
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_api_keys_page_returns_html(client):
    """GET /dashboard/api-keys should return the API keys page."""
    resp = await client.get("/dashboard/api-keys", follow_redirects=True)
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "API Keys" in resp.text


@pytest.mark.anyio
async def test_api_keys_page_shows_auth_disabled_banner(client):
    """API keys page should show info banner when auth is disabled."""
    resp = await client.get("/dashboard/api-keys", follow_redirects=True)
    assert resp.status_code == 200
    assert "Authentication is disabled" in resp.text


@pytest.mark.anyio
async def test_create_api_key_action(client):
    """POST /dashboard/api-keys should create a key and show the plaintext key."""
    with patch("dashboard.router._perform_create_api_key", new_callable=AsyncMock) as mock_create:
        mock_create.return_value = {
            "success": True,
            "message": "API key 'CI Key' created",
            "key_name": "CI Key",
            "plaintext_key": "ngx_abc123def456",
        }
        resp = await client.post(
            "/dashboard/api-keys",
            data={"name": "CI Key", "role": "operator"},
        )
        assert resp.status_code == 200
        assert "ngx_abc123def456" in resp.text
        assert "will not be shown again" in resp.text


@pytest.mark.anyio
async def test_revoke_api_key_action(client):
    """DELETE /dashboard/api-keys/{id} should return result toast."""
    with patch("dashboard.router._perform_revoke_api_key", new_callable=AsyncMock) as mock_revoke:
        mock_revoke.return_value = {"success": True, "message": "API key revoked"}
        resp = await client.delete("/dashboard/api-keys/key-test123")
        assert resp.status_code == 200
        assert "revoked" in resp.text.lower()


@pytest.mark.anyio
async def test_api_keys_page_htmx_returns_fragment(client):
    """HTMX request to /dashboard/api-keys should return just the table fragment."""
    resp = await client.get("/dashboard/api-keys", headers={"HX-Request": "true"}, follow_redirects=True)
    assert resp.status_code == 200
    assert "<!DOCTYPE" not in resp.text


# ---------------------------------------------------------------------------
# Login page
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_login_page_redirects_when_auth_disabled(client):
    """GET /dashboard/login should redirect to dashboard when auth disabled."""
    resp = await client.get("/dashboard/login", follow_redirects=False)
    assert resp.status_code == 302
    assert "/dashboard/" in resp.headers["location"]


@pytest.mark.anyio
async def test_login_post_redirects_when_auth_disabled(client):
    """POST /dashboard/login should redirect when auth disabled."""
    resp = await client.post("/dashboard/login", data={"username": "test", "password": "test"}, follow_redirects=False)
    assert resp.status_code == 302


@pytest.mark.anyio
async def test_verify_2fa_redirects_when_auth_disabled(client):
    """POST /dashboard/login/verify-2fa should redirect when auth disabled."""
    resp = await client.post(
        "/dashboard/login/verify-2fa",
        data={"challenge_token": "tok", "totp_code": "123456"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
