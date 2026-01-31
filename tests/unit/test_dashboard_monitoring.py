"""
Dashboard monitoring page tests.

Tests that monitoring pages (health, certificates, events, transactions)
render correctly and return proper HTML responses.
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
# Health page
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_health_page_returns_html(client):
    """GET /dashboard/health should return the health dashboard page."""
    resp = await client.get("/dashboard/health", follow_redirects=True)
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "System Health" in resp.text


@pytest.mark.anyio
async def test_health_page_htmx_returns_fragment(client):
    """HTMX request to /dashboard/health should return just the cards fragment."""
    resp = await client.get("/dashboard/health", headers={"HX-Request": "true"}, follow_redirects=True)
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    # Fragment should not include full HTML boilerplate
    assert "<!DOCTYPE" not in resp.text


@pytest.mark.anyio
async def test_health_cards_fragment(client):
    """GET /dashboard/fragments/health-cards should return health cards HTML."""
    resp = await client.get("/dashboard/fragments/health-cards")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "NGINX" in resp.text


@pytest.mark.anyio
async def test_health_page_contains_card_sections(client):
    """Health page should contain the expected card sections."""
    resp = await client.get("/dashboard/health", follow_redirects=True)
    assert resp.status_code == 200
    assert "NGINX Status" in resp.text
    assert "Sites" in resp.text
    assert "SSL Certificates" in resp.text
    assert "Security" in resp.text


# ---------------------------------------------------------------------------
# Certificates page
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_certificates_page_returns_html(client):
    """GET /dashboard/certificates should return the certificates page."""
    resp = await client.get("/dashboard/certificates", follow_redirects=True)
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "SSL Certificates" in resp.text


@pytest.mark.anyio
async def test_certificates_page_htmx_returns_fragment(client):
    """HTMX request to /dashboard/certificates should return fragment."""
    resp = await client.get("/dashboard/certificates", headers={"HX-Request": "true"}, follow_redirects=True)
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.anyio
async def test_certificates_page_handles_empty(client):
    """Certificates page should handle no certificates gracefully."""
    resp = await client.get("/dashboard/certificates", follow_redirects=True)
    assert resp.status_code == 200
    # Should show either the table or the empty state
    assert "No certificates" in resp.text or "table" in resp.text


# ---------------------------------------------------------------------------
# Events page
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_events_page_returns_html(client):
    """GET /dashboard/events should return the events page."""
    resp = await client.get("/dashboard/events", follow_redirects=True)
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "Event Log" in resp.text


@pytest.mark.anyio
async def test_events_page_htmx_returns_fragment(client):
    """HTMX request to /dashboard/events should return fragment."""
    resp = await client.get("/dashboard/events", headers={"HX-Request": "true"}, follow_redirects=True)
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.anyio
async def test_events_page_severity_filter(client):
    """Events page should accept severity filter parameter."""
    resp = await client.get("/dashboard/events?severity=error", follow_redirects=True)
    assert resp.status_code == 200
    assert "Event Log" in resp.text


@pytest.mark.anyio
async def test_events_page_category_filter(client):
    """Events page should accept category filter parameter."""
    resp = await client.get("/dashboard/events?category=transaction", follow_redirects=True)
    assert resp.status_code == 200
    assert "Event Log" in resp.text


# ---------------------------------------------------------------------------
# Transactions page
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_transactions_page_returns_html(client):
    """GET /dashboard/transactions should return the transactions page."""
    resp = await client.get("/dashboard/transactions", follow_redirects=True)
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "Transaction History" in resp.text


@pytest.mark.anyio
async def test_transactions_page_htmx_returns_fragment(client):
    """HTMX request to /dashboard/transactions should return fragment."""
    resp = await client.get("/dashboard/transactions", headers={"HX-Request": "true"}, follow_redirects=True)
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.anyio
async def test_transactions_page_status_filter(client):
    """Transactions page should accept status filter parameter."""
    resp = await client.get("/dashboard/transactions?status=completed", follow_redirects=True)
    assert resp.status_code == 200
    assert "Transaction History" in resp.text


@pytest.mark.anyio
async def test_transaction_detail_not_found(client):
    """Transaction detail for nonexistent ID should return not found message."""
    resp = await client.get("/dashboard/transactions/nonexistent-id/detail")
    assert resp.status_code == 200
    assert "not found" in resp.text.lower()


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_rollback_returns_toast(client):
    """POST rollback should return a toast fragment."""
    resp = await client.post("/dashboard/transactions/nonexistent-id/rollback")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    # Should be an error toast since the transaction doesn't exist
    assert "toast" in resp.text


@pytest.mark.anyio
async def test_rollback_nonexistent_transaction(client):
    """Rollback of nonexistent transaction should show error."""
    resp = await client.post("/dashboard/transactions/bad-id/rollback")
    assert resp.status_code == 200
    assert "error" in resp.text.lower() or "failed" in resp.text.lower()


# ---------------------------------------------------------------------------
# Navigation
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_nav_contains_monitoring_links(client):
    """Dashboard pages should include monitoring navigation links."""
    resp = await client.get("/dashboard/health", follow_redirects=True)
    assert resp.status_code == 200
    assert "/dashboard/health" in resp.text
    assert "/dashboard/certificates" in resp.text
    assert "/dashboard/events" in resp.text
    assert "/dashboard/transactions" in resp.text
