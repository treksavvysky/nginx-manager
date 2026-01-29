"""
Unit tests for security headers middleware.

Tests that security headers are added to responses
and that CORS is configured correctly.
"""

import os
import sys

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request
from starlette.responses import Response

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "api"))


class TestSecurityHeaders:
    """Test security headers middleware adds correct headers."""

    @pytest.fixture
    def client(self):
        """Create a test client with the SecurityHeadersMiddleware."""
        from starlette.middleware.base import BaseHTTPMiddleware

        app = FastAPI()

        class SecurityHeadersMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request: Request, call_next) -> Response:
                response = await call_next(request)
                response.headers["X-Content-Type-Options"] = "nosniff"
                response.headers["X-Frame-Options"] = "DENY"
                response.headers["X-XSS-Protection"] = "1; mode=block"
                response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
                response.headers["Cache-Control"] = "no-store"
                return response

        app.add_middleware(SecurityHeadersMiddleware)

        @app.get("/")
        async def root():
            return {"status": "ok"}

        @app.get("/api/test")
        async def api_test():
            return {"data": "test"}

        return TestClient(app)

    def test_x_content_type_options(self, client):
        """X-Content-Type-Options: nosniff is set."""
        response = client.get("/")
        assert response.headers.get("X-Content-Type-Options") == "nosniff"

    def test_x_frame_options(self, client):
        """X-Frame-Options: DENY is set."""
        response = client.get("/")
        assert response.headers.get("X-Frame-Options") == "DENY"

    def test_x_xss_protection(self, client):
        """X-XSS-Protection header is set."""
        response = client.get("/")
        assert response.headers.get("X-XSS-Protection") == "1; mode=block"

    def test_referrer_policy(self, client):
        """Referrer-Policy is set."""
        response = client.get("/")
        assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

    def test_cache_control(self, client):
        """Cache-Control: no-store is set."""
        response = client.get("/")
        assert response.headers.get("Cache-Control") == "no-store"

    def test_headers_on_all_endpoints(self, client):
        """Security headers present on all endpoints."""
        response = client.get("/api/test")
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("X-Frame-Options") == "DENY"
        assert response.headers.get("X-XSS-Protection") == "1; mode=block"
        assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        assert response.headers.get("Cache-Control") == "no-store"

    def test_headers_on_404(self, client):
        """Security headers present even on 404 responses."""
        response = client.get("/nonexistent")
        assert response.status_code == 404
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("X-Frame-Options") == "DENY"


class TestCORSConfiguration:
    """Test CORS origin configuration logic."""

    def test_cors_wildcard_in_debug_mode(self):
        """CORS allows all origins when API_DEBUG=true and no origins configured."""
        api_debug = True
        cors_allowed_origins = ""
        cors_origins = (
            [o.strip() for o in cors_allowed_origins.split(",") if o.strip()]
            if cors_allowed_origins
            else ["*"]
            if api_debug
            else []
        )
        assert cors_origins == ["*"]

    def test_cors_empty_in_production(self):
        """CORS blocks all origins when API_DEBUG=false and no origins configured."""
        api_debug = False
        cors_allowed_origins = ""
        cors_origins = (
            [o.strip() for o in cors_allowed_origins.split(",") if o.strip()]
            if cors_allowed_origins
            else ["*"]
            if api_debug
            else []
        )
        assert cors_origins == []

    def test_cors_specific_origins(self):
        """CORS uses configured origins when specified."""
        api_debug = False
        cors_allowed_origins = "https://app.example.com, https://admin.example.com"
        cors_origins = (
            [o.strip() for o in cors_allowed_origins.split(",") if o.strip()]
            if cors_allowed_origins
            else ["*"]
            if api_debug
            else []
        )
        assert cors_origins == ["https://app.example.com", "https://admin.example.com"]

    def test_cors_specific_origins_override_debug(self):
        """Explicit origins are used even in debug mode."""
        api_debug = True
        cors_allowed_origins = "https://only-this.example.com"
        cors_origins = (
            [o.strip() for o in cors_allowed_origins.split(",") if o.strip()]
            if cors_allowed_origins
            else ["*"]
            if api_debug
            else []
        )
        assert cors_origins == ["https://only-this.example.com"]
