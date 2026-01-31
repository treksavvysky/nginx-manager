"""
NGINX Manager Web Dashboard.

Server-rendered dashboard using HTMX + Alpine.js + Jinja2.
Provides a web UI for site management, calling the same
business logic as the REST API.
"""

from pathlib import Path

from fastapi import APIRouter
from fastapi.templating import Jinja2Templates

DASHBOARD_DIR = Path(__file__).parent
TEMPLATES_DIR = DASHBOARD_DIR / "templates"
STATIC_DIR = DASHBOARD_DIR / "static"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def create_dashboard_router() -> APIRouter:
    """Create and return the dashboard router with all view routes."""
    from dashboard.router import router

    return router
