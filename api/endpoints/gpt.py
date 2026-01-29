"""
GPT integration endpoints.

Provides a Custom GPT-compatible OpenAPI schema and
system instruction template for configuring a GPT.
"""

from pathlib import Path

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from core.gpt_schema import generate_gpt_schema

router = APIRouter(prefix="/gpt", tags=["GPT Integration"])


@router.get(
    "/openapi.json",
    summary="GPT-Compatible OpenAPI Schema",
    description="Returns an OpenAPI 3.1 schema optimized for OpenAI Custom GPT Actions.",
    response_class=JSONResponse,
    include_in_schema=False
)
async def gpt_openapi_schema(
    request: Request,
    server_url: str = Query(
        default=None,
        description=(
            "The public HTTPS URL where GPT will reach this API. "
            "Must match the origin configured in your Custom GPT. "
            "Example: https://yourdomain.com:8000"
        )
    ),
):
    """Generate GPT-compatible OpenAPI schema."""
    app = request.app
    raw_schema = app.openapi()

    if not server_url:
        # Build from request, preferring HTTPS and respecting
        # X-Forwarded-Proto/Host headers set by reverse proxies.
        proto = request.headers.get("x-forwarded-proto", request.url.scheme)
        host = request.headers.get("x-forwarded-host", request.url.netloc)
        server_url = f"{proto}://{host}".rstrip("/")

    gpt_schema = generate_gpt_schema(
        openapi_schema=raw_schema,
        server_url=server_url,
        include_tags=[
            "Site Configuration",
            "NGINX Control",
            "SSL Certificates",
            "Agent Workflows",
        ]
    )

    return JSONResponse(content=gpt_schema)


@router.get(
    "/instructions",
    summary="GPT System Instructions",
    description="Returns the system instruction template for configuring a Custom GPT.",
    response_class=PlainTextResponse,
    include_in_schema=False
)
async def gpt_instructions():
    """Return GPT system instruction template."""
    instructions_path = Path(__file__).parent.parent / "gpt" / "instructions.md"
    if instructions_path.exists():
        return PlainTextResponse(content=instructions_path.read_text())
    return PlainTextResponse(
        content="# Instructions file not found\n\nPlease create api/gpt/instructions.md",
        status_code=404
    )
