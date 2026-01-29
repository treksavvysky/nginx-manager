"""
Agent workflow endpoints.

Compound operations that orchestrate multiple steps with
checkpoint-based execution and automatic rollback on failure.
"""

import asyncio
import json
import logging
from typing import Union

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse

from models.workflow import (
    SetupSiteRequest,
    MigrateSiteRequest,
    WorkflowResponse,
    WorkflowDryRunResponse,
    WorkflowType,
    WorkflowProgressEvent,
)
from core.workflow_definitions import (
    build_setup_site_workflow,
    build_migrate_site_workflow,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/workflows", tags=["Agent Workflows"])


@router.post(
    "/setup-site",
    response_model=Union[WorkflowResponse, WorkflowDryRunResponse],
    status_code=200,
    summary="Setup Complete Site",
    description="""
    Compound workflow: Create site + optional SSL certificate + verify.

    **Steps:**
    1. Check prerequisites (NGINX running, name available)
    2. Create site configuration (checkpoint)
    3. Verify NGINX config is valid
    4. (If request_ssl=true) Diagnose SSL prerequisites
    5. (If request_ssl=true) Request Let's Encrypt certificate (checkpoint)
    6. (If request_ssl=true) Verify SSL installation

    **Rollback:** If site creation or verification fails, all checkpoint
    steps are automatically rolled back. SSL failures do NOT rollback
    the site creation - the site remains usable over HTTP.

    **Dry Run:** Use `?dry_run=true` to preview all steps without executing.

    **Streaming:** Use `?stream=true` to receive Server-Sent Events
    with real-time progress updates for each step.
    """,
    responses={
        200: {"description": "Workflow completed (or dry-run preview)"},
        400: {"description": "Invalid request parameters"},
        422: {"description": "Validation error"},
    }
)
async def setup_site(
    request: SetupSiteRequest,
    dry_run: bool = Query(default=False, description="Preview workflow without executing"),
    stream: bool = Query(default=False, description="Stream progress via Server-Sent Events"),
):
    """Execute the setup-site workflow."""
    context = request.model_dump()

    if dry_run:
        return _dry_run_setup_site(context)

    engine = build_setup_site_workflow(context)

    if stream:
        return _stream_workflow(engine, context)

    result = await engine.execute(context)
    return result


@router.post(
    "/migrate-site",
    response_model=Union[WorkflowResponse, WorkflowDryRunResponse],
    status_code=200,
    summary="Migrate/Update Site Safely",
    description="""
    Compound workflow: Verify + update + validate with automatic rollback.

    **Steps:**
    1. Verify site exists
    2. Update site configuration (checkpoint)
    3. Validate NGINX configuration after update

    **Rollback:** If config validation fails after the update, the change
    is automatically rolled back to the previous working state.

    **Dry Run:** Use `?dry_run=true` to preview what would change.

    **Streaming:** Use `?stream=true` for real-time progress via SSE.
    """,
    responses={
        200: {"description": "Workflow completed (or dry-run preview)"},
        400: {"description": "Invalid request parameters"},
        422: {"description": "Validation error"},
    }
)
async def migrate_site(
    request: MigrateSiteRequest,
    dry_run: bool = Query(default=False, description="Preview workflow without executing"),
    stream: bool = Query(default=False, description="Stream progress via Server-Sent Events"),
):
    """Execute the migrate-site workflow."""
    context = request.model_dump()

    if dry_run:
        return _dry_run_migrate_site(context)

    engine = build_migrate_site_workflow(context)

    if stream:
        return _stream_workflow(engine, context)

    result = await engine.execute(context)
    return result


# =============================================================================
# Dry-Run Helpers
# =============================================================================

def _dry_run_setup_site(context: dict) -> WorkflowDryRunResponse:
    """Preview setup-site workflow steps."""
    request_ssl = context.get("request_ssl", False)

    steps = [
        {"step": 1, "name": "check_prerequisites", "action": "Check NGINX is running and site name is available"},
        {"step": 2, "name": "create_site", "action": f"Create {context.get('site_type', 'static')} site '{context['name']}'", "is_checkpoint": True},
        {"step": 3, "name": "verify_site", "action": "Verify NGINX config is valid after creation"},
    ]

    if request_ssl:
        domain = context["server_names"][0] if context.get("server_names") else context["name"]
        steps.extend([
            {"step": 4, "name": "diagnose_ssl", "action": f"Check DNS/port prerequisites for {domain}"},
            {"step": 5, "name": "request_certificate", "action": f"Request Let's Encrypt certificate for {domain}", "is_checkpoint": True},
            {"step": 6, "name": "verify_ssl", "action": "Verify SSL installation and config validity"},
        ])

    return WorkflowDryRunResponse(
        workflow_type=WorkflowType.SETUP_SITE,
        would_succeed=True,
        message=f"Would execute {len(steps)} steps to setup site '{context['name']}'",
        steps=steps,
        warnings=[] if request_ssl else [
            {"code": "no_ssl", "message": "SSL not requested. Site will be HTTP-only."}
        ],
        prerequisites_met=True,
        missing_prerequisites=[]
    )


def _dry_run_migrate_site(context: dict) -> WorkflowDryRunResponse:
    """Preview migrate-site workflow steps."""
    changes = []
    if context.get("server_names"):
        changes.append(f"server_names -> {context['server_names']}")
    if context.get("listen_port"):
        changes.append(f"listen_port -> {context['listen_port']}")
    if context.get("root_path"):
        changes.append(f"root_path -> {context['root_path']}")
    if context.get("proxy_pass"):
        changes.append(f"proxy_pass -> {context['proxy_pass']}")

    steps = [
        {"step": 1, "name": "verify_exists", "action": f"Verify site '{context['name']}' exists"},
        {"step": 2, "name": "update_site", "action": f"Update configuration: {', '.join(changes) or 'no changes specified'}", "is_checkpoint": True},
        {"step": 3, "name": "test_config", "action": "Validate NGINX config after update"},
    ]

    warnings = []
    if not changes:
        warnings.append({"code": "no_changes", "message": "No update fields specified. Nothing would change."})

    return WorkflowDryRunResponse(
        workflow_type=WorkflowType.MIGRATE_SITE,
        would_succeed=bool(changes),
        message=f"Would execute {len(steps)} steps to migrate site '{context['name']}'",
        steps=steps,
        warnings=warnings,
        prerequisites_met=True,
        missing_prerequisites=[]
    )


# =============================================================================
# SSE Streaming
# =============================================================================

def _stream_workflow(engine, context: dict) -> StreamingResponse:
    """Create an SSE streaming response for workflow progress."""

    async def event_generator():
        progress_queue: asyncio.Queue[WorkflowProgressEvent] = asyncio.Queue()

        async def progress_callback(event: WorkflowProgressEvent):
            await progress_queue.put(event)

        engine.on_progress(progress_callback)

        # Run workflow in background task
        task = asyncio.create_task(engine.execute(context))

        while not task.done():
            try:
                event = await asyncio.wait_for(progress_queue.get(), timeout=1.0)
                yield f"event: {event.event_type}\ndata: {json.dumps(event.model_dump(), default=str)}\n\n"
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"

        # Drain remaining events
        while not progress_queue.empty():
            event = progress_queue.get_nowait()
            yield f"event: {event.event_type}\ndata: {json.dumps(event.model_dump(), default=str)}\n\n"

        # Send final result
        result = await task
        yield f"event: result\ndata: {json.dumps(result.model_dump(), default=str)}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )
