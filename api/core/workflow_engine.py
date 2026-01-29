"""
Workflow execution engine with checkpoint-based rollback.

Manages multi-step operations, tracking progress and providing
automatic rollback when steps fail. Each step that creates a
transaction becomes a checkpoint that can be rolled back.
"""

import asyncio
import logging
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from models.workflow import (
    WorkflowProgressEvent,
    WorkflowResponse,
    WorkflowStatus,
    WorkflowStepResult,
    WorkflowStepStatus,
    WorkflowType,
)

logger = logging.getLogger(__name__)


@dataclass
class WorkflowStep:
    """Definition of a single workflow step."""

    name: str
    description: str
    execute: Callable[..., Awaitable[dict[str, Any]]]
    is_checkpoint: bool = True
    skip_condition: Callable[[dict[str, Any]], bool] | None = None
    rollback_on_failure: bool = True


class WorkflowEngine:
    """
    Executes multi-step workflows with checkpoint-based rollback.

    Usage:
        engine = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE)
        engine.add_step(WorkflowStep(
            name="create_site",
            description="Create NGINX site configuration",
            execute=create_site_step,
            is_checkpoint=True
        ))
        result = await engine.execute(context={"name": "example.com", ...})
    """

    def __init__(
        self,
        workflow_type: WorkflowType,
        step_timeout: int = 120,
        auto_rollback: bool = True,
    ):
        self.workflow_type = workflow_type
        self.step_timeout = step_timeout
        self.auto_rollback = auto_rollback
        self.steps: list[WorkflowStep] = []
        self._progress_callbacks: list[Callable[[WorkflowProgressEvent], Awaitable[None]]] = []

    def add_step(self, step: WorkflowStep) -> None:
        """Add a step to the workflow."""
        self.steps.append(step)

    def on_progress(self, callback: Callable[[WorkflowProgressEvent], Awaitable[None]]) -> None:
        """Register a progress callback for SSE streaming."""
        self._progress_callbacks.append(callback)

    async def execute(self, context: dict[str, Any]) -> WorkflowResponse:
        """
        Execute all workflow steps in sequence.

        Args:
            context: Shared context dict passed to all steps.
                     Steps can read/write to communicate data downstream.

        Returns:
            WorkflowResponse with results from all steps.
        """
        workflow_id = f"wf-{uuid.uuid4().hex[:12]}"
        started_at = datetime.utcnow()
        step_results: list[WorkflowStepResult] = []
        checkpoint_transaction_ids: list[str] = []
        all_transaction_ids: list[str] = []
        failed_step: str | None = None

        await self._emit_progress(
            WorkflowProgressEvent(
                workflow_id=workflow_id,
                event_type="workflow_started",
                total_steps=len(self.steps),
                message=f"Starting {self.workflow_type.value} workflow ({len(self.steps)} steps)",
            )
        )

        for i, step in enumerate(self.steps):
            step_number = i + 1

            # Check skip condition
            if step.skip_condition and step.skip_condition(context):
                result = WorkflowStepResult(
                    step_name=step.name,
                    step_number=step_number,
                    status=WorkflowStepStatus.SKIPPED,
                    message=f"Step skipped: {step.description}",
                    is_checkpoint=step.is_checkpoint,
                )
                step_results.append(result)

                await self._emit_progress(
                    WorkflowProgressEvent(
                        workflow_id=workflow_id,
                        event_type="step_skipped",
                        step_name=step.name,
                        step_number=step_number,
                        total_steps=len(self.steps),
                        message=f"Step {step_number}/{len(self.steps)} skipped: {step.description}",
                    )
                )
                continue

            step_started = datetime.utcnow()

            await self._emit_progress(
                WorkflowProgressEvent(
                    workflow_id=workflow_id,
                    event_type="step_started",
                    step_name=step.name,
                    step_number=step_number,
                    total_steps=len(self.steps),
                    message=f"Step {step_number}/{len(self.steps)}: {step.description}",
                )
            )

            try:
                step_data = await asyncio.wait_for(step.execute(context), timeout=self.step_timeout)

                step_completed = datetime.utcnow()
                duration = int((step_completed - step_started).total_seconds() * 1000)

                success = step_data.get("success", True)
                txn_id = step_data.get("transaction_id")

                if txn_id:
                    all_transaction_ids.append(txn_id)
                    if step.is_checkpoint:
                        checkpoint_transaction_ids.append(txn_id)

                # Store result in context for downstream steps
                context[f"step_{step.name}_result"] = step_data

                if not success:
                    failed_step = step.name
                    step_results.append(
                        WorkflowStepResult(
                            step_name=step.name,
                            step_number=step_number,
                            status=WorkflowStepStatus.FAILED,
                            message=step_data.get("message", "Step failed"),
                            transaction_id=txn_id,
                            started_at=step_started,
                            completed_at=step_completed,
                            duration_ms=duration,
                            data=step_data,
                            error=step_data.get("message"),
                            is_checkpoint=step.is_checkpoint,
                        )
                    )

                    await self._emit_progress(
                        WorkflowProgressEvent(
                            workflow_id=workflow_id,
                            event_type="step_failed",
                            step_name=step.name,
                            step_number=step_number,
                            total_steps=len(self.steps),
                            message=f"Step failed: {step_data.get('message')}",
                        )
                    )

                    if step.rollback_on_failure:
                        break
                    else:
                        # Step failed but doesn't trigger rollback - continue
                        # Mark remaining steps with same skip group as skipped
                        continue

                step_results.append(
                    WorkflowStepResult(
                        step_name=step.name,
                        step_number=step_number,
                        status=WorkflowStepStatus.COMPLETED,
                        message=step_data.get("message", "Step completed"),
                        transaction_id=txn_id,
                        started_at=step_started,
                        completed_at=step_completed,
                        duration_ms=duration,
                        data=step_data,
                        is_checkpoint=step.is_checkpoint,
                    )
                )

                await self._emit_progress(
                    WorkflowProgressEvent(
                        workflow_id=workflow_id,
                        event_type="step_completed",
                        step_name=step.name,
                        step_number=step_number,
                        total_steps=len(self.steps),
                        message=f"Step completed: {step.description}",
                        data={"transaction_id": txn_id} if txn_id else None,
                    )
                )

            except TimeoutError:
                step_completed = datetime.utcnow()
                duration = int((step_completed - step_started).total_seconds() * 1000)
                failed_step = step.name

                step_results.append(
                    WorkflowStepResult(
                        step_name=step.name,
                        step_number=step_number,
                        status=WorkflowStepStatus.FAILED,
                        message=f"Step timed out after {self.step_timeout}s",
                        started_at=step_started,
                        completed_at=step_completed,
                        duration_ms=duration,
                        error=f"Timeout after {self.step_timeout} seconds",
                        is_checkpoint=step.is_checkpoint,
                    )
                )

                await self._emit_progress(
                    WorkflowProgressEvent(
                        workflow_id=workflow_id,
                        event_type="step_failed",
                        step_name=step.name,
                        step_number=step_number,
                        total_steps=len(self.steps),
                        message=f"Step timed out after {self.step_timeout}s",
                    )
                )

                if step.rollback_on_failure:
                    break

            except Exception as e:
                step_completed = datetime.utcnow()
                duration = int((step_completed - step_started).total_seconds() * 1000)
                failed_step = step.name

                step_results.append(
                    WorkflowStepResult(
                        step_name=step.name,
                        step_number=step_number,
                        status=WorkflowStepStatus.FAILED,
                        message=f"Step failed with exception: {e!s}",
                        started_at=step_started,
                        completed_at=step_completed,
                        duration_ms=duration,
                        error=str(e),
                        is_checkpoint=step.is_checkpoint,
                    )
                )

                await self._emit_progress(
                    WorkflowProgressEvent(
                        workflow_id=workflow_id,
                        event_type="step_failed",
                        step_name=step.name,
                        step_number=step_number,
                        total_steps=len(self.steps),
                        message=f"Step exception: {e!s}",
                    )
                )

                if step.rollback_on_failure:
                    break

        # Calculate completion stats
        completed_count = sum(1 for s in step_results if s.status == WorkflowStepStatus.COMPLETED)
        completed_at = datetime.utcnow()
        total_duration = int((completed_at - started_at).total_seconds() * 1000)

        # Handle rollback if a step failed and there are checkpoints to rollback
        rolled_back = False
        rollback_details = None

        if failed_step and self.auto_rollback and checkpoint_transaction_ids:
            # Only rollback if the failing step triggers rollback
            failing_step_obj = next((s for s in self.steps if s.name == failed_step), None)
            if failing_step_obj and failing_step_obj.rollback_on_failure:
                rolled_back, rollback_details = await self._rollback_checkpoints(
                    checkpoint_transaction_ids, reason=f"Workflow step '{failed_step}' failed"
                )
                if rolled_back:
                    for result in step_results:
                        if (
                            result.status == WorkflowStepStatus.COMPLETED
                            and result.transaction_id
                            and result.transaction_id in checkpoint_transaction_ids
                        ):
                            result.status = WorkflowStepStatus.ROLLED_BACK

        # Determine final status
        if failed_step:
            failing_step_obj = next((s for s in self.steps if s.name == failed_step), None)
            if rolled_back:
                status = WorkflowStatus.ROLLED_BACK
            elif failing_step_obj and not failing_step_obj.rollback_on_failure:
                # Non-critical failure (e.g., SSL diagnostics)
                if completed_count > 0:
                    status = WorkflowStatus.PARTIALLY_COMPLETED
                else:
                    status = WorkflowStatus.FAILED
            elif completed_count > 0:
                status = WorkflowStatus.PARTIALLY_COMPLETED
            else:
                status = WorkflowStatus.FAILED
        else:
            status = WorkflowStatus.COMPLETED

        suggestions = self._generate_suggestions(status, step_results, context)
        warnings = self._generate_warnings(step_results, context)

        response = WorkflowResponse(
            workflow_id=workflow_id,
            workflow_type=self.workflow_type,
            status=status,
            message=self._build_summary(status, completed_count, len(self.steps), failed_step),
            total_steps=len(self.steps),
            completed_steps=completed_count,
            failed_step=failed_step,
            steps=step_results,
            rolled_back=rolled_back,
            rollback_details=rollback_details,
            started_at=started_at,
            completed_at=completed_at,
            total_duration_ms=total_duration,
            transaction_ids=all_transaction_ids,
            suggestions=suggestions,
            warnings=warnings,
        )

        final_event_type = "workflow_completed" if not failed_step else "workflow_failed"
        await self._emit_progress(
            WorkflowProgressEvent(
                workflow_id=workflow_id,
                event_type=final_event_type,
                total_steps=len(self.steps),
                message=response.message,
                data={"status": status.value, "workflow_id": workflow_id},
            )
        )

        return response

    async def _rollback_checkpoints(
        self, transaction_ids: list[str], reason: str
    ) -> tuple[bool, dict[str, Any] | None]:
        """Rollback checkpoint transactions in reverse order."""
        from core.transaction_manager import get_transaction_manager

        txn_manager = get_transaction_manager()
        rollback_results = []
        all_success = True

        for txn_id in reversed(transaction_ids):
            try:
                can_rollback, _ = await txn_manager.can_rollback(txn_id)
                if can_rollback:
                    result = await txn_manager.rollback_transaction(txn_id, reason=reason)
                    rollback_results.append(
                        {"transaction_id": txn_id, "success": result.success, "message": result.message}
                    )
                    if not result.success:
                        all_success = False
                else:
                    rollback_results.append(
                        {"transaction_id": txn_id, "success": False, "message": "Cannot rollback this transaction"}
                    )
                    all_success = False
            except Exception as e:
                logger.error(f"Rollback failed for transaction {txn_id}: {e}")
                rollback_results.append(
                    {"transaction_id": txn_id, "success": False, "message": f"Rollback error: {e!s}"}
                )
                all_success = False

        return all_success, {"rollbacks": rollback_results}

    def _build_summary(self, status: WorkflowStatus, completed: int, total: int, failed_step: str | None) -> str:
        if status == WorkflowStatus.COMPLETED:
            return f"Workflow completed successfully ({completed}/{total} steps)"
        elif status == WorkflowStatus.ROLLED_BACK:
            return f"Workflow failed at step '{failed_step}' - all changes rolled back"
        elif status == WorkflowStatus.PARTIALLY_COMPLETED:
            return f"Workflow partially completed ({completed}/{total} steps) - failed at '{failed_step}'"
        else:
            return f"Workflow failed at step '{failed_step}'"

    def _generate_suggestions(
        self, status: WorkflowStatus, steps: list[WorkflowStepResult], context: dict[str, Any]
    ) -> list[dict[str, Any]]:
        suggestions = []

        if status == WorkflowStatus.COMPLETED:
            suggestions.append(
                {
                    "action": "Test the site by sending a request with the appropriate Host header",
                    "command": f"curl -H 'Host: {context.get('server_names', [''])[0]}' http://localhost/",
                    "priority": "medium",
                }
            )
            if context.get("request_ssl") and any(
                s.step_name == "request_certificate" and s.status == WorkflowStepStatus.COMPLETED for s in steps
            ):
                suggestions.append(
                    {
                        "action": "Verify SSL certificate is serving correctly",
                        "command": f"curl -vI https://{context.get('server_names', [''])[0]}/",
                        "priority": "medium",
                    }
                )
        elif status == WorkflowStatus.ROLLED_BACK:
            suggestions.append(
                {"action": "Review the failed step and fix the underlying issue before retrying", "priority": "high"}
            )
            suggestions.append({"action": "Retry the workflow after addressing the issue", "priority": "medium"})
        elif status == WorkflowStatus.PARTIALLY_COMPLETED:
            failed = next((s for s in steps if s.status == WorkflowStepStatus.FAILED), None)
            if failed and failed.step_name in ("diagnose_ssl", "request_certificate"):
                suggestions.append(
                    {
                        "action": "Site was created successfully but SSL setup failed. "
                        "Fix DNS/port issues and request the certificate separately.",
                        "priority": "high",
                    }
                )
            else:
                suggestions.append(
                    {"action": "Review the failed step and consider manual intervention", "priority": "high"}
                )
        elif status == WorkflowStatus.FAILED:
            suggestions.append({"action": "Check the error details and fix the root cause", "priority": "high"})

        return suggestions

    def _generate_warnings(self, steps: list[WorkflowStepResult], context: dict[str, Any]) -> list[dict[str, Any]]:
        warnings = []

        # Check for SSL steps that were skipped
        ssl_skipped = any(
            s.step_name in ("diagnose_ssl", "request_certificate") and s.status == WorkflowStepStatus.SKIPPED
            for s in steps
        )
        if ssl_skipped:
            warnings.append(
                {
                    "code": "ssl_skipped",
                    "message": "SSL certificate was not requested. The site is HTTP-only.",
                    "suggestion": "Request an SSL certificate to enable HTTPS.",
                }
            )

        return warnings

    async def _emit_progress(self, event: WorkflowProgressEvent) -> None:
        """Emit a progress event to all registered callbacks."""
        for callback in self._progress_callbacks:
            try:
                await callback(event)
            except Exception as e:
                logger.warning(f"Progress callback error: {e}")
