"""
Unit tests for the workflow engine.

Tests workflow execution, checkpoint rollback, skip conditions,
progress callbacks, and error handling.
"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, patch, MagicMock

from core.workflow_engine import WorkflowEngine, WorkflowStep
from models.workflow import (
    WorkflowType,
    WorkflowStatus,
    WorkflowStepStatus,
    WorkflowProgressEvent,
)


# =============================================================================
# Helper step functions for testing
# =============================================================================

async def success_step(context):
    return {"success": True, "message": "Step succeeded"}


async def success_step_with_txn(context):
    return {"success": True, "message": "Step succeeded", "transaction_id": "txn-test-123"}


async def success_step_with_txn_2(context):
    return {"success": True, "message": "Step 2 succeeded", "transaction_id": "txn-test-456"}


async def failure_step(context):
    return {"success": False, "message": "Step failed intentionally"}


async def exception_step(context):
    raise RuntimeError("Unexpected error")


async def slow_step(context):
    await asyncio.sleep(10)
    return {"success": True, "message": "Slow step done"}


async def context_writer_step(context):
    context["shared_value"] = 42
    return {"success": True, "message": "Wrote to context"}


async def context_reader_step(context):
    value = context.get("shared_value")
    return {"success": True, "message": f"Read value: {value}", "data": {"value": value}}


class TestWorkflowEngineBasic:
    """Tests for basic engine operation."""

    @pytest.mark.asyncio
    async def test_empty_workflow_completes(self):
        engine = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE)
        result = await engine.execute({})
        assert result.status == WorkflowStatus.COMPLETED
        assert result.total_steps == 0
        assert result.completed_steps == 0

    @pytest.mark.asyncio
    async def test_single_successful_step(self):
        engine = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE)
        engine.add_step(WorkflowStep(
            name="test_step",
            description="A test step",
            execute=success_step,
            is_checkpoint=False,
        ))

        result = await engine.execute({})
        assert result.status == WorkflowStatus.COMPLETED
        assert result.total_steps == 1
        assert result.completed_steps == 1
        assert len(result.steps) == 1
        assert result.steps[0].status == WorkflowStepStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_multiple_successful_steps(self):
        engine = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE)
        for i in range(3):
            engine.add_step(WorkflowStep(
                name=f"step_{i}",
                description=f"Step {i}",
                execute=success_step,
                is_checkpoint=False,
            ))

        result = await engine.execute({})
        assert result.status == WorkflowStatus.COMPLETED
        assert result.completed_steps == 3
        assert len(result.steps) == 3

    @pytest.mark.asyncio
    async def test_workflow_id_generated(self):
        engine = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE)
        engine.add_step(WorkflowStep(
            name="test", description="Test", execute=success_step, is_checkpoint=False
        ))
        result = await engine.execute({})
        assert result.workflow_id.startswith("wf-")

    @pytest.mark.asyncio
    async def test_timing_recorded(self):
        engine = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE)
        engine.add_step(WorkflowStep(
            name="test", description="Test", execute=success_step, is_checkpoint=False
        ))
        result = await engine.execute({})
        assert result.started_at is not None
        assert result.completed_at is not None
        assert result.total_duration_ms is not None
        assert result.total_duration_ms >= 0

    @pytest.mark.asyncio
    async def test_step_timing_recorded(self):
        engine = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE)
        engine.add_step(WorkflowStep(
            name="test", description="Test", execute=success_step, is_checkpoint=False
        ))
        result = await engine.execute({})
        step = result.steps[0]
        assert step.started_at is not None
        assert step.completed_at is not None
        assert step.duration_ms is not None


class TestWorkflowEngineFailure:
    """Tests for failure handling."""

    @pytest.mark.asyncio
    async def test_step_returns_failure(self):
        engine = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE)
        engine.add_step(WorkflowStep(
            name="failing", description="Fails", execute=failure_step, is_checkpoint=False
        ))

        result = await engine.execute({})
        assert result.status == WorkflowStatus.FAILED
        assert result.failed_step == "failing"
        assert result.completed_steps == 0

    @pytest.mark.asyncio
    async def test_step_raises_exception(self):
        engine = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE)
        engine.add_step(WorkflowStep(
            name="exploding", description="Explodes", execute=exception_step, is_checkpoint=False
        ))

        result = await engine.execute({})
        assert result.status == WorkflowStatus.FAILED
        assert result.failed_step == "exploding"
        assert "Unexpected error" in result.steps[0].error

    @pytest.mark.asyncio
    async def test_failure_stops_execution(self):
        engine = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE)
        engine.add_step(WorkflowStep(
            name="step1", description="Success", execute=success_step, is_checkpoint=False
        ))
        engine.add_step(WorkflowStep(
            name="step2", description="Fail", execute=failure_step, is_checkpoint=False
        ))
        engine.add_step(WorkflowStep(
            name="step3", description="Never reached", execute=success_step, is_checkpoint=False
        ))

        result = await engine.execute({})
        assert result.status == WorkflowStatus.PARTIALLY_COMPLETED
        assert result.completed_steps == 1
        assert result.failed_step == "step2"
        # step3 should not have a result since execution stopped
        assert len(result.steps) == 2

    @pytest.mark.asyncio
    async def test_timeout_causes_failure(self):
        engine = WorkflowEngine(
            workflow_type=WorkflowType.SETUP_SITE,
            step_timeout=1  # 1 second timeout
        )
        engine.add_step(WorkflowStep(
            name="slow", description="Too slow", execute=slow_step, is_checkpoint=False
        ))

        result = await engine.execute({})
        assert result.status == WorkflowStatus.FAILED
        assert result.failed_step == "slow"
        assert "timed out" in result.steps[0].message.lower()


class TestWorkflowEngineRollback:
    """Tests for checkpoint rollback."""

    @pytest.mark.asyncio
    async def test_rollback_on_failure(self):
        engine = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE, auto_rollback=True)
        engine.add_step(WorkflowStep(
            name="create", description="Create",
            execute=success_step_with_txn, is_checkpoint=True
        ))
        engine.add_step(WorkflowStep(
            name="verify", description="Verify",
            execute=failure_step, is_checkpoint=False
        ))

        with patch("core.transaction_manager.get_transaction_manager") as mock_get_tm:
            mock_tm = MagicMock()
            mock_tm.can_rollback = AsyncMock(return_value=(True, ""))
            mock_result = MagicMock()
            mock_result.success = True
            mock_result.message = "Rolled back"
            mock_tm.rollback_transaction = AsyncMock(return_value=mock_result)
            mock_get_tm.return_value = mock_tm

            result = await engine.execute({})
            assert result.status == WorkflowStatus.ROLLED_BACK
            assert result.rolled_back is True
            mock_tm.rollback_transaction.assert_called_once_with(
                "txn-test-123", reason="Workflow step 'verify' failed"
            )

    @pytest.mark.asyncio
    async def test_multiple_checkpoints_rolled_back_in_reverse(self):
        engine = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE, auto_rollback=True)
        engine.add_step(WorkflowStep(
            name="step1", description="Step 1",
            execute=success_step_with_txn, is_checkpoint=True
        ))
        engine.add_step(WorkflowStep(
            name="step2", description="Step 2",
            execute=success_step_with_txn_2, is_checkpoint=True
        ))
        engine.add_step(WorkflowStep(
            name="step3", description="Fail",
            execute=failure_step, is_checkpoint=False
        ))

        with patch("core.transaction_manager.get_transaction_manager") as mock_get_tm:
            mock_tm = MagicMock()
            mock_tm.can_rollback = AsyncMock(return_value=(True, ""))
            mock_result = MagicMock()
            mock_result.success = True
            mock_result.message = "Rolled back"
            mock_tm.rollback_transaction = AsyncMock(return_value=mock_result)
            mock_get_tm.return_value = mock_tm

            result = await engine.execute({})
            assert result.rolled_back is True
            # Should rollback in reverse: txn-test-456 first, then txn-test-123
            calls = mock_tm.rollback_transaction.call_args_list
            assert len(calls) == 2
            assert calls[0][0][0] == "txn-test-456"
            assert calls[1][0][0] == "txn-test-123"

    @pytest.mark.asyncio
    async def test_no_rollback_when_disabled(self):
        engine = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE, auto_rollback=False)
        engine.add_step(WorkflowStep(
            name="create", description="Create",
            execute=success_step_with_txn, is_checkpoint=True
        ))
        engine.add_step(WorkflowStep(
            name="verify", description="Verify",
            execute=failure_step, is_checkpoint=False
        ))

        result = await engine.execute({})
        assert result.rolled_back is False
        assert result.status == WorkflowStatus.PARTIALLY_COMPLETED

    @pytest.mark.asyncio
    async def test_no_rollback_for_non_critical_failure(self):
        engine = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE, auto_rollback=True)
        engine.add_step(WorkflowStep(
            name="create", description="Create",
            execute=success_step_with_txn, is_checkpoint=True
        ))
        engine.add_step(WorkflowStep(
            name="optional", description="Optional step",
            execute=failure_step, is_checkpoint=False, rollback_on_failure=False
        ))

        result = await engine.execute({})
        assert result.rolled_back is False
        assert result.status == WorkflowStatus.PARTIALLY_COMPLETED

    @pytest.mark.asyncio
    async def test_no_rollback_when_no_checkpoints(self):
        engine = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE, auto_rollback=True)
        engine.add_step(WorkflowStep(
            name="check", description="Check",
            execute=success_step, is_checkpoint=False
        ))
        engine.add_step(WorkflowStep(
            name="fail", description="Fail",
            execute=failure_step, is_checkpoint=False
        ))

        result = await engine.execute({})
        assert result.rolled_back is False
        assert result.status == WorkflowStatus.PARTIALLY_COMPLETED


class TestWorkflowEngineSkipCondition:
    """Tests for step skip conditions."""

    @pytest.mark.asyncio
    async def test_skip_condition_skips_step(self):
        engine = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE)
        engine.add_step(WorkflowStep(
            name="always_run", description="Always runs",
            execute=success_step, is_checkpoint=False
        ))
        engine.add_step(WorkflowStep(
            name="conditional", description="Conditional",
            execute=success_step, is_checkpoint=False,
            skip_condition=lambda ctx: True  # Always skip
        ))

        result = await engine.execute({})
        assert result.completed_steps == 1
        assert len(result.steps) == 2
        assert result.steps[0].status == WorkflowStepStatus.COMPLETED
        assert result.steps[1].status == WorkflowStepStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skip_condition_based_on_context(self):
        engine = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE)
        engine.add_step(WorkflowStep(
            name="step1", description="Step 1",
            execute=success_step, is_checkpoint=False
        ))
        engine.add_step(WorkflowStep(
            name="ssl_step", description="SSL step",
            execute=success_step, is_checkpoint=False,
            skip_condition=lambda ctx: not ctx.get("request_ssl", False)
        ))

        result = await engine.execute({"request_ssl": False})
        assert result.steps[1].status == WorkflowStepStatus.SKIPPED

        engine2 = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE)
        engine2.add_step(WorkflowStep(
            name="step1", description="Step 1",
            execute=success_step, is_checkpoint=False
        ))
        engine2.add_step(WorkflowStep(
            name="ssl_step", description="SSL step",
            execute=success_step, is_checkpoint=False,
            skip_condition=lambda ctx: not ctx.get("request_ssl", False)
        ))
        result2 = await engine2.execute({"request_ssl": True})
        assert result2.steps[1].status == WorkflowStepStatus.COMPLETED


class TestWorkflowEngineContext:
    """Tests for context passing between steps."""

    @pytest.mark.asyncio
    async def test_context_shared_between_steps(self):
        engine = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE)
        engine.add_step(WorkflowStep(
            name="writer", description="Write to context",
            execute=context_writer_step, is_checkpoint=False
        ))
        engine.add_step(WorkflowStep(
            name="reader", description="Read from context",
            execute=context_reader_step, is_checkpoint=False
        ))

        result = await engine.execute({})
        assert result.status == WorkflowStatus.COMPLETED
        # The reader step should have read the value 42
        reader_data = result.steps[1].data
        assert reader_data is not None
        assert reader_data.get("data", {}).get("value") == 42

    @pytest.mark.asyncio
    async def test_step_results_stored_in_context(self):
        engine = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE)
        engine.add_step(WorkflowStep(
            name="first", description="First",
            execute=success_step, is_checkpoint=False
        ))

        context = {}
        await engine.execute(context)
        assert "step_first_result" in context
        assert context["step_first_result"]["success"] is True

    @pytest.mark.asyncio
    async def test_transaction_ids_collected(self):
        engine = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE)
        engine.add_step(WorkflowStep(
            name="step1", description="Step 1",
            execute=success_step_with_txn, is_checkpoint=True
        ))
        engine.add_step(WorkflowStep(
            name="step2", description="Step 2",
            execute=success_step_with_txn_2, is_checkpoint=True
        ))

        result = await engine.execute({})
        assert result.transaction_ids == ["txn-test-123", "txn-test-456"]


class TestWorkflowEngineProgress:
    """Tests for progress callback mechanism."""

    @pytest.mark.asyncio
    async def test_progress_callbacks_invoked(self):
        engine = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE)
        engine.add_step(WorkflowStep(
            name="test", description="Test", execute=success_step, is_checkpoint=False
        ))

        events = []

        async def capture_event(event: WorkflowProgressEvent):
            events.append(event)

        engine.on_progress(capture_event)
        await engine.execute({})

        # Should have: workflow_started, step_started, step_completed, workflow_completed
        event_types = [e.event_type for e in events]
        assert "workflow_started" in event_types
        assert "step_started" in event_types
        assert "step_completed" in event_types
        assert "workflow_completed" in event_types

    @pytest.mark.asyncio
    async def test_progress_callback_error_doesnt_break_workflow(self):
        engine = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE)
        engine.add_step(WorkflowStep(
            name="test", description="Test", execute=success_step, is_checkpoint=False
        ))

        async def broken_callback(event):
            raise RuntimeError("Callback broke")

        engine.on_progress(broken_callback)
        result = await engine.execute({})
        assert result.status == WorkflowStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_failure_emits_workflow_failed(self):
        engine = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE)
        engine.add_step(WorkflowStep(
            name="fail", description="Fail", execute=failure_step, is_checkpoint=False
        ))

        events = []

        async def capture_event(event):
            events.append(event)

        engine.on_progress(capture_event)
        await engine.execute({})

        event_types = [e.event_type for e in events]
        assert "workflow_failed" in event_types
        assert "step_failed" in event_types


class TestWorkflowEngineSuggestions:
    """Tests for suggestion and warning generation."""

    @pytest.mark.asyncio
    async def test_completed_workflow_has_suggestions(self):
        engine = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE)
        engine.add_step(WorkflowStep(
            name="test", description="Test", execute=success_step, is_checkpoint=False
        ))

        result = await engine.execute({"name": "test.com", "server_names": ["test.com"]})
        assert len(result.suggestions) > 0

    @pytest.mark.asyncio
    async def test_failed_workflow_has_suggestions(self):
        engine = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE, auto_rollback=False)
        engine.add_step(WorkflowStep(
            name="fail", description="Fail", execute=failure_step, is_checkpoint=False
        ))

        result = await engine.execute({})
        assert len(result.suggestions) > 0

    @pytest.mark.asyncio
    async def test_summary_message_format(self):
        engine = WorkflowEngine(workflow_type=WorkflowType.SETUP_SITE)
        engine.add_step(WorkflowStep(
            name="s1", description="S1", execute=success_step, is_checkpoint=False
        ))
        engine.add_step(WorkflowStep(
            name="s2", description="S2", execute=success_step, is_checkpoint=False
        ))

        result = await engine.execute({})
        assert "2/2" in result.message
        assert "completed successfully" in result.message.lower()
