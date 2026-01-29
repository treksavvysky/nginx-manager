"""
Unit tests for workflow models.
"""

import pytest
from pydantic import ValidationError

from models.transaction import OperationType
from models.workflow import (
    MigrateSiteRequest,
    SetupSiteRequest,
    WorkflowDryRunResponse,
    WorkflowProgressEvent,
    WorkflowResponse,
    WorkflowStatus,
    WorkflowStepResult,
    WorkflowStepStatus,
    WorkflowType,
)


class TestWorkflowEnums:
    """Tests for workflow enum types."""

    def test_workflow_type_values(self):
        assert WorkflowType.SETUP_SITE.value == "setup_site"
        assert WorkflowType.MIGRATE_SITE.value == "migrate_site"

    def test_workflow_status_values(self):
        assert WorkflowStatus.PENDING.value == "pending"
        assert WorkflowStatus.IN_PROGRESS.value == "in_progress"
        assert WorkflowStatus.COMPLETED.value == "completed"
        assert WorkflowStatus.PARTIALLY_COMPLETED.value == "partially_completed"
        assert WorkflowStatus.FAILED.value == "failed"
        assert WorkflowStatus.ROLLED_BACK.value == "rolled_back"

    def test_workflow_step_status_values(self):
        assert WorkflowStepStatus.PENDING.value == "pending"
        assert WorkflowStepStatus.IN_PROGRESS.value == "in_progress"
        assert WorkflowStepStatus.COMPLETED.value == "completed"
        assert WorkflowStepStatus.FAILED.value == "failed"
        assert WorkflowStepStatus.SKIPPED.value == "skipped"
        assert WorkflowStepStatus.ROLLED_BACK.value == "rolled_back"

    def test_operation_type_includes_workflow(self):
        assert OperationType.WORKFLOW_EXECUTE.value == "workflow_execute"


class TestSetupSiteRequest:
    """Tests for SetupSiteRequest validation."""

    def test_valid_static_site(self):
        req = SetupSiteRequest(
            name="example.com", server_names=["example.com"], site_type="static", root_path="/var/www/example"
        )
        assert req.name == "example.com"
        assert req.site_type == "static"
        assert req.request_ssl is False

    def test_valid_reverse_proxy(self):
        req = SetupSiteRequest(
            name="api.example.com",
            server_names=["api.example.com"],
            site_type="reverse_proxy",
            proxy_pass="http://localhost:3000",
        )
        assert req.proxy_pass == "http://localhost:3000"

    def test_valid_with_ssl(self):
        req = SetupSiteRequest(
            name="secure.com",
            server_names=["secure.com", "www.secure.com"],
            site_type="static",
            root_path="/var/www/secure",
            request_ssl=True,
            ssl_alt_names=["www.secure.com"],
            auto_renew=True,
        )
        assert req.request_ssl is True
        assert req.ssl_alt_names == ["www.secure.com"]

    def test_invalid_name_with_path_traversal(self):
        with pytest.raises(ValidationError):
            SetupSiteRequest(
                name="../etc/passwd", server_names=["evil.com"], site_type="static", root_path="/var/www/test"
            )

    def test_invalid_name_special_chars(self):
        with pytest.raises(ValidationError):
            SetupSiteRequest(
                name="site with spaces", server_names=["test.com"], site_type="static", root_path="/var/www/test"
            )

    def test_invalid_site_type(self):
        with pytest.raises(ValidationError):
            SetupSiteRequest(
                name="test.com", server_names=["test.com"], site_type="invalid_type", root_path="/var/www/test"
            )

    def test_static_requires_root_path(self):
        with pytest.raises(ValidationError):
            SetupSiteRequest(name="test.com", server_names=["test.com"], site_type="static")

    def test_reverse_proxy_requires_proxy_pass(self):
        with pytest.raises(ValidationError):
            SetupSiteRequest(name="test.com", server_names=["test.com"], site_type="reverse_proxy")

    def test_invalid_proxy_pass_scheme(self):
        with pytest.raises(ValidationError):
            SetupSiteRequest(
                name="test.com", server_names=["test.com"], site_type="reverse_proxy", proxy_pass="ftp://localhost:3000"
            )

    def test_invalid_root_path_relative(self):
        with pytest.raises(ValidationError):
            SetupSiteRequest(name="test.com", server_names=["test.com"], site_type="static", root_path="relative/path")

    def test_server_names_normalized(self):
        req = SetupSiteRequest(
            name="test.com",
            server_names=["  TEST.COM  ", "  WWW.TEST.COM  "],
            site_type="static",
            root_path="/var/www/test",
        )
        assert req.server_names == ["test.com", "www.test.com"]

    def test_empty_server_names_rejected(self):
        with pytest.raises(ValidationError):
            SetupSiteRequest(name="test.com", server_names=[], site_type="static", root_path="/var/www/test")


class TestMigrateSiteRequest:
    """Tests for MigrateSiteRequest validation."""

    def test_valid_request(self):
        req = MigrateSiteRequest(name="example.com", server_names=["new.example.com"], listen_port=8080)
        assert req.name == "example.com"
        assert req.server_names == ["new.example.com"]
        assert req.listen_port == 8080

    def test_minimal_request(self):
        req = MigrateSiteRequest(name="example.com")
        assert req.server_names is None
        assert req.listen_port is None
        assert req.root_path is None
        assert req.proxy_pass is None

    def test_invalid_name(self):
        with pytest.raises(ValidationError):
            MigrateSiteRequest(name="../../etc")

    def test_invalid_proxy_pass(self):
        with pytest.raises(ValidationError):
            MigrateSiteRequest(name="test.com", proxy_pass="not-a-url")


class TestWorkflowStepResult:
    """Tests for WorkflowStepResult model."""

    def test_basic_creation(self):
        result = WorkflowStepResult(
            step_name="create_site",
            step_number=1,
            status=WorkflowStepStatus.COMPLETED,
            message="Site created successfully",
        )
        assert result.step_name == "create_site"
        assert result.step_number == 1
        assert result.status == WorkflowStepStatus.COMPLETED
        assert result.transaction_id is None
        assert result.is_checkpoint is False

    def test_checkpoint_step(self):
        result = WorkflowStepResult(
            step_name="create_site",
            step_number=2,
            status=WorkflowStepStatus.COMPLETED,
            message="Site created",
            transaction_id="txn-123",
            is_checkpoint=True,
            duration_ms=150,
        )
        assert result.transaction_id == "txn-123"
        assert result.is_checkpoint is True
        assert result.duration_ms == 150

    def test_failed_step(self):
        result = WorkflowStepResult(
            step_name="verify_site",
            step_number=3,
            status=WorkflowStepStatus.FAILED,
            message="Verification failed",
            error="nginx -t returned errors",
        )
        assert result.status == WorkflowStepStatus.FAILED
        assert result.error == "nginx -t returned errors"


class TestWorkflowResponse:
    """Tests for WorkflowResponse model."""

    def test_successful_workflow(self):
        response = WorkflowResponse(
            workflow_type=WorkflowType.SETUP_SITE,
            status=WorkflowStatus.COMPLETED,
            message="Workflow completed successfully (3/3 steps)",
            total_steps=3,
            completed_steps=3,
            transaction_ids=["txn-1", "txn-2"],
        )
        assert response.workflow_id.startswith("wf-")
        assert response.status == WorkflowStatus.COMPLETED
        assert response.rolled_back is False
        assert len(response.transaction_ids) == 2

    def test_failed_workflow(self):
        response = WorkflowResponse(
            workflow_type=WorkflowType.MIGRATE_SITE,
            status=WorkflowStatus.ROLLED_BACK,
            message="Workflow failed",
            total_steps=3,
            completed_steps=1,
            failed_step="test_config",
            rolled_back=True,
            rollback_details={"rollbacks": [{"transaction_id": "txn-1", "success": True}]},
        )
        assert response.status == WorkflowStatus.ROLLED_BACK
        assert response.failed_step == "test_config"
        assert response.rolled_back is True

    def test_serialization(self):
        response = WorkflowResponse(
            workflow_type=WorkflowType.SETUP_SITE,
            status=WorkflowStatus.COMPLETED,
            message="Done",
            total_steps=3,
            completed_steps=3,
            suggestions=[{"action": "test site", "priority": "medium"}],
            warnings=[{"code": "no_ssl", "message": "No SSL"}],
        )
        data = response.model_dump()
        assert "workflow_id" in data
        assert data["workflow_type"] == "setup_site"
        assert data["status"] == "completed"
        assert len(data["suggestions"]) == 1
        assert len(data["warnings"]) == 1


class TestWorkflowDryRunResponse:
    """Tests for WorkflowDryRunResponse model."""

    def test_dry_run_response(self):
        response = WorkflowDryRunResponse(
            workflow_type=WorkflowType.SETUP_SITE,
            would_succeed=True,
            message="Would execute 3 steps",
            steps=[
                {"step": 1, "name": "check_prerequisites", "action": "Check NGINX"},
                {"step": 2, "name": "create_site", "action": "Create site", "is_checkpoint": True},
                {"step": 3, "name": "verify_site", "action": "Verify"},
            ],
        )
        assert response.dry_run is True
        assert response.would_succeed is True
        assert len(response.steps) == 3
        assert response.prerequisites_met is True


class TestWorkflowProgressEvent:
    """Tests for WorkflowProgressEvent model."""

    def test_progress_event(self):
        event = WorkflowProgressEvent(
            workflow_id="wf-abc123",
            event_type="step_completed",
            step_name="create_site",
            step_number=2,
            total_steps=3,
            message="Step completed: Create site",
        )
        assert event.workflow_id == "wf-abc123"
        assert event.event_type == "step_completed"
        assert event.step_number == 2

    def test_serialization(self):
        event = WorkflowProgressEvent(
            workflow_id="wf-abc123", event_type="workflow_started", total_steps=3, message="Starting workflow"
        )
        data = event.model_dump()
        assert data["workflow_id"] == "wf-abc123"
        assert data["event_type"] == "workflow_started"
        assert data["step_name"] is None
