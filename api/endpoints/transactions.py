"""
Transaction management endpoints.

Provides access to transaction history, details, and rollback
operations for configuration changes.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Query

from core.auth_dependency import require_role
from core.transaction_manager import get_transaction_manager
from models.auth import AuthContext, Role
from models.transaction import (
    OperationType,
    RollbackRequest,
    RollbackResult,
    TransactionDetail,
    TransactionListResponse,
    TransactionStatus,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/transactions", tags=["Transactions & Rollback"])


@router.get(
    "/",
    response_model=TransactionListResponse,
    summary="List Transactions",
    description="""
List all transactions with optional filtering.

Transactions represent atomic configuration changes. Each transaction
captures before/after state, enabling rollback if needed.

**AI Agent Usage:**
- Review recent changes before making modifications
- Find transaction ID for rollback operations
- Verify transaction status after operations

**Filtering Options:**
- `status`: Filter by transaction status
- `operation`: Filter by operation type
- `resource_type`: Filter by resource type

**Pagination:**
- Use `limit` and `offset` for pagination
- Default 50 transactions per page
""",
)
async def list_transactions(
    status: TransactionStatus | None = Query(
        None, description="Filter by status (pending, in_progress, completed, failed, rolled_back)"
    ),
    operation: OperationType | None = Query(None, description="Filter by operation type"),
    resource_type: str | None = Query(None, description="Filter by resource type (site, nginx, certificate)"),
    limit: int = Query(50, ge=1, le=200, description="Maximum transactions to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    auth: AuthContext = Depends(require_role(Role.VIEWER)),
) -> TransactionListResponse:
    """List transactions with filtering."""
    transaction_manager = get_transaction_manager()

    return await transaction_manager.list_transactions(
        limit=limit, offset=offset, status=status, operation=operation, resource_type=resource_type
    )


@router.get(
    "/{transaction_id}",
    response_model=TransactionDetail,
    summary="Get Transaction Details",
    description="""
Get full transaction details including configuration diff.

Returns:
- Complete transaction metadata
- Before and after state summaries
- Unified diff of changed files
- List of affected files
- Rollback eligibility status

**AI Agent Usage:**
- Review exactly what changed in a transaction
- Determine if rollback is appropriate
- Understand failure causes from error details
""",
)
async def get_transaction(
    transaction_id: str, auth: AuthContext = Depends(require_role(Role.VIEWER))
) -> TransactionDetail:
    """Get detailed transaction information."""
    transaction_manager = get_transaction_manager()

    transaction = await transaction_manager.get_transaction_detail(transaction_id)
    if not transaction:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "transaction_not_found",
                "message": f"Transaction '{transaction_id}' not found",
                "suggestion": "Check the transaction ID and try again",
            },
        )

    return transaction


@router.post(
    "/{transaction_id}/rollback",
    response_model=RollbackResult,
    summary="Rollback Transaction",
    description="""
Restore configuration to state before a transaction.

**What Happens:**
1. Creates a new rollback transaction
2. Restores configuration files from snapshot
3. Validates configuration with `nginx -t`
4. Reloads NGINX to apply restored config
5. Verifies health after reload

**Rollback Eligibility:**
- Only completed or failed transactions can be rolled back
- Already rolled-back transactions cannot be rolled back again
- Snapshot must still exist (not cleaned by retention policy)

**AI Agent Usage:**
- Recover from problematic configuration changes
- Quickly restore known-good state
- Use after failed deployments
""",
    responses={
        200: {"description": "Rollback result (check 'success' field)"},
        404: {"description": "Transaction not found"},
        400: {"description": "Transaction cannot be rolled back"},
    },
)
async def rollback_transaction(
    transaction_id: str,
    request: RollbackRequest = RollbackRequest(),
    auth: AuthContext = Depends(require_role(Role.ADMIN)),
) -> RollbackResult:
    """Rollback a transaction to restore previous configuration."""
    transaction_manager = get_transaction_manager()

    # Check if transaction exists
    transaction = await transaction_manager.get_transaction(transaction_id)
    if not transaction:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "transaction_not_found",
                "message": f"Transaction '{transaction_id}' not found",
                "suggestion": "Check the transaction ID and try again",
            },
        )

    # Check if rollback is possible
    can_rollback, reason = await transaction_manager.can_rollback(transaction_id)
    if not can_rollback:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "rollback_not_allowed",
                "message": f"Cannot rollback transaction: {reason}",
                "transaction_id": transaction_id,
                "transaction_status": transaction.status.value,
            },
        )

    # Perform rollback
    result = await transaction_manager.rollback_transaction(transaction_id=transaction_id, reason=request.reason)

    return result


@router.get(
    "/{transaction_id}/can-rollback",
    summary="Check Rollback Eligibility",
    description="""
Check if a transaction can be rolled back.

Returns whether rollback is possible and the reason if not.
""",
)
async def check_rollback_eligibility(
    transaction_id: str, auth: AuthContext = Depends(require_role(Role.VIEWER))
) -> dict:
    """Check if a transaction can be rolled back."""
    transaction_manager = get_transaction_manager()

    transaction = await transaction_manager.get_transaction(transaction_id)
    if not transaction:
        raise HTTPException(
            status_code=404,
            detail={"error": "transaction_not_found", "message": f"Transaction '{transaction_id}' not found"},
        )

    can_rollback, reason = await transaction_manager.can_rollback(transaction_id)

    return {
        "transaction_id": transaction_id,
        "can_rollback": can_rollback,
        "reason": reason if not can_rollback else None,
        "transaction_status": transaction.status.value,
    }
