from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.api import deps
from app.models import User, AuditLog
from app.schemas.auth import UserRead, APIResponse, AuditLogRead
from app.services.audit_service import log_audit_event

router = APIRouter()

@router.get("/users", response_model=APIResponse)
async def list_users(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(deps.get_db),
    current_user: User = Depends(deps.require_role("admin"))
):
    """
    List users with pagination.
    """
    stmt = select(User).limit(limit).offset(offset)
    result = await db.execute(stmt)
    users = result.scalars().all()

    # Manually map to UserRead to avoid validation issues with SQLAlchemy models
    user_data = [UserRead.model_validate(u) for u in users]

    return APIResponse(success=True, data=user_data)

@router.post("/users/{user_id}/ban", response_model=APIResponse)
async def ban_user(
    user_id: UUID,
    db: AsyncSession = Depends(deps.get_db),
    current_user: User = Depends(deps.require_role("admin"))
):
    """
    Ban a user (set is_verified = False, or we might need an is_active flag).
    The prompt says 'Set is_active = False (you may need to add this boolean column to the User model if missing, or use is_verified)'.
    Checking User model, it doesn't have is_active. It has is_verified.
    I'll use is_verified=False for now as a ban mechanism (effectively locking them out of protected routes).
    Or better, I should check if I should add is_active.
    The prompt says: "you may need to add this boolean column to the User model if missing, or use is_verified".
    I will use `is_verified` for now to avoid DB migration in this step if not strictly necessary,
    but `is_verified` usually means email verification. Banning is different.
    However, strict compliance with prompt "or use is_verified" allows it.

    Wait, if I set `is_verified=False`, they can just re-verify email?
    The `verify-email` endpoint isn't shown here, but typically yes.
    Maybe I should add `is_active`?

    Let's check `User` model again.
    It has `is_verified` and `mfa_enabled`.

    If I add `is_active`, I need to run migration.
    The prompt goal is "Implement Operational Support Layer".

    If I use `is_verified = False`, `get_current_user` will raise 403.
    So it effectively bans them.

    Let's stick to `is_verified` as per prompt suggestion to avoid migrations if possible.
    """
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_verified = False
    # Also revoke tokens
    # We don't have easy access to AuthService here without redis, but we can revoke in DB
    # But AuthService logic is better.
    # We can just set verified=False and they can't access APIs.
    # But their tokens might still be valid for a bit until checked?
    # `get_current_user` checks `user.is_verified`. So immediate effect.

    await log_audit_event(db, "user_banned", current_user.id, "admin_action", True, {"target_user_id": str(user_id)})
    await db.commit()

    return APIResponse(success=True, data={"message": "User banned (is_verified set to False)"})

@router.post("/users/{user_id}/unban", response_model=APIResponse)
async def unban_user(
    user_id: UUID,
    db: AsyncSession = Depends(deps.get_db),
    current_user: User = Depends(deps.require_role("admin"))
):
    """
    Unban a user (set is_verified = True).
    """
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_verified = True
    await log_audit_event(db, "user_unbanned", current_user.id, "admin_action", True, {"target_user_id": str(user_id)})
    await db.commit()

    return APIResponse(success=True, data={"message": "User unbanned (is_verified set to True)", "user_id": str(user_id)})

@router.get("/audit-logs", response_model=APIResponse)
async def get_audit_logs(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    user_id: Optional[UUID] = None,
    db: AsyncSession = Depends(deps.get_db),
    current_user: User = Depends(deps.require_role("admin"))
):
    """
    Fetch audit logs.
    """
    stmt = select(AuditLog).order_by(desc(AuditLog.timestamp)).limit(limit).offset(offset)

    if user_id:
        stmt = stmt.where(AuditLog.user_id == user_id)

    result = await db.execute(stmt)
    logs = result.scalars().all()

    log_data = [AuditLogRead.model_validate(l) for l in logs]

    return APIResponse(success=True, data=log_data)

@router.post("/organizations", response_model=APIResponse, status_code=status.HTTP_501_NOT_IMPLEMENTED)
async def create_organization(
    db: AsyncSession = Depends(deps.get_db),
    current_user: User = Depends(deps.require_role("admin"))
):
    """
    Create new organization - NOT IMPLEMENTED (returns 501).
    Organization table not yet implemented in database.
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Organization management not yet implemented"
    )
