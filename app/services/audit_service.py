import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import AuditLog

async def log_audit_event(
    db: AsyncSession,
    event_type: str,
    user_id: Optional[uuid.UUID],
    ip_address: str,
    success: bool,
    details: Optional[dict] = None
):
    """
    Create immutable audit log entry.
    CRITICAL: Never update or delete audit logs.
    """
    log_entry = AuditLog(
        event_type=event_type,
        user_id=user_id,
        ip_address=ip_address,
        success=success,
        details=details
        # timestamp handled by default=func.now()
    )
    db.add(log_entry)
    # We don't commit here to allow it to be part of a larger transaction
    # But if called independently it should be committed.
    # Usually audit logs should be committed regardless of main transaction success/fail,
    # but in SQLAlchemy async session, nested transactions are tricky.
    # For this implementation, we assume the caller handles commit,
    # OR we create a separate session if we want to ensure it persists even on failure.
    # Best practice: If auditing a failure, we likely rollback the main transaction then commit the audit log.
    # We will leave commit to the caller or specialized middleware.
