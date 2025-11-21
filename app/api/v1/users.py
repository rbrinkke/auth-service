from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import delete
import pyotp
from redis.asyncio import Redis

from app.api import deps
from app.schemas.auth import UserRead, APIResponse, SwitchOrgRequest
from app.models import User, AuditLog, OrganizationMember, RefreshToken
from app.core.security import decrypt_mfa_secret, encrypt_mfa_secret
from app.core.config import settings
from app.services.auth_service import AuthService
from app.core.redis import redis_client

router = APIRouter()

async def get_redis() -> Redis:
    return redis_client.get_client()

@router.post("/switch-org", response_model=APIResponse)
async def switch_org(
    request: Request,
    switch_in: SwitchOrgRequest,
    current_user: User = Depends(deps.get_current_user),
    db: AsyncSession = Depends(deps.get_db),
    redis: Redis = Depends(get_redis)
):
    """
    Issue new access token scoped to target organization.
    """
    service = AuthService(db, redis)
    result = await service.switch_org(current_user.id, switch_in.target_org_id)
    return APIResponse(success=True, data=result)

@router.get("/me", response_model=APIResponse)
async def read_users_me(
    current_user: User = Depends(deps.get_current_user),
):
    """
    Get current user profile.
    """
    return APIResponse(success=True, data=UserRead.model_validate(current_user))

@router.get("/mfa/secret", response_model=APIResponse)
async def get_mfa_secret(
    current_user: User = Depends(deps.get_current_user),
    db: AsyncSession = Depends(deps.get_db),
):
    """
    Get MFA secret and otpauth URI.
    """
    if current_user.mfa_enabled:
         # Security Constraint: Only allow this if MFA is not yet enabled.
         raise HTTPException(status_code=400, detail="MFA is already enabled.")

    if not current_user.mfa_secret:
        # Generate new secret if one doesn't exist
        secret = pyotp.random_base32()
        current_user.mfa_secret = encrypt_mfa_secret(secret)
        db.add(current_user)
        await db.commit()
        await db.refresh(current_user)
        decrypted_secret = secret
    else:
        decrypted_secret = decrypt_mfa_secret(current_user.mfa_secret)

    # Generate otpauth URI
    totp = pyotp.TOTP(decrypted_secret)
    provisioning_uri = totp.provisioning_uri(name=current_user.email, issuer_name=settings.APP_NAME)

    return APIResponse(success=True, data={
        "secret": decrypted_secret,
        "uri": provisioning_uri
    })

@router.post("/mfa/enable", response_model=APIResponse)
async def enable_mfa(
    request: Request,
    current_user: User = Depends(deps.get_current_user),
    db: AsyncSession = Depends(deps.get_db),
):
    """
    Enable MFA for the user.
    """
    if current_user.mfa_enabled:
        return APIResponse(success=True, data={"message": "MFA is already enabled."})

    current_user.mfa_enabled = True
    db.add(current_user)

    # Create audit log
    audit = AuditLog(
        event_type="mfa_enabled",
        user_id=current_user.id,
        ip_address=request.client.host,
        success=True,
        details={"action": "enabled_mfa"}
    )
    db.add(audit)

    await db.commit()

    return APIResponse(success=True, data={"message": "MFA enabled successfully."})


@router.get("/organizations", response_model=APIResponse)
async def list_user_organizations(
    current_user: User = Depends(deps.get_current_user),
    db: AsyncSession = Depends(deps.get_db),
):
    """
    List user's organizations.
    """
    from app.models import Organization
    from sqlalchemy import select
    
    stmt = select(Organization).join(OrganizationMember).where(OrganizationMember.user_id == current_user.id)
    result = await db.execute(stmt)
    orgs = result.scalars().all()
    
    data = [
        {"id": str(org.id), "name": org.name, "slug": org.slug}
        for org in orgs
    ]
    
    return APIResponse(success=True, data={"organizations": data})

@router.delete("/me", response_model=APIResponse)
async def delete_user_me(
    request: Request,
    current_user: User = Depends(deps.get_current_user),
    db: AsyncSession = Depends(deps.get_db),
):
    """
    Self-deletion endpoint (GDPR compliance).
    Performs a hard delete of the user object.
    Cascading rules ensure cleanup of related data (tokens, memberships, codes).
    Audit logs are preserved (user_id set to NULL via database constraint).
    """
    # Log event before deleting user
    audit = AuditLog(
        event_type="user_deleted",
        user_id=current_user.id,
        ip_address=request.client.host,
        success=True,
        details={"email": current_user.email}
    )
    db.add(audit)
    
    # Hard delete the user
    await db.delete(current_user)
    
    await db.commit()

    return APIResponse(success=True, data={"message": "User deleted successfully."})
