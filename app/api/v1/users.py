from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
import pyotp

from app.api import deps
from app.schemas.auth import UserRead, APIResponse
from app.models import User, AuditLog
from app.core.security import decrypt_mfa_secret, encrypt_mfa_secret
from app.core.config import settings

router = APIRouter()

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


@router.get("/organizations", response_model=APIResponse, status_code=status.HTTP_501_NOT_IMPLEMENTED)
async def list_user_organizations(
    current_user: User = Depends(deps.get_current_user),
):
    """
    List user's organizations - NOT IMPLEMENTED (returns 501).
    Organization table not yet implemented in database.
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Organization management not yet implemented"
    )

@router.delete("/me", response_model=APIResponse)
async def delete_user_me(
    request: Request,
    current_user: User = Depends(deps.get_current_user),
    db: AsyncSession = Depends(deps.get_db),
):
    """
    Self-deletion endpoint (GDPR compliance).
    """
    # Log event
    audit = AuditLog(
        event_type="user_deleted",
        user_id=current_user.id,
        ip_address=request.client.host,
        success=True,
        details={"email": current_user.email}
    )
    db.add(audit)

    # Delete user
    # Relationships (RefreshToken, OrganizationMember) are CASCADE.
    # AuditLog is SET NULL.
    await db.delete(current_user)
    await db.commit()

    return APIResponse(success=True, data={"message": "User deleted successfully."})
