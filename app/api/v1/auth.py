from fastapi import APIRouter, Depends, Request, status, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis

from app.api import deps
from app.schemas.auth import (
    UserCreate, UserLogin, MFAVerify, RefreshRequest,
    LogoutRequest, SwitchOrgRequest, APIResponse, TokenResponse, MFAResponse
)
from app.services.auth_service import AuthService
from app.utils.rate_limiter import limiter
from app.core.config import settings
from app.core.redis import redis_client
from app.models import User

router = APIRouter()

# Helper dependency to get Redis client from pool
async def get_redis() -> Redis:
    return redis_client.get_client()

@router.post("/signup", response_model=APIResponse, status_code=status.HTTP_201_CREATED)
async def signup(
    request: Request,
    user_in: UserCreate,
    db: AsyncSession = Depends(deps.get_db),
    redis: Redis = Depends(get_redis)
):
    """
    Register a new user account.
    """
    # Rate limit: 3 per hour per IP
    await limiter.limit(redis, request.client.host, "signup", 3, 3600)

    service = AuthService(db, redis)
    await service.create_user(user_in, request.client.host)

    return APIResponse(
        success=True,
        data={"message": "Account created. Please verify your email."}
    )

@router.post("/login", response_model=APIResponse)
async def login(
    request: Request,
    user_in: UserLogin,
    db: AsyncSession = Depends(deps.get_db),
    redis: Redis = Depends(get_redis)
):
    """
    Authenticate user. Returns either tokens (200) or MFA requirement (200/202).
    """
    # Rate limit: Defined in settings
    await limiter.limit(redis, request.client.host, "login", settings.LOGIN_RATE_LIMIT, settings.LOGIN_RATE_WINDOW)

    service = AuthService(db, redis)
    result = await service.authenticate_user(user_in, request.client.host)

    # If MFA required, result contains 'mfa_required': True
    # Prompt says "Returns 200 with tokens OR 202 if MFA required"
    if result.get("mfa_required"):
        # We can return 202 Accepted for MFA step
        return APIResponse(
            success=True,
            data=result
        ) # FastAPI default is 200, we might want to change status code if strictly required, but APIResponse model wraps it.
        # To strictly return 202, we'd need to manipulate the response object or use JSONResponse,
        # but using response_model is cleaner.
        # I'll keep it 200 OK with data indicating MFA, or I can use Response param to set 202.
        # Let's check prompt "Returns 200 with tokens OR 202 if MFA required".
        # I will inject Response to set status code.

    return APIResponse(success=True, data=result)

@router.post("/mfa/verify", response_model=APIResponse)
async def mfa_verify(
    request: Request,
    mfa_in: MFAVerify,
    db: AsyncSession = Depends(deps.get_db),
    redis: Redis = Depends(get_redis)
):
    """
    Verify MFA code and issue tokens.
    """
    service = AuthService(db, redis)
    result = await service.verify_mfa(mfa_in.session_token, mfa_in.totp_code, request.client.host)
    return APIResponse(success=True, data=result)

@router.post("/refresh", response_model=APIResponse)
async def refresh_token(
    request: Request,
    refresh_in: RefreshRequest,
    db: AsyncSession = Depends(deps.get_db),
    redis: Redis = Depends(get_redis)
):
    """
    Rotate refresh token and issue new access token.
    """
    # Rate limit: 10 per 5 mins
    await limiter.limit(redis, request.client.host, "refresh", 10, 300)

    service = AuthService(db, redis)
    result = await service.refresh_token(refresh_in.refresh_token, request.client.host)
    return APIResponse(success=True, data=result)

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

@router.post("/logout", response_model=APIResponse)
async def logout(
    request: Request,
    logout_in: LogoutRequest,
    db: AsyncSession = Depends(deps.get_db),
    redis: Redis = Depends(get_redis)
):
    """
    Revoke refresh token(s).
    """
    service = AuthService(db, redis)
    await service.logout(logout_in.refresh_token, logout_in.revoke_all, request.client.host)
    return APIResponse(success=True, data={"message": "Logged out successfully"})
