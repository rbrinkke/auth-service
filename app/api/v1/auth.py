from fastapi import APIRouter, Depends, Request, status, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis

from app.db.session import get_db
from app.schemas.auth import (
    UserCreate, UserLogin, TokenResponse, MFAResponse,
    MFAVerify, RefreshRequest, LogoutRequest, APIResponse, SwitchOrgRequest
)
from app.services.auth_service import AuthService
from app.utils.rate_limiter import limiter
from app.core.config import settings
from app.core.redis import redis_client
from app.api import deps
from app.models import User
from app.core.security import public_key_to_jwk

router = APIRouter()

# Dependency to get Redis
async def get_redis() -> Redis:
    return redis_client.get_client()

@router.post("/signup", response_model=APIResponse, status_code=status.HTTP_201_CREATED)
async def signup(
    request: Request,
    user_in: UserCreate,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis)
):
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
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis)
):
    await limiter.limit(redis, request.client.host, "login", settings.LOGIN_RATE_LIMIT, settings.LOGIN_RATE_WINDOW)

    service = AuthService(db, redis)
    result = await service.authenticate_user(user_in, request.client.host)

    if result.get("mfa_required"):
        return APIResponse(success=True, data=result) # Status 200 usually, or 202

    return APIResponse(success=True, data=result)

@router.post("/mfa/verify", response_model=APIResponse)
async def mfa_verify(
    request: Request,
    mfa_in: MFAVerify,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis)
):
    service = AuthService(db, redis)
    result = await service.verify_mfa(mfa_in.session_token, mfa_in.totp_code, request.client.host)
    return APIResponse(success=True, data=result)

@router.post("/refresh", response_model=APIResponse)
async def refresh_token(
    request: Request,
    refresh_in: RefreshRequest,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis)
):
    # Rate limit per token is hard because we don't know the token identity easily without hashing
    # We can limit by IP for now or hash the token and limit that key
    await limiter.limit(redis, request.client.host, "refresh", 10, 300)

    service = AuthService(db, redis)
    result = await service.refresh_token(refresh_in.refresh_token, request.client.host)
    return APIResponse(success=True, data=result)

@router.post("/switch-org", response_model=APIResponse)
async def switch_org(
    request: Request,
    switch_in: SwitchOrgRequest,
    current_user: User = Depends(deps.get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis)
):
    service = AuthService(db, redis)
    result = await service.switch_org(current_user.id, switch_in.target_org_id)
    return APIResponse(success=True, data=result)

@router.post("/logout", response_model=APIResponse)
async def logout(
    request: Request,
    logout_in: LogoutRequest,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis)
):
    service = AuthService(db, redis)
    await service.logout(logout_in.refresh_token, logout_in.revoke_all, request.client.host)
    return APIResponse(success=True, data={"message": "Logged out successfully"})
