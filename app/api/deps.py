from typing import AsyncGenerator
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import AsyncSessionLocal
from app.core.security import decode_access_token
from app.models import User
from app.core.exceptions import InvalidTokenError

# Security scheme for Bearer token extraction
security_scheme = HTTPBearer()

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency to provide an async database session.
    Yields an AsyncSession and ensures it is closed after use.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Dependency to get the current authenticated user.

    Steps:
    1. Extract JWT from Bearer header.
    2. Decode and validate the token signature (RS256).
    3. Verify user exists in the database.
    4. Verify user is email-verified.

    Raises:
        HTTPException(401): If token is invalid or user not found.
        HTTPException(403): If user is not verified.
    """
    token = credentials.credentials
    try:
        payload = decode_access_token(token)
        user_id = payload.get("sub")

        if not user_id:
            raise InvalidTokenError("Token missing subject claim")

        # Verify user exists in DB
        stmt = select(User).where(User.id == user_id)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user:
            raise InvalidTokenError("User no longer exists")

        # UPDATED: Enforce strict email verification for all protected routes
        if not user.is_verified:
             raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Email verification required"
            )

        # Store user in request state for potential logging usage
        request.state.user = user
        return user

    except HTTPException:
        # Re-raise HTTP exceptions (like our 403 above)
        raise
    except Exception:
        # Catch all security/validation errors and return generic 401
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
