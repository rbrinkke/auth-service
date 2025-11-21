from typing import Generator, AsyncGenerator
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.exceptions import InvalidTokenError

from app.db.session import get_db
from app.core.security import decode_access_token
from app.models import User
from app.core.exceptions import InvalidTokenError

security = HTTPBearer()

async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Validate access token and return current user.
    Security: Verifies JWT signature using public key.
    """
    token = credentials.credentials
    try:
        payload = decode_access_token(token)
        user_id = payload.get("sub")
        if not user_id:
            raise InvalidTokenError("Invalid token subject")

        # Fetch user from DB to ensure still exists
        # In a pure standalone stateless verification, we wouldn't do this,
        # but the prompt asks to "Verify user is member of target org" and "Check user still active" in logic steps.
        # Also deps.py in prompt shows checking DB.
        result = await db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        # Store user in request state for logging if needed
        request.state.user = user
        return user
    except InvalidTokenError as e:
        raise HTTPException(
             status_code=status.HTTP_401_UNAUTHORIZED,
             detail=str(e),
             headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
