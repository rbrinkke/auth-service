import uuid
import secrets
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from redis.asyncio import Redis

from app.models import User
from app.core import security
from app.core.exceptions import InvalidCredentialsError

class MFAService:
    def __init__(self, db: AsyncSession, redis: Redis):
        self.db = db
        self.redis = redis

    async def initiate_mfa_session(self, user_id: uuid.UUID) -> str:
        """
        Create a temporary MFA session and return the session token.
        """
        session_token = secrets.token_urlsafe(32)
        await self.redis.setex(f"mfa_session:{session_token}", 300, str(user_id))
        return session_token

    async def verify_mfa(self, session_token: str, totp_code: str) -> User:
        """
        Verify MFA code for a given session.
        Returns the user if successful.
        """
        # Rate Limiting
        rate_limit_key = f"mfa_attempts:{session_token}"
        attempts = await self.redis.incr(rate_limit_key)
        if attempts == 1:
            await self.redis.expire(rate_limit_key, 300) # 5 minutes

        if attempts > 3:
            # Revoke session
            await self.redis.delete(f"mfa_session:{session_token}")
            await self.redis.delete(rate_limit_key)
            raise InvalidCredentialsError("Too many failed attempts. Session revoked.")

        user_id_str = await self.redis.get(f"mfa_session:{session_token}")
        if not user_id_str:
            raise InvalidCredentialsError("Invalid or expired session")

        user_id = uuid.UUID(user_id_str)
        stmt = select(User).where(User.id == user_id)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user or not user.mfa_secret:
            raise InvalidCredentialsError("Invalid user state")

        # Decrypt secret
        try:
            plain_secret = security.decrypt_mfa_secret(user.mfa_secret)
        except Exception:
            raise InvalidCredentialsError("Security Error: MFA key invalid")

        if not security.verify_totp(plain_secret, totp_code):
             raise InvalidCredentialsError("Invalid TOTP code")

        # Success - cleanup
        await self.redis.delete(f"mfa_session:{session_token}")

        return user
