import pytest
from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from app.models import User
from app.services.auth_service import AuthService
from app.core.config import settings
from app.schemas.auth import UserLogin
from app.core.exceptions import InvalidCredentialsError, AuthenticationError

@pytest.mark.asyncio
class TestAccountLockout:

    async def test_account_locks_after_max_attempts(self, db_session, redis_client, user_factory):
        # Create a user
        user = await user_factory(password="password123", is_verified=True)
        
        auth_service = AuthService(db_session, redis_client)

        # Try failing N times
        max_attempts = settings.SECURITY_MAX_LOGIN_ATTEMPTS

        for i in range(max_attempts):
            with pytest.raises(InvalidCredentialsError):
                await auth_service.authenticate_user(
                    UserLogin(email=user.email, password="wrongpassword"),
                    ip_address="127.0.0.1"
                )

        # Verify user is locked
        stmt = select(User).where(User.id == user.id)
        result = await db_session.execute(stmt)
        updated_user = result.scalar_one()

        assert updated_user.failed_login_attempts >= max_attempts
        assert updated_user.locked_until is not None
        assert updated_user.locked_until > datetime.now(timezone.utc)

    async def test_user_cannot_login_while_locked(self, db_session, redis_client, user_factory):
        user = await user_factory(password="password123", is_verified=True)
        auth_service = AuthService(db_session, redis_client)

        # Manually lock the user
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=30)
        user.failed_login_attempts = settings.SECURITY_MAX_LOGIN_ATTEMPTS
        await db_session.commit()

        # Try with CORRECT password
        with pytest.raises(AuthenticationError) as excinfo:
            await auth_service.authenticate_user(
                UserLogin(email=user.email, password="password123"),
                ip_address="127.0.0.1"
            )

        assert "locked" in str(excinfo.value).lower()

    async def test_correct_password_resets_counter(self, db_session, redis_client, user_factory):
        user = await user_factory(password="password123", is_verified=True)
        auth_service = AuthService(db_session, redis_client)

        # Fail once
        with pytest.raises(InvalidCredentialsError):
            await auth_service.authenticate_user(
                UserLogin(email=user.email, password="wrong"),
                ip_address="127.0.0.1"
            )

        # Reload user
        await db_session.refresh(user)
        assert user.failed_login_attempts == 1

        # Succeed
        await auth_service.authenticate_user(
            UserLogin(email=user.email, password="password123"),
            ip_address="127.0.0.1"
        )

        # Reload user
        await db_session.refresh(user)
        assert user.failed_login_attempts == 0
        assert user.locked_until is None

    async def test_auto_unlock_after_duration(self, db_session, redis_client, user_factory):
        user = await user_factory(password="password123", is_verified=True)
        auth_service = AuthService(db_session, redis_client)

        # Lock user in the past
        user.locked_until = datetime.now(timezone.utc) - timedelta(minutes=1)
        user.failed_login_attempts = settings.SECURITY_MAX_LOGIN_ATTEMPTS
        await db_session.commit()

        # Try with correct password
        result = await auth_service.authenticate_user(
            UserLogin(email=user.email, password="password123"),
            ip_address="127.0.0.1"
        )

        assert result is not None
        assert "access_token" in result

        # Verify reset
        await db_session.refresh(user)
        assert user.failed_login_attempts == 0
        assert user.locked_until is None
