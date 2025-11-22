import uuid
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from redis.asyncio import Redis

from app.models import User, OrganizationMember, RefreshToken, PasswordResetCode, ServiceAccount
from app.schemas.auth import UserLogin
from app.core import security
from app.core.config import settings
from app.core.exceptions import (
    InvalidCredentialsError,
    AuthenticationError,
    InvalidTokenError,
    InvalidScopesError,
    UserNotFoundError,
    InvalidVerificationCodeError,
    MembershipNotFoundError
)
from app.services.audit_service import log_audit_event
from app.services.email import get_email_provider
from app.services.mfa_service import MFAService

class AuthService:
    def __init__(self, db: AsyncSession, redis: Redis):
        self.db = db
        self.redis = redis
        self.email_service = get_email_provider()
        self.mfa_service = MFAService(db, redis)

    async def authenticate_user(self, user_in: UserLogin, ip_address: str) -> dict:
        # 1. Get user
        stmt = select(User).where(User.email == user_in.email)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user:
            await log_audit_event(self.db, "login_failed", None, ip_address, False, {"reason": "user_not_found"})
            await self.db.commit()
            raise InvalidCredentialsError("Invalid email or password")

        # Check Lock Status (IMMEDIATELY)
        if user.locked_until:
            if user.locked_until > datetime.now(timezone.utc):
                # Account is locked
                await log_audit_event(self.db, "login_failed", user.id, ip_address, False, {"reason": "account_locked"})
                raise AuthenticationError("Account is temporarily locked due to multiple failed login attempts.")
            else:
                # Auto-Unlock (Lock expired)
                user.failed_login_attempts = 0
                user.locked_until = None

        # 2. Verify password
        if not await security.verify_password(user_in.password, user.password_hash):
            # Handle Incorrect Password
            user.failed_login_attempts += 1
            user.last_failed_login = datetime.now(timezone.utc)

            # Check Threshold
            if user.failed_login_attempts >= settings.SECURITY_MAX_LOGIN_ATTEMPTS:
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=settings.SECURITY_LOCKOUT_DURATION_MINUTES)
                await log_audit_event(self.db, "account_locked", user.id, ip_address, False, {"reason": "max_attempts_exceeded"})

                # Trigger "Account Locked" email
                if hasattr(self.email_service, 'send_account_locked_email'):
                     await self.email_service.send_account_locked_email(user.email)

            else:
                await log_audit_event(self.db, "login_failed", user.id, ip_address, False, {"reason": "invalid_password", "attempts": user.failed_login_attempts})

            await self.db.commit()
            raise InvalidCredentialsError("Invalid email or password")

        # Password Correct
        # Reset counters
        user.failed_login_attempts = 0
        user.locked_until = None

        # 3. Verify user is active/verified
        if not user.is_verified:
            await log_audit_event(self.db, "login_failed", user.id, ip_address, False, {"reason": "user_not_verified"})
            await self.db.commit()
            raise InvalidCredentialsError("Account not verified or is inactive")

        # 4. MFA Check
        if user.mfa_enabled:
            # Generate temp session token using MFAService
            session_token = await self.mfa_service.initiate_mfa_session(user.id)

            await log_audit_event(self.db, "login_mfa_required", user.id, ip_address, True)
            await self.db.commit()

            return {"mfa_required": True, "session_token": session_token}

        # 4. Success
        return await self._finalize_login(user, ip_address)

    async def verify_mfa(self, session_token: str, totp_code: str, ip_address: str) -> dict:
        # Delegate to MFAService
        user = await self.mfa_service.verify_mfa(session_token, totp_code)
        return await self._finalize_login(user, ip_address)

    async def _finalize_login(self, user: User, ip_address: str, org_id: Optional[uuid.UUID] = None) -> dict:
        # Get Org context
        if not org_id:
            # Default to first org or None
            stmt = select(OrganizationMember).where(OrganizationMember.user_id == user.id)
            result = await self.db.execute(stmt)
            memberships = result.scalars().all()
            if memberships:
                org_id = memberships[0].org_id
                roles = memberships[0].roles
            else:
                org_id = None
                roles = []
        else:
             # Validate membership
             stmt = select(OrganizationMember).where(
                 OrganizationMember.user_id == user.id,
                 OrganizationMember.org_id == org_id
             )
             result = await self.db.execute(stmt)
             member = result.scalar_one_or_none()
             if not member:
                 raise MembershipNotFoundError("Not a member of this organization")
             roles = member.roles

        # Generate Tokens
        access_token = security.create_access_token(
            user_id=str(user.id),
            org_id=str(org_id) if org_id else None,
            roles=roles,
            email=user.email,
            verified=user.is_verified
        )

        refresh_token = security.generate_refresh_token()
        refresh_token_hash = security.hash_refresh_token(refresh_token)

        # Store Refresh Token
        db_refresh = RefreshToken(
            token_hash=refresh_token_hash,
            user_id=user.id,
            org_id=org_id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
            device_info={"ip": ip_address}
        )
        self.db.add(db_refresh)

        await log_audit_event(self.db, "login_success", user.id, ip_address, True)
        await self.db.commit()

        return {
            "mfa_required": False,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }

    async def refresh_token(self, refresh_token: str, ip_address: str) -> dict:
        token_hash = security.hash_refresh_token(refresh_token)

        # Lock the row
        stmt = select(RefreshToken).where(
            RefreshToken.token_hash == token_hash
        ).with_for_update()

        result = await self.db.execute(stmt)
        db_token = result.scalar_one_or_none()

        if not db_token:
            # Potential reuse attack or invalid token
            raise InvalidTokenError("Invalid refresh token")

        if db_token.revoked:
            # Revoke all tokens for this user (Security Best Practice)
            await self._revoke_user_tokens(db_token.user_id)
            await self.db.commit()
            raise InvalidTokenError("Token reused - Security Alert")

        # Ensure timezone awareness for comparison (SQLite compatibility)
        expires_at = db_token.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at < datetime.now(timezone.utc):
            raise InvalidTokenError("Token expired")

        # Token Rotation
        await self.db.delete(db_token)

        # 2. Create new token
        user_id = db_token.user_id
        org_id = db_token.org_id

        # Get user details for JWT
        stmt = select(User).where(User.id == user_id)
        user = (await self.db.execute(stmt)).scalar_one()

        roles = []
        if org_id:
            stmt = select(OrganizationMember).where(
                OrganizationMember.user_id == user_id,
                OrganizationMember.org_id == org_id
            )
            member = (await self.db.execute(stmt)).scalar_one_or_none()
            if member:
                roles = member.roles

        new_access_token = security.create_access_token(
            user_id=str(user_id),
            org_id=str(org_id) if org_id else None,
            roles=roles,
            email=user.email,
            verified=user.is_verified
        )

        new_refresh_token = security.generate_refresh_token()
        new_refresh_hash = security.hash_refresh_token(new_refresh_token)

        new_db_token = RefreshToken(
            token_hash=new_refresh_hash,
            user_id=user_id,
            org_id=org_id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
            device_info={"ip": ip_address}
        )
        self.db.add(new_db_token)

        await log_audit_event(self.db, "token_refreshed", user_id, ip_address, True)
        await self.db.commit()

        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "Bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }

    async def _revoke_user_tokens(self, user_id: uuid.UUID):
        stmt = delete(RefreshToken).where(RefreshToken.user_id == user_id)
        await self.db.execute(stmt)

    async def switch_org(self, user_id: uuid.UUID, target_org_id: uuid.UUID) -> dict:
        # Check membership
        stmt = select(OrganizationMember).where(
            OrganizationMember.user_id == user_id,
            OrganizationMember.org_id == target_org_id
        )
        result = await self.db.execute(stmt)
        member = result.scalar_one_or_none()

        if not member:
            raise MembershipNotFoundError("Not a member of target organization")

        # Get user info
        stmt = select(User).where(User.id == user_id)
        user = (await self.db.execute(stmt)).scalar_one()

        new_access_token = security.create_access_token(
            user_id=str(user_id),
            org_id=str(target_org_id),
            roles=member.roles,
            email=user.email,
            verified=user.is_verified
        )

        return {
            "access_token": new_access_token,
            "token_type": "Bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }

    async def logout(self, refresh_token: str, revoke_all: bool, ip_address: str):
        token_hash = security.hash_refresh_token(refresh_token)

        if revoke_all:
            # We need to find the user_id first
            stmt = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
            result = await self.db.execute(stmt)
            token = result.scalar_one_or_none()
            if token:
                await self._revoke_user_tokens(token.user_id)
        else:
            stmt = delete(RefreshToken).where(RefreshToken.token_hash == token_hash)
            await self.db.execute(stmt)

        await log_audit_event(self.db, "logout", None, ip_address, True)
        await self.db.commit()

    async def forgot_password(self, email: str, ip_address: str):
        """
        Initiate password recovery.
        """
        stmt = select(User).where(User.email == email)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()

        # Security: Always return success to prevent enumeration
        if not user:
             await log_audit_event(self.db, "forgot_password_failed", None, ip_address, False, {"reason": "user_not_found"})
             await self.db.commit()
             return

        # Generate 6-digit code
        code = f"{secrets.randbelow(1000000):06d}"
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
        
        # Store in DB
        reset_code_entry = PasswordResetCode(
            user_id=user.id,
            code=code,
            expires_at=expires_at
        )
        self.db.add(reset_code_entry)

        # Send email (passing code as token)
        await self.email_service.send_password_reset_email(user.email, code)

        await log_audit_event(self.db, "forgot_password_initiated", user.id, ip_address, True)
        await self.db.commit()

    async def verify_reset_code(self, email: str, code: str):
        """
        Verify password reset code validity (without resetting password).
        """
        # Find user first
        stmt = select(User).where(User.email == email)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user:
             # Ambiguous error for security
             raise InvalidVerificationCodeError("Invalid email or code")

        # Check DB for code
        stmt = select(PasswordResetCode).where(
            PasswordResetCode.user_id == user.id,
            PasswordResetCode.code == code,
            PasswordResetCode.expires_at > datetime.now(timezone.utc)
        )
        result = await self.db.execute(stmt)
        reset_code_entry = result.scalar_one_or_none()

        if not reset_code_entry:
            raise InvalidVerificationCodeError("Invalid or expired reset code")

        # Code is valid
        return True

    async def reset_password_with_code(self, email: str, code: str, new_password: str, ip_address: str):
        """
        Reset password using email + code instead of token.
        """
        # Verify code (and get user implicitly, but we need user obj)
        await self.verify_reset_code(email, code)

        # Find user (again, optimized: verify_reset_code could return user/entry but keeping signature simple)
        stmt = select(User).where(User.email == email)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user:
            raise UserNotFoundError("User not found")

        # Hash new password
        hashed_password = await security.hash_password(new_password)
        user.password_hash = hashed_password

        # Revoke all existing refresh tokens
        await self._revoke_user_tokens(user.id)

        # Delete ALL reset codes for this user (security: consume the code)
        stmt = delete(PasswordResetCode).where(PasswordResetCode.user_id == user.id)
        await self.db.execute(stmt)

        await log_audit_event(self.db, "password_reset_success", user.id, ip_address, True)
        await self.db.commit()

    async def logout_all_sessions(self, user_id: uuid.UUID, ip_address: str):
        """
        Revoke all refresh tokens for a user (logout all devices).
        """
        await self._revoke_user_tokens(user_id)
        await log_audit_event(self.db, "logout_all_sessions", user_id, ip_address, True)
        await self.db.commit()

    async def authenticate_service_account(self, client_id: str, client_secret: str, requested_scopes: Optional[str]) -> dict:
        """
        Authenticate a service account via Client Credentials Flow.
        """
        # 1. Fetch ServiceAccount
        stmt = select(ServiceAccount).where(ServiceAccount.client_id == client_id)
        result = await self.db.execute(stmt)
        service_account = result.scalar_one_or_none()

        if not service_account or not service_account.is_active:
            # Mitigate timing attacks by performing a dummy verification
            await security.verify_password("dummy_password", "$argon2id$v=19$m=65536,t=3,p=4$ZHVtbXlzYWx0$ZHVtbXloYXNo")
            raise InvalidCredentialsError("Invalid client_id or client_secret")

        # 2. Verify secret
        if not await security.verify_password(client_secret, service_account.client_secret_hash):
            raise InvalidCredentialsError("Invalid client_id or client_secret")

        # 3. Scope Validation
        allowed_scopes = set(service_account.scopes)

        if requested_scopes:
            req_scopes_list = requested_scopes.split()
            for scope in req_scopes_list:
                if scope not in allowed_scopes:
                    raise InvalidScopesError(f"Scope '{scope}' is not allowed for this service account")
            final_scopes = " ".join(req_scopes_list)
        else:
            # Default to all allowed scopes
            final_scopes = " ".join(service_account.scopes)

        # 4. Generate JWT
        access_token = security.create_access_token(
            user_id=str(service_account.client_id), # Use client_id as sub
            org_id=None,
            roles=[],
            email=None,
            verified=True,
            scope=final_scopes,
            claims={"type": "service_account"}
        )

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }
