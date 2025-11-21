import uuid
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
from sqlalchemy.orm import selectinload
from fastapi import HTTPException, status
from redis.asyncio import Redis

from app.models import User, Organization, OrganizationMember, RefreshToken
from app.schemas.auth import UserCreate, UserLogin
from app.core import security
from app.core.config import settings
from app.core.exceptions import InvalidCredentialsError, MFARequiredError, AuthenticationError, InvalidTokenError
from app.services.audit_service import log_audit_event
from app.services.email import get_email_provider

class AuthService:
    def __init__(self, db: AsyncSession, redis: Redis):
        self.db = db
        self.redis = redis
        self.email_service = get_email_provider()

    async def create_user(self, user_in: UserCreate, ip_address: str) -> User:
        # Check email
        stmt = select(User).where(User.email == user_in.email)
        result = await self.db.execute(stmt)
        if result.scalar_one_or_none():
            await log_audit_event(self.db, "signup_failed", None, ip_address, False, {"reason": "email_exists"})
            await self.db.commit()
            # Return success to prevent enumeration? Prompt says "Return success (don't expose user ID)"
            # But step 3 says "Check if email already exists...".
            # Prompt logic says: "If user not found: Log failed attempt... generic error (no user enumeration)" for LOGIN.
            # For SIGNUP: "Return success (don't expose user ID)" after creating.
            # If email exists, we should probably raise an error or fail silently.
            # To be robust and follow "best-in-class":
            raise HTTPException(
                status_code=409,
                detail="Email already registered"
            )

        # Hash password
        hashed_password = security.hash_password(user_in.password)

        # Create User
        user = User(
            email=user_in.email,
            password_hash=hashed_password,
            is_verified=False,
            mfa_secret=security.encrypt_mfa_secret(security.generate_totp_secret()) # Generate encrypted secret initially, even if disabled
        )
        self.db.add(user)

        # If Org provided
        if user_in.organization_name:
            # Flush to get user ID
            await self.db.flush()
            org = Organization(
                name=user_in.organization_name,
                slug=user_in.organization_name.lower().replace(" ", "-") # Simple slugify
            )
            self.db.add(org)
            await self.db.flush()

            member = OrganizationMember(
                user_id=user.id,
                org_id=org.id,
                roles=["owner"]
            )
            self.db.add(member)

        await log_audit_event(self.db, "signup_success", user.id, ip_address, True)
        await self.db.commit()
        await self.db.refresh(user)
        return user

    async def authenticate_user(self, user_in: UserLogin, ip_address: str) -> dict:
        # 1. Get user
        stmt = select(User).where(User.email == user_in.email)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user:
            await log_audit_event(self.db, "login_failed", None, ip_address, False, {"reason": "user_not_found"})
            await self.db.commit()
            raise InvalidCredentialsError("Invalid email or password")

        # 2. Verify password
        if not security.verify_password(user_in.password, user.password_hash):
            await log_audit_event(self.db, "login_failed", user.id, ip_address, False, {"reason": "invalid_password"})
            await self.db.commit()
            raise InvalidCredentialsError("Invalid email or password")

        # 3. Verify user is active/verified
        if not user.is_verified:
            await log_audit_event(self.db, "login_failed", user.id, ip_address, False, {"reason": "user_not_verified"})
            await self.db.commit()
            raise InvalidCredentialsError("Account not verified or is inactive")

        # 4. MFA Check
        if user.mfa_enabled:
            # Generate temp session token
            session_token = secrets.token_urlsafe(32)
            await self.redis.setex(f"mfa_session:{session_token}", 300, str(user.id))

            await log_audit_event(self.db, "login_mfa_required", user.id, ip_address, True)
            await self.db.commit()

            return {"mfa_required": True, "session_token": session_token}

        # 4. Success
        return await self._finalize_login(user, ip_address)

    async def verify_mfa(self, session_token: str, totp_code: str, ip_address: str) -> dict:
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
             # Increment failure logic could be here
             raise InvalidCredentialsError("Invalid TOTP code")

        # Success
        await self.redis.delete(f"mfa_session:{session_token}")
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
                 raise AuthenticationError("Not a member of this organization")
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
            device_info={"ip": ip_address} # Simplified
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
        # 1. Revoke/Delete old token. Prompt says "Delete OLD refresh token".
        #    But we also have a 'revoked' column.
        #    Prompt says: "Delete OLD refresh token from DB (within same transaction) ... Insert NEW refresh token" in 3.3
        #    So we delete it.
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
            raise AuthenticationError("Not a member of target organization")

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

        await log_audit_event(self.db, "logout", None, ip_address, True) # User ID might be unknown if token invalid
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

        # Generate password reset token (short-lived JWT)
        # Use a special scope for password reset
        reset_token = security.create_access_token(
            user_id=str(user.id),
            org_id=None,
            roles=[],
            email=user.email,
            verified=user.is_verified,
            expires_delta=timedelta(minutes=15),
            scope="password_reset"
        )

        # Send email
        await self.email_service.send_password_reset_email(user.email, reset_token)

        await log_audit_event(self.db, "forgot_password_initiated", user.id, ip_address, True)
        await self.db.commit()

    async def reset_password(self, token: str, new_password: str, ip_address: str):
        """
        Reset password using the token.
        """
        try:
            payload = security.decode_access_token(token)
        except Exception:
            raise InvalidTokenError("Invalid or expired token")

        if payload.get("scope") != "password_reset":
            raise InvalidTokenError("Invalid token scope")

        user_id = payload.get("sub")
        if not user_id:
            raise InvalidTokenError("Invalid token")

        stmt = select(User).where(User.id == uuid.UUID(user_id))
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user:
            raise InvalidTokenError("User not found")

        # Hash new password
        hashed_password = security.hash_password(new_password)
        user.password_hash = hashed_password

        # Revoke all existing refresh tokens
        await self._revoke_user_tokens(user.id)

        await log_audit_event(self.db, "password_reset_success", user.id, ip_address, True)
        await self.db.commit()

    async def verify_email(self, email: str, code: str):
        """
        Verify email address with verification code.
        """
        # Get verification code from Redis
        redis_key = f"email_verification:{email}"
        stored_code = await self.redis.get(redis_key)

        if not stored_code or stored_code != code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification code"
            )

        # Find user by email
        stmt = select(User).where(User.email == email)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Mark as verified
        user.is_verified = True
        await self.db.commit()

        # Delete verification code from Redis
        await self.redis.delete(redis_key)

        await log_audit_event(self.db, "email_verified", user.id, "system", True)

    async def resend_verification(self, email: str):
        """
        Resend email verification code.
        """
        # Find user by email
        stmt = select(User).where(User.email == email)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user:
            # Don't reveal if user exists (security)
            return

        if user.is_verified:
            # Already verified, don't send
            return

        # Generate new verification code
        import secrets
        verification_code = secrets.randbelow(1000000)
        code_str = f"{verification_code:06d}"

        # Store in Redis with 15 min expiry
        redis_key = f"email_verification:{email}"
        await self.redis.setex(redis_key, 900, code_str)

        # Send email
        await self.email_service.send_verification_email(user.email, code_str)

        await log_audit_event(self.db, "verification_email_resent", user.id, "system", True)

    async def verify_reset_code(self, email: str, code: str):
        """
        Verify password reset code validity (without resetting password).
        """
        redis_key = f"password_reset:{email}"
        stored_code = await self.redis.get(redis_key)

        if not stored_code or stored_code != code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset code"
            )

        # Code is valid
        return True

    async def reset_password_with_code(self, email: str, code: str, new_password: str, ip_address: str):
        """
        Reset password using email + code instead of token.
        """
        # Verify code first
        await self.verify_reset_code(email, code)

        # Find user
        stmt = select(User).where(User.email == email)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Hash new password
        hashed_password = security.hash_password(new_password)
        user.password_hash = hashed_password

        # Revoke all existing refresh tokens
        await self._revoke_user_tokens(user.id)

        # Delete reset code from Redis
        redis_key = f"password_reset:{email}"
        await self.redis.delete(redis_key)

        await log_audit_event(self.db, "password_reset_success", user.id, ip_address, True)
        await self.db.commit()

    async def logout_all_sessions(self, user_id: uuid.UUID, ip_address: str):
        """
        Revoke all refresh tokens for a user (logout all devices).
        """
        await self._revoke_user_tokens(user_id)
        await log_audit_event(self.db, "logout_all_sessions", user_id, ip_address, True)
        await self.db.commit()
