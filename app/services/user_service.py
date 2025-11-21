import uuid
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from redis.asyncio import Redis

from app.models import User, Organization, OrganizationMember, EmailVerificationCode
from app.schemas.auth import UserCreate
from app.core import security
from app.core.exceptions import EmailAlreadyExistsError, UserNotFoundError, InvalidVerificationCodeError
from app.services.audit_service import log_audit_event
from app.services.email import get_email_provider

class UserService:
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
            raise EmailAlreadyExistsError("Email already registered")

        # Hash password
        hashed_password = await security.hash_password(user_in.password)

        # Create User
        user = User(
            email=user_in.email,
            password_hash=hashed_password,
            is_verified=False,
            mfa_secret=security.encrypt_mfa_secret(security.generate_totp_secret())
        )
        self.db.add(user)
        await self.db.flush()

        # If Org provided
        if user_in.organization_name:
            # Flush to get user ID
            await self.db.flush()
            org = Organization(
                name=user_in.organization_name,
                slug=user_in.organization_name.lower().replace(" ", "-")
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

        # Generate and send verification email
        verification_code = secrets.randbelow(1000000)
        code_str = f"{verification_code:06d}"
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

        verification_entry = EmailVerificationCode(
            user_id=user.id,
            code=code_str,
            expires_at=expires_at
        )
        self.db.add(verification_entry)

        await self.email_service.send_verification_email(user.email, code_str)

        await self.db.commit()
        await self.db.refresh(user)
        return user

    async def verify_email(self, email: str, code: str):
        """
        Verify email address with verification code.
        """
        # Find user first
        stmt = select(User).where(User.email == email)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user:
            raise UserNotFoundError("User not found")

        # Check DB for code
        stmt = select(EmailVerificationCode).where(
            EmailVerificationCode.user_id == user.id,
            EmailVerificationCode.code == code,
            EmailVerificationCode.expires_at > datetime.now(timezone.utc)
        )
        result = await self.db.execute(stmt)
        verification_entry = result.scalar_one_or_none()

        if not verification_entry:
            raise InvalidVerificationCodeError("Invalid or expired verification code")

        # Mark as verified
        user.is_verified = True

        # Delete all verification codes for this user
        stmt = delete(EmailVerificationCode).where(EmailVerificationCode.user_id == user.id)
        await self.db.execute(stmt)

        await self.db.commit()

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
        verification_code = secrets.randbelow(1000000)
        code_str = f"{verification_code:06d}"
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

        # Store in DB
        verification_entry = EmailVerificationCode(
            user_id=user.id,
            code=code_str,
            expires_at=expires_at
        )
        self.db.add(verification_entry)

        # Send email
        await self.email_service.send_verification_email(user.email, code_str)

        await log_audit_event(self.db, "verification_email_resent", user.id, "system", True)
        await self.db.commit()
