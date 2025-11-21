from pydantic import BaseModel, EmailStr, ConfigDict, Field, field_validator
from typing import Optional, List, Any
import re
from uuid import UUID
from datetime import datetime

# Base Schemas
class APIResponse(BaseModel):
    success: bool
    data: Optional[Any] = None
    error: Optional[Any] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class ErrorDetail(BaseModel):
    code: str
    message: str
    details: Optional[Any] = None

# Auth Schemas
class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    organization_name: Optional[str] = None

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one number')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        return v

class UserLogin(BaseModel):
    email: EmailStr
    password: str
    device_info: Optional[dict] = None

class MFAVerify(BaseModel):
    session_token: str
    totp_code: str

class RefreshRequest(BaseModel):
    refresh_token: str

class LogoutRequest(BaseModel):
    refresh_token: str
    revoke_all: bool = False

class SwitchOrgRequest(BaseModel):
    target_org_id: UUID

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)

    @field_validator("new_password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one number')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        return v

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int

class MFAResponse(BaseModel):
    mfa_required: bool = True
    session_token: str

# User Read Schemas
class UserRead(BaseModel):
    id: UUID
    email: EmailStr
    is_verified: bool
    mfa_enabled: bool

    model_config = ConfigDict(from_attributes=True)

class OrganizationRead(BaseModel):
    id: UUID
    name: str
    slug: str

    model_config = ConfigDict(from_attributes=True)

class AuditLogRead(BaseModel):
    id: UUID
    event_type: str
    user_id: Optional[UUID]
    ip_address: str
    success: bool
    details: Optional[dict]
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)
