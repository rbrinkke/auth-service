import os
import secrets
import hashlib
import base64
import json
import asyncio
import time
import struct
import hmac
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

import jwt
from passlib.context import CryptContext
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

from app.core.config import settings
from app.core.exceptions import TokenExpiredError, InvalidTokenError

# Password hashing context
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__memory_cost=65536,  # 64 MB
    argon2__time_cost=3,
    argon2__parallelism=4
)

_PRIVATE_KEY_OBJ: Optional[rsa.RSAPrivateKey] = None
_PUBLIC_KEY_OBJ: Optional[rsa.RSAPublicKey] = None
_PUBLIC_KEY_PEM: Optional[str] = None
_JWK_SET: Optional[Dict[str, Any]] = None
_MFA_FERNET: Optional[Fernet] = None

def get_mfa_fernet() -> Fernet:
    """
    Singleton accessor for the Fernet encryption instance.
    Relies strictly on the environment variable to avoid insecure defaults.
    """
    global _MFA_FERNET
    if _MFA_FERNET is None:
        # UPDATED: Removed fallback. Settings will raise error on startup if key is missing.
        try:
             _MFA_FERNET = Fernet(settings.MFA_ENCRYPTION_KEY)
        except Exception as e:
             raise RuntimeError(f"Invalid MFA_ENCRYPTION_KEY configuration: {str(e)}")
    return _MFA_FERNET

def encrypt_mfa_secret(secret: str) -> str:
    f = get_mfa_fernet()
    return f.encrypt(secret.encode()).decode()

def decrypt_mfa_secret(encrypted_secret: str) -> str:
    f = get_mfa_fernet()
    return f.decrypt(encrypted_secret.encode()).decode()

def generate_rsa_keypair() -> None:
    """
    Checks if RSA keypair exists. If not, generates 2048-bit RSA keypair
    and saves them to the configured paths with appropriate permissions.
    """
    private_path = Path(settings.PRIVATE_KEY_PATH)
    public_path = Path(settings.PUBLIC_KEY_PATH)

    if private_path.exists() and public_path.exists():
        return

    # Ensure directory exists
    private_path.parent.mkdir(parents=True, exist_ok=True)

    # Generate Key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Serialize Private Key
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(settings.PRIVATE_KEY_PASSWORD.encode())
    )

    # Serialize Public Key
    public_key = key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Write Private Key
    with open(private_path, "wb") as f:
        f.write(private_pem)
    os.chmod(private_path, 0o600)

    # Write Public Key
    with open(public_path, "wb") as f:
        f.write(public_pem)
    os.chmod(public_path, 0o644)

def load_rsa_keys() -> None:
    """
    Loads RSA keys into memory and generates JWK set.
    Must be called on application startup.
    """
    global _PRIVATE_KEY_OBJ, _PUBLIC_KEY_OBJ, _PUBLIC_KEY_PEM, _JWK_SET

    if not Path(settings.PRIVATE_KEY_PATH).exists() or not Path(settings.PUBLIC_KEY_PATH).exists():
        generate_rsa_keypair()

    with open(settings.PRIVATE_KEY_PATH, "rb") as f:
        _PRIVATE_KEY_OBJ = serialization.load_pem_private_key(
            f.read(),
            password=settings.PRIVATE_KEY_PASSWORD.encode(),
            backend=default_backend()
        )

    with open(settings.PUBLIC_KEY_PATH, "rb") as f:
        pub_pem_bytes = f.read()
        _PUBLIC_KEY_PEM = pub_pem_bytes.decode()
        _PUBLIC_KEY_OBJ = serialization.load_pem_public_key(
            pub_pem_bytes,
            backend=default_backend()
        )

    # Generate JWK
    public_numbers = _PUBLIC_KEY_OBJ.public_numbers()

    def int_to_base64(value):
        """Convert an integer to a Base64URL-encoded string"""
        value_hex = format(value, 'x')
        if len(value_hex) % 2 == 1:
            value_hex = '0' + value_hex
        value_bytes = bytes.fromhex(value_hex)
        return base64.urlsafe_b64encode(value_bytes).rstrip(b'=').decode('ascii')

    e = int_to_base64(public_numbers.e)
    n = int_to_base64(public_numbers.n)

    # Key ID
    kid = hashlib.sha256(pub_pem_bytes).hexdigest()[:16]

    jwk_dict = {
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "kid": kid,
        "n": n,
        "e": e
    }

    _JWK_SET = {"keys": [jwk_dict]}

def get_private_key() -> rsa.RSAPrivateKey:
    if _PRIVATE_KEY_OBJ is None:
        load_rsa_keys()
    if _PRIVATE_KEY_OBJ is None:
         raise RuntimeError("Private key not loaded")
    return _PRIVATE_KEY_OBJ

def get_public_key_pem() -> str:
    if _PUBLIC_KEY_PEM is None:
        load_rsa_keys()
    if _PUBLIC_KEY_PEM is None:
        raise RuntimeError("Public key not loaded")
    return _PUBLIC_KEY_PEM

def public_key_to_jwk() -> Dict[str, Any]:
    """Returns the JWK Set."""
    if _JWK_SET is None:
        load_rsa_keys()
    if _JWK_SET is None:
        raise RuntimeError("JWK Set not loaded")
    return _JWK_SET

def create_access_token(
    user_id: str,
    org_id: Optional[str],
    roles: list[str],
    email: Optional[str],
    verified: bool,
    expires_delta: Optional[timedelta] = None,
    scope: Optional[str] = None,
    claims: Optional[Dict[str, Any]] = None
) -> str:
    """
    Creates a JWT access token using RS256.
    """
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    jwks = public_key_to_jwk()
    kid = jwks["keys"][0]["kid"]

    to_encode = {
        "iss": settings.ISSUER_URL,
        "sub": str(user_id),
        "exp": expire,
        "iat": now,
        "jti": secrets.token_hex(16),
        "org_id": str(org_id) if org_id else None,
        "roles": roles,
        "email": email,
        "verified": verified
    }
    if scope:
        to_encode["scope"] = scope

    if claims:
        to_encode.update(claims)

    encoded_jwt = jwt.encode(
        to_encode,
        get_private_key(),
        algorithm="RS256",
        headers={"kid": kid}
    )
    return encoded_jwt

def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decodes and validates the JWT access token.
    """
    try:
        payload = jwt.decode(
            token,
            get_public_key_pem(),
            algorithms=["RS256"],
            issuer=settings.ISSUER_URL,
            options={"verify_exp": True, "verify_iss": True}
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise TokenExpiredError("Token has expired")
    except jwt.PyJWTError as e:
        raise InvalidTokenError(f"Could not validate credentials: {str(e)}")

async def verify_password(plain_password: str, hashed_password: str) -> bool:
    return await asyncio.to_thread(pwd_context.verify, plain_password, hashed_password)

async def hash_password(password: str) -> str:
    return await asyncio.to_thread(pwd_context.hash, password)

def generate_refresh_token() -> str:
    return secrets.token_urlsafe(64)

def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

# --- Pure Python TOTP Implementation (RFC 6238) ---

def base32_decode(secret: str) -> bytes:
    """Decode base32 secret (RFC 4648)"""
    # Remove padding and convert to uppercase
    secret = secret.upper().replace(' ', '').replace('=', '')
    # Add padding back
    padding_len = (8 - len(secret) % 8) % 8
    secret += '=' * padding_len
    return base64.b32decode(secret)

def _generate_totp_code(secret: str, time_step: int = 30, digits: int = 6, digest=hashlib.sha1) -> str:
    """
    Generate TOTP code (RFC 6238)
    Internal helper.
    """
    try:
        key = base32_decode(secret)
    except Exception:
        # Invalid base32 string
        return ""

    # Calculate time counter
    counter = int(time.time()) // time_step

    # Convert counter to 8-byte big-endian
    counter_bytes = struct.pack('>Q', counter)

    # Calculate HMAC
    hmac_hash = hmac.new(key, counter_bytes, digest).digest()

    # Dynamic truncation
    offset = hmac_hash[-1] & 0x0F
    code = struct.unpack('>I', hmac_hash[offset:offset+4])[0] & 0x7FFFFFFF

    # Generate OTP
    otp = code % (10 ** digits)

    return str(otp).zfill(digits)

def generate_totp_secret() -> str:
    """
    Generate a random base32 encoded secret.
    """
    # Generate 20 bytes (160 bits) of randomness, which encodes to 32 base32 characters.
    # standard for Google Authenticator is 16 bytes (128 bits) or 20 bytes (160 bits).
    # pyotp.random_base32() generates 32 chars which corresponds to 20 bytes.
    random_bytes = secrets.token_bytes(20)
    return base64.b32encode(random_bytes).decode('utf-8').replace('=', '')

def verify_totp(secret: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify TOTP code with time window tolerance.
    """
    if not secret or not code:
        return False

    try:
        key = base32_decode(secret)
    except Exception:
        return False

    current_time = int(time.time())
    time_step = 30
    digits = 6
    digest = hashlib.sha1

    # Check current time and adjacent windows
    for offset in range(-valid_window, valid_window + 1):
        check_time = current_time + (offset * time_step)
        counter = check_time // time_step

        counter_bytes = struct.pack('>Q', counter)
        hmac_hash = hmac.new(key, counter_bytes, digest).digest()
        offset_byte = hmac_hash[-1] & 0x0F
        binary = struct.unpack('>I', hmac_hash[offset_byte:offset_byte+4])[0] & 0x7FFFFFFF
        otp = binary % (10 ** digits)
        test_code = str(otp).zfill(digits)

        if code == test_code:
            return True

    return False

def generate_provisioning_uri(secret: str, name: str, issuer_name: Optional[str] = None) -> str:
    """
    Generate otpauth URI for QR code generation.
    Format: otpauth://totp/{label}?secret={secret}&issuer={issuer}
    Label is usually {issuer}:{name} or just {name}.
    """
    from urllib.parse import quote

    label = quote(name)
    if issuer_name:
        label = f"{quote(issuer_name)}:{label}"

    uri = f"otpauth://totp/{label}?secret={secret}"

    if issuer_name:
        uri += f"&issuer={quote(issuer_name)}"

    return uri
