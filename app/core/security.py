import os
import secrets
import hashlib
import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

import jwt
from passlib.context import CryptContext
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import pyotp

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
        encryption_algorithm=serialization.NoEncryption()
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
            password=None,
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
    email: str,
    verified: bool,
    expires_delta: Optional[timedelta] = None,
    scope: Optional[str] = None
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

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def generate_refresh_token() -> str:
    return secrets.token_urlsafe(64)

def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def generate_totp_secret() -> str:
    return pyotp.random_base32()

def verify_totp(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)
