import pytest
import uuid
from unittest.mock import MagicMock, patch, AsyncMock
from app.services.mfa_service import MFAService
from app.core.exceptions import InvalidCredentialsError
from app.core import security
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from pathlib import Path
import os

@pytest.mark.asyncio
async def test_mfa_rate_limiting_fails_after_3_attempts() -> None:
    """
    Verify that MFA verification fails and revokes session after 3 bad attempts.
    """
    # Mock dependencies
    mock_db = AsyncMock()
    mock_redis = AsyncMock()

    # Setup service
    service = MFAService(db=mock_db, redis=mock_redis)
    session_token = "test_session_token"

    # Mock Redis behavior for attempts
    # We want to verify the logic:
    # if attempts > 3: raise ...

    # Scenario: 4th attempt
    mock_redis.incr.return_value = 4

    with pytest.raises(InvalidCredentialsError) as exc_info:
        await service.verify_mfa(session_token, "123456")

    assert "Too many failed attempts" in str(exc_info.value)

    # Verify session revocation
    assert mock_redis.delete.call_count >= 2
    # It should delete session token and rate limit key
    mock_redis.delete.assert_any_call(f"mfa_session:{session_token}")
    mock_redis.delete.assert_any_call(f"mfa_attempts:{session_token}")

@pytest.mark.asyncio
async def test_mfa_rate_limiting_allows_3_attempts() -> None:
    """
    Verify that MFA verification proceeds (to validation) on 3rd attempt.
    """
    # Mock dependencies
    mock_db = AsyncMock()
    mock_redis = AsyncMock()

    # Setup service
    service = MFAService(db=mock_db, redis=mock_redis)
    session_token = "test_session_token"
    user_id = uuid.uuid4()

    # Mock Redis behavior for attempts
    mock_redis.incr.return_value = 3

    # Mock Redis returning session user
    mock_redis.get.return_value = str(user_id)

    # Mock DB returning user (incomplete setup, enough to pass the rate limit check)
    # We expect it to fail later with "Invalid user state" or similar if we don't setup user fully,
    # but crucially NOT "Too many failed attempts"

    # Let's just verify it passes the rate limit check and calls redis.get
    # To do this without crashing, we make redis.get return None, triggering "Invalid or expired session"
    # which happens AFTER rate limit check.
    mock_redis.get.return_value = None

    with pytest.raises(InvalidCredentialsError) as exc_info:
        await service.verify_mfa(session_token, "123456")

    assert "Invalid or expired session" in str(exc_info.value)
    # Ensure we didn't revoke due to rate limit
    # Revocation calls happen inside the `if attempts > 3` block
    # Note: `verify_mfa` calls delete on success, but here we failed with invalid session
    # so delete shouldn't be called except maybe for cleanup?
    # Actually looking at code: delete is called on success.
    # And on > 3 attempts.
    # So here it shouldn't be called.
    mock_redis.delete.assert_not_called()


def test_private_key_cannot_be_loaded_without_password(tmp_path: Path) -> None:
    """
    Verify that the private key cannot be loaded if the password is incorrect.
    """
    # 1. Generate a real private key file encrypted with "correct_password"
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    correct_password = b"correct_password"
    wrong_password = "wrong_password"

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(correct_password)
    )

    key_path = tmp_path / "private.pem"
    pub_path = tmp_path / "public.pem"

    with open(key_path, "wb") as f:
        f.write(pem)

    # Create dummy public key file as load_rsa_keys checks for existence
    with open(pub_path, "wb") as f:
        f.write(b"dummy public key")

    # 2. Mock settings to point to this file and use WRONG password
    with patch("app.core.security.settings") as mock_settings:
        mock_settings.PRIVATE_KEY_PATH = str(key_path)
        mock_settings.PUBLIC_KEY_PATH = str(pub_path)
        mock_settings.PRIVATE_KEY_PASSWORD = wrong_password

        # Also mock global variables in security.py to force reload or avoid side effects
        # We are testing load_rsa_keys directly, but we need to reset the global state if it was already loaded
        # However, we can just call load_rsa_keys and expect exception

        # We need to reset the globals in security module just in case,
        # or simply ensure we are calling the function that attempts the load.

        # The function is security.load_rsa_keys()

        # Verify it raises ValueError (from cryptography)
        with pytest.raises(ValueError): # cryptography raises ValueError for bad password
             security.load_rsa_keys()
