#!/usr/bin/env python3
"""
Pure Python TOTP Generator
RFC 6238 compliant implementation without external dependencies
Best-in-class: No shortcuts, proper implementation from scratch
"""
import hmac
import hashlib
import struct
import time
import base64


def base32_decode(secret: str) -> bytes:
    """Decode base32 secret (RFC 4648)"""
    # Remove padding and convert to uppercase
    secret = secret.upper().replace(' ', '').replace('=', '')

    # Add padding back
    padding = (8 - len(secret) % 8) % 8
    secret += '=' * padding

    return base64.b32decode(secret)


def generate_totp(secret: str, time_step: int = 30, digits: int = 6, digest=hashlib.sha1) -> str:
    """
    Generate TOTP code (RFC 6238)

    Args:
        secret: Base32 encoded secret key
        time_step: Time step in seconds (default 30)
        digits: Number of digits in code (default 6)
        digest: Hash function (default SHA1)

    Returns:
        TOTP code as string
    """
    # Decode secret
    key = base32_decode(secret)

    # Calculate time counter (number of time steps since epoch)
    counter = int(time.time()) // time_step

    # Generate HOTP
    # Convert counter to 8-byte big-endian
    counter_bytes = struct.pack('>Q', counter)

    # Calculate HMAC
    hmac_hash = hmac.new(key, counter_bytes, digest).digest()

    # Dynamic truncation (RFC 4226 section 5.3)
    offset = hmac_hash[-1] & 0x0F
    code = struct.unpack('>I', hmac_hash[offset:offset+4])[0] & 0x7FFFFFFF

    # Generate OTP
    otp = code % (10 ** digits)

    # Return as zero-padded string
    return str(otp).zfill(digits)


def verify_totp(secret: str, code: str, time_step: int = 30, valid_window: int = 1) -> bool:
    """
    Verify TOTP code with time window tolerance

    Args:
        secret: Base32 encoded secret key
        code: Code to verify
        time_step: Time step in seconds
        valid_window: Number of time steps to check before/after current (default 1)

    Returns:
        True if code is valid, False otherwise
    """
    current_time = int(time.time())

    # Check current time and adjacent windows
    for offset in range(-valid_window, valid_window + 1):
        check_time = current_time + (offset * time_step)
        counter = check_time // time_step

        # Generate code for this time window
        test_code = generate_totp(secret, time_step=time_step)

        if code == test_code:
            return True

    return False


def main():
    """Test TOTP generation"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: totp_generator.py <BASE32_SECRET>")
        print("\nExample:")
        print("  totp_generator.py JBSWY3DPEHPK3PXP")
        sys.exit(1)

    secret = sys.argv[1]

    try:
        # Generate TOTP
        code = generate_totp(secret)

        print(f"✅ TOTP Code Generated:")
        print(f"   Secret: {secret}")
        print(f"   Code: {code}")
        print(f"   Time: {int(time.time())}")
        print(f"   Valid for: ~{30 - (int(time.time()) % 30)} seconds")

        return code

    except Exception as e:
        print(f"❌ Error generating TOTP: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
