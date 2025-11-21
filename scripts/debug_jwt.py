#!/usr/bin/env python3
"""
Debug JWT validation issue
Tests JWT token validation step-by-step
"""
import sys
import asyncio
import httpx

async def test_jwt_endpoint():
    """Test /users/me endpoint with detailed debugging"""

    # Read token
    with open('/tmp/mfa_token.txt') as f:
        token = f.read().strip()

    print("=" * 60)
    print("JWT Validation Debug Test")
    print("=" * 60)

    # Test 1: Check token format
    print(f"\n1. Token format check:")
    print(f"   Length: {len(token)} chars")
    print(f"   Starts with: {token[:20]}...")
    print(f"   Has 3 parts: {len(token.split('.')) == 3}")

    # Test 2: Direct HTTP request with different headers
    print(f"\n2. Testing HTTP request variations:")

    base_url = "http://localhost:8000"

    # Variation 1: Bearer with capital B
    print(f"\n   Variation 1: Authorization: Bearer <token>")
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{base_url}/users/me",
                headers={"Authorization": f"Bearer {token}"}
            )
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text[:200]}")
        except Exception as e:
            print(f"   Error: {e}")

    # Variation 2: Check health endpoint first
    print(f"\n   Variation 2: Testing health endpoint")
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{base_url}/health")
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.json()}")
        except Exception as e:
            print(f"   Error: {e}")

    # Variation 3: Test with httpx follow redirects
    print(f"\n   Variation 3: With follow_redirects=True")
    async with httpx.AsyncClient(follow_redirects=True) as client:
        try:
            response = await client.get(
                f"{base_url}/users/me",
                headers={"Authorization": f"Bearer {token}"}
            )
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text[:200]}")
        except Exception as e:
            print(f"   Error: {e}")

    # Test 3: Validate token in container
    print(f"\n3. Validating token in application context:")
    # This would be run inside the container
    print(f"   (Run inside container to test)")

if __name__ == "__main__":
    asyncio.run(test_jwt_endpoint())
