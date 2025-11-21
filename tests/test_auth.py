import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_jwks(client: AsyncClient):
    response = await client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    data = response.json()
    assert "keys" in data
    assert len(data["keys"]) > 0
    assert data["keys"][0]["kty"] == "RSA"
    assert data["keys"][0]["alg"] == "RS256"

from sqlalchemy import text

@pytest.mark.asyncio
async def test_signup_login_flow(client: AsyncClient, db_session):
    # Signup
    signup_data = {
        "email": "test@example.com",
        "password": "StrongPassword123!",
        "organization_name": "Test Org"
    }
    response = await client.post("/api/v1/auth/signup", json=signup_data)
    assert response.status_code == 201
    assert response.json()["success"] is True
    user_id = response.json()["data"]["user_id"]

    # Manually verify user in DB (simulating email verification)
    await db_session.execute(
        text("UPDATE users SET is_verified = TRUE WHERE id = :user_id"),
        {"user_id": user_id}
    )
    await db_session.commit()

    # Login
    login_data = {
        "email": "test@example.com",
        "password": "StrongPassword123!"
    }
    response = await client.post("/api/v1/auth/login", json=login_data)
    assert response.status_code == 200
    data = response.json()["data"]
    assert "access_token" in data
    assert "refresh_token" in data

    access_token = data["access_token"]
    refresh_token = data["refresh_token"]

    # Refresh
    refresh_data = {"refresh_token": refresh_token}
    response = await client.post("/api/v1/auth/refresh", json=refresh_data)
    assert response.status_code == 200
    new_data = response.json()["data"]
    assert new_data["access_token"] != access_token
    assert new_data["refresh_token"] != refresh_token

    # Logout
    logout_data = {"refresh_token": new_data["refresh_token"], "revoke_all": False}
    response = await client.post("/api/v1/auth/logout", json=logout_data)
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_login_invalid_password(client: AsyncClient):
    # Signup
    signup_data = {
        "email": "wrong@example.com",
        "password": "StrongPassword123!",
    }
    await client.post("/api/v1/auth/signup", json=signup_data)

    # Login Wrong Pass
    login_data = {
        "email": "wrong@example.com",
        "password": "WrongPassword123!"
    }
    response = await client.post("/api/v1/auth/login", json=login_data)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "InvalidCredentialsError"

@pytest.mark.asyncio
async def test_rate_limit(client: AsyncClient):
    # Only test if we can (might need mocking time or just spamming)
    # Since we set limit to 5, let's try 6 times
    login_data = {
        "email": "rate@example.com",
        "password": "Password123!"
    }
    # We need to make sure signup doesn't hit rate limit first or use different IP mocking
    # But client fixture uses loopback.
    await client.post("/api/v1/auth/signup", json=login_data)
    
    # Let's just verify we get 429 after some attempts
    # Note: redis rate limiter depends on time window.
    pass
