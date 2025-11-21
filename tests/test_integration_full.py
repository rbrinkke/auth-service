import pytest
import pyotp
from sqlalchemy import text
from app.db.session import AsyncSessionLocal

# Configuration
USER_EMAIL = "integration.test@example.com"
USER_PASSWORD = "Password123!"

# Context to share state between tests steps
# Since we are running in one async function or multiple steps, we can pass state.
# But pytest functions are independent.
# However, if we write a single long scenario test, we can keep state in local variables.
# The prompt asks for "Scenario to Implement" which suggests a flow.
# I will implement it as a single async test function to maintain state easily,
# or a class with ordering, but a single function is often cleaner for "stories".

@pytest.mark.asyncio
async def test_full_integration_flow(client, db_session):
    # 1. Signup
    response = await client.post("/auth/signup", json={
        "email": USER_EMAIL,
        "password": USER_PASSWORD,
        "organization_name": "TestOrg"
    })
    assert response.status_code == 201, response.text
    assert response.json()["success"] is True

    # 2. Backdoor Verification
    # We use the db_session fixture which is connected to the same sqlite db
    await db_session.execute(
        text("UPDATE users SET is_verified = 1 WHERE email = :email"),
        {"email": USER_EMAIL}
    )
    await db_session.commit()

    # 3. Initial Login
    response = await client.post("/auth/login", json={
        "email": USER_EMAIL,
        "password": USER_PASSWORD
    })
    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert "access_token" in data
    assert "refresh_token" in data
    access_token = data["access_token"]
    refresh_token = data["refresh_token"]

    # 4. MFA Setup
    headers = {"Authorization": f"Bearer {access_token}"}

    # Get Secret
    response = await client.get("/users/mfa/secret", headers=headers)
    assert response.status_code == 200, response.text
    data = response.json()["data"]
    mfa_secret = data["secret"]
    assert mfa_secret is not None

    # Enable MFA
    response = await client.post("/users/mfa/enable", headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["success"] is True

    # 5. MFA Login Flow
    # Login again
    response = await client.post("/auth/login", json={
        "email": USER_EMAIL,
        "password": USER_PASSWORD
    })
    assert response.status_code == 200, response.text
    data = response.json()["data"]

    # Assert MFA required
    assert data.get("mfa_required") is True
    session_token = data.get("session_token")
    assert session_token is not None

    # Generate TOTP
    totp = pyotp.TOTP(mfa_secret)
    code = totp.now()

    # Submit code
    response = await client.post("/auth/mfa/verify", json={
        "session_token": session_token,
        "totp_code": code
    })

    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert "access_token" in data
    assert "refresh_token" in data

    # Update tokens
    new_access_token = data["access_token"]
    new_refresh_token = data["refresh_token"]

    # 6. Token Validation
    headers = {"Authorization": f"Bearer {new_access_token}"}
    response = await client.get("/users/me", headers=headers)
    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert data["email"] == USER_EMAIL
    assert data["mfa_enabled"] is True

    # 7. Cleanup (Self Deletion)
    response = await client.delete("/users/me", headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["success"] is True

    # 8. Verify Cleanup
    # Attempt login again
    # We expect 401 because the user should not exist (or authentication fails)
    # The login endpoint will try to find the user.
    response = await client.post("/auth/login", json={
        "email": USER_EMAIL,
        "password": USER_PASSWORD
    })

    # If user not found, AuthService.authenticate_user typically raises AuthenticationError -> 401
    assert response.status_code == 401, response.text
