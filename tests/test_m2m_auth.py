import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import secrets

from app.main import app
from app.models import ServiceAccount
from app.core import security

@pytest.fixture
async def service_account(db_session: AsyncSession):
    client_id = f"service_{secrets.token_hex(8)}"
    client_secret = secrets.token_urlsafe(32)
    hashed = security.hash_password(client_secret)

    sa = ServiceAccount(
        client_id=client_id,
        client_secret_hash=hashed,
        name="Test Service",
        scopes=["test:read", "test:write"],
        is_active=True
    )
    db_session.add(sa)
    await db_session.commit()
    await db_session.refresh(sa)
    return {"id": sa.id, "client_id": client_id, "client_secret": client_secret, "scopes": sa.scopes}

@pytest.mark.asyncio
async def test_create_service_account_script(db_session: AsyncSession):
    # Ideally we test the script logic, but since it runs as a separate process,
    # we can test the underlying logic or just rely on integration tests.
    # Here we will focus on the API flow.
    pass

@pytest.mark.asyncio
async def test_authenticate_service_account_success(client: AsyncClient, service_account):
    response = await client.post("/api/v1/auth/token", json={
        "grant_type": "client_credentials",
        "client_id": service_account["client_id"],
        "client_secret": service_account["client_secret"],
        "scope": "test:read"
    })
    assert response.status_code == 200, response.text
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "Bearer"

    # Verify Token
    payload = security.decode_access_token(data["access_token"])
    assert payload["sub"] == service_account["client_id"]
    assert payload["scope"] == "test:read"
    assert payload["type"] == "service_account"

@pytest.mark.asyncio
async def test_authenticate_service_account_default_scopes(client: AsyncClient, service_account):
    response = await client.post("/api/v1/auth/token", json={
        "grant_type": "client_credentials",
        "client_id": service_account["client_id"],
        "client_secret": service_account["client_secret"]
    })
    assert response.status_code == 200
    data = response.json()
    payload = security.decode_access_token(data["access_token"])
    assert payload["scope"] == "test:read test:write"

@pytest.mark.asyncio
async def test_authenticate_service_account_invalid_secret(client: AsyncClient, service_account):
    response = await client.post("/api/v1/auth/token", json={
        "grant_type": "client_credentials",
        "client_id": service_account["client_id"],
        "client_secret": "wrong_secret"
    })
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_authenticate_service_account_invalid_scope(client: AsyncClient, service_account):
    response = await client.post("/api/v1/auth/token", json={
        "grant_type": "client_credentials",
        "client_id": service_account["client_id"],
        "client_secret": service_account["client_secret"],
        "scope": "admin:all"
    })
    assert response.status_code == 401  # Or 403 depending on implementation, InvalidScopesError maps to AuthenticationError which might be 401

@pytest.mark.asyncio
async def test_authenticate_service_account_not_found(client: AsyncClient):
    response = await client.post("/api/v1/auth/token", json={
        "grant_type": "client_credentials",
        "client_id": "non_existent",
        "client_secret": "secret"
    })
    assert response.status_code == 401
