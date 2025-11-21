import os
import sys
import json
import uuid
import pytest
from typing import AsyncGenerator
from unittest.mock import MagicMock

# 1. Force DATABASE_URL to be SQLite BEFORE importing any app code
# This prevents the app from trying to connect to Postgres (5432)
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"
os.environ["DATABASE_URL"] = TEST_DATABASE_URL

from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.types import TypeDecorator, TEXT, String
import sqlalchemy.dialects.postgresql

# --- PATCH POSTGRES TYPES FOR SQLITE ---
import sqlalchemy.dialects.postgresql

class MockARRAY(TypeDecorator):
    impl = TEXT
    cache_ok = True
    def process_bind_param(self, value, dialect):
        return json.dumps(value) if value is not None else None
    def process_result_value(self, value, dialect):
        return json.loads(value) if value is not None else None
    def __init__(self, item_type=None, as_tuple=False, dimension=None, zero_indexes=False):
        super().__init__()

class MockJSONB(TypeDecorator):
    impl = TEXT
    cache_ok = True
    def process_bind_param(self, value, dialect):
        return json.dumps(value) if value is not None else None
    def process_result_value(self, value, dialect):
        return json.loads(value) if value is not None else None

class MockUUID(TypeDecorator):
    impl = String
    cache_ok = True
    def process_bind_param(self, value, dialect):
        return str(value) if value is not None else None
    def process_result_value(self, value, dialect):
        try:
            return uuid.UUID(value) if value is not None else None
        except ValueError:
            return None
    def __init__(self, as_uuid=True):
        super().__init__()

# Apply patches BEFORE importing app models
sqlalchemy.dialects.postgresql.ARRAY = MockARRAY
sqlalchemy.dialects.postgresql.JSONB = MockJSONB
sqlalchemy.dialects.postgresql.UUID = MockUUID
# ---------------------------------------

# Import app modules
import app.db.session
from app.main import app as fastapi_app
from app.db.session import get_db
from app.db.base import Base
from app.api.v1.auth import get_redis
from app.core.redis import redis_client

# Create Test Engine (configured for SQLite)
test_engine = create_async_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False}
)

# Patch the engine in app.db.session (used by dependencies)
app.db.session.engine = test_engine

# Patch the engine in app.main (used by lifespan)
import app.main
app.main.engine = test_engine

TestingSessionLocal = async_sessionmaker(
    test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False
)

@pytest.fixture(scope="function", autouse=True)
async def cleanup_redis():
    """Flush Redis before each test to clear rate limits and other state."""
    import redis.asyncio as aioredis
    try:
        # Connect to exposed Docker port 6380
        redis_client = await aioredis.from_url("redis://localhost:6380/0")
        await redis_client.flushall()
        await redis_client.aclose()
    except Exception as e:
        print(f"Warning: Could not connect to Redis or flush: {e}")
    yield

@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"

@pytest.fixture(scope="function")
async def init_db():
    # Import app.models here to ensure models are loaded before create_all
    import app.models 
    # Create tables
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

@pytest.fixture
async def db_session(init_db) -> AsyncGenerator[AsyncSession, None]:
    async with TestingSessionLocal() as session:
        yield session

@pytest.fixture
async def client(db_session) -> AsyncGenerator[AsyncClient, None]:
    # Override dependency
    async def override_get_db():
        yield db_session

    fastapi_app.dependency_overrides[get_db] = override_get_db

    # Mock Redis
    import fakeredis.aioredis
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)

    async def dummy_close():
        pass

    # Set the client to our fake one
    redis_client._client = fake_redis

    async def override_get_redis():
        return fake_redis

    fastapi_app.dependency_overrides[get_redis] = override_get_redis

    # httpx 0.28.0+ deprecation fix: usage of ASGITransport
    async with AsyncClient(transport=ASGITransport(app=fastapi_app), base_url="http://test") as c:
        yield c

    fastapi_app.dependency_overrides.clear()

    # Restore/Cleanup
    redis_client._client = None
    await fake_redis.aclose()

@pytest.fixture
async def redis_client():
    """Mock redis client for unit tests"""
    import fakeredis.aioredis
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield fake_redis
    await fake_redis.aclose()

@pytest.fixture
async def user_factory(db_session):
    """Factory to create a user for testing"""
    from app.models import User
    from app.core.security import hash_password

    async def _create_user(email="test@example.com", password="password", is_verified=True):
        user = User(
            email=email,
            password_hash=await hash_password(password),
            is_verified=is_verified,
            mfa_enabled=False
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)
        return user

    return _create_user

# Utility functions for integration tests
def assert_jwt_structure(token: str):
    """
    Validate JWT structure without verification.
    Returns: Decoded payload (header + payload only, no signature verification)
    """
    import base64
    import json

    parts = token.split('.')
    assert len(parts) == 3, "Invalid JWT structure"

    # Decode header
    header_data = parts[0] + '=' * (-len(parts[0]) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_data))

    # Decode payload
    payload_data = parts[1] + '=' * (-len(parts[1]) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_data))

    assert "typ" in header, "Missing typ in JWT header"
    assert "alg" in header, "Missing alg in JWT header"
    assert "sub" in payload, "Missing sub in JWT payload"
    assert "exp" in payload, "Missing exp in JWT payload"

    return {"header": header, "payload": payload}


async def wait_for_rate_limit_reset(seconds: int = 61):
    """
    Wait for rate limit window to reset.
    Use this between tests that might trigger rate limiting.
    """
    import asyncio
    print(f"⏳ Waiting {seconds}s for rate limit reset...")
    await asyncio.sleep(seconds)
    print("✅ Rate limit window reset")

# Real integration test fixtures
@pytest.fixture
async def real_client():
    """HTTPx client to REAL service at localhost:8000"""
    import httpx
    async with httpx.AsyncClient(
        base_url="http://localhost:8000",
        timeout=30.0,
        follow_redirects=True
    ) as client:
        # Verify service is reachable
        try:
            response = await client.get("/health")
            assert response.status_code == 200
        except httpx.ConnectError:
            pytest.fail("Cannot connect to service at localhost:8000. Is it running?")
        yield client

@pytest.fixture
async def db_connection():
    """Direct PostgreSQL connection"""
    import asyncpg
    conn = await asyncpg.connect(
        host="localhost",
        port=5433,
        database="idp_db",
        user="user",
        password="password"
    )
    try:
        yield conn
    finally:
        await conn.close()

@pytest.fixture
async def redis_connection():
    """Direct Redis connection"""
    import redis.asyncio as aioredis
    redis_client = await aioredis.from_url("redis://localhost:6380/0", decode_responses=True)
    try:
        yield redis_client
    finally:
        await redis_client.close()

@pytest.fixture
async def test_user(real_client, db_connection):
    """Create verified test user"""
    import uuid as uuid_lib
    unique_id = str(uuid_lib.uuid4())[:8]
    email = f"test_{unique_id}@example.com"
    password = "SecurePass123!@#"

    # Register
    response = await real_client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": password, "organization_name": f"Org{unique_id}"}
    )
    assert response.status_code == 201
    data = response.json()
    user_id = data["data"]["user_id"]

    # Mark as verified
    await db_connection.execute(
        "UPDATE users SET is_verified = TRUE WHERE id = $1",
        uuid_lib.UUID(user_id)
    )

    user_data = {
        "email": email,
        "password": password,
        "user_id": user_id,
        "full_name": f"Test User {unique_id}"
    }

    yield user_data

    # Cleanup
    try:
        await db_connection.execute(
            "DELETE FROM users WHERE id = $1",
            uuid_lib.UUID(user_id)
        )
    except Exception as e:
        print(f"Warning: Failed to cleanup test user: {e}")

@pytest.fixture
async def test_admin_user(real_client, db_connection):
    """Create admin user"""
    import uuid as uuid_lib
    unique_id = str(uuid_lib.uuid4())[:8]
    email = f"admin_{unique_id}@example.com"
    password = "AdminPass123!@#"

    # 1. Register a user (without organization name initially)
    response = await real_client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": password}
    )
    assert response.status_code == 201
    signup_data = response.json()
    user_id = signup_data["data"]["user_id"]

    # Mark user as verified
    await db_connection.execute(
        "UPDATE users SET is_verified = TRUE WHERE id = $1",
        uuid_lib.UUID(user_id)
    )

    # 2. Manually create an Organization
    org_id = uuid_lib.uuid4()
    org_name = f"AdminOrg_{unique_id}"
    org_slug = org_name.lower().replace(" ", "-")
    await db_connection.execute(
        "INSERT INTO organizations (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())",
        org_id, org_name, org_slug
    )

    # 3. Manually create an OrganizationMember for the user with 'admin' role
    member_id = uuid_lib.uuid4()
    await db_connection.execute(
        "INSERT INTO organization_members (id, user_id, org_id, roles, created_at) VALUES ($1, $2, $3, $4, NOW())",
        member_id, uuid_lib.UUID(user_id), org_id, ["admin"]
    )

    user_data = {
        "email": email,
        "password": password,
        "user_id": user_id,
        "org_id": str(org_id), # Store the org_id for later use in tests
        "roles": ["admin"] # For test logic
    }

    yield user_data

    # Cleanup
    try:
        await db_connection.execute(
            "DELETE FROM users WHERE id = $1",
            uuid_lib.UUID(user_id)
        )
        await db_connection.execute(
            "DELETE FROM organizations WHERE id = $1",
            org_id
        )
        await db_connection.execute(
            "DELETE FROM organization_members WHERE id = $1",
            member_id
        )
    except Exception as e:
        print(f"Warning: Failed to cleanup admin user: {e}")

@pytest.fixture
async def user_token(real_client, test_user):
    """Login and return access token"""
    response = await real_client.post(
        "/api/v1/auth/login",
        json={"email": test_user["email"], "password": test_user["password"]}
    )
    assert response.status_code == 200
    data = response.json()
    return data["data"]["access_token"]

@pytest.fixture
async def admin_token(real_client, test_admin_user):
    """Admin login and return token"""
    response = await real_client.post(
        "/api/v1/auth/login",
        json={"email": test_admin_user["email"], "password": test_admin_user["password"], "org_id": test_admin_user["org_id"]}
    )
    assert response.status_code == 200
    data = response.json()
    token = data["data"]["access_token"]
    return token

@pytest.fixture
async def auth_headers(user_token):
    """Authorization headers with Bearer token"""
    return {"Authorization": f"Bearer {user_token}"}

@pytest.fixture
async def admin_headers(admin_token):
    """Admin authorization headers"""
    return {"Authorization": f"Bearer {admin_token}"}

@pytest.fixture
async def user_with_mfa(real_client, test_user, user_token):
    """User with MFA enabled"""
    headers = {"Authorization": f"Bearer {user_token}"}

    # Get MFA secret
    response = await real_client.get("/api/v1/users/mfa/secret", headers=headers)
    assert response.status_code == 200
    data = response.json()
    mfa_secret = data["data"]["secret"]

    # Generate TOTP (Pure Python RFC 6238)
    import hmac
    import struct
    import time
    import base64

    def generate_totp(secret: str) -> str:
        key = base64.b32decode(secret.upper() + '=' * (-len(secret) % 8))
        counter = int(time.time()) // 30
        counter_bytes = struct.pack('>Q', counter)
        hmac_hash = hmac.new(key, counter_bytes, 'sha1').digest()
        offset = hmac_hash[-1] & 0x0F
        code = struct.unpack('>I', hmac_hash[offset:offset+4])[0] & 0x7FFFFFFF
        return str(code % 1000000).zfill(6)

    totp_code = generate_totp(mfa_secret)

    # Enable MFA
    response = await real_client.post(
        "/api/v1/users/mfa/enable",
        headers=headers,
        json={"totp_code": totp_code}
    )
    assert response.status_code == 200

    user_data = {
        **test_user,
        "mfa_secret": mfa_secret,
        "totp_generator": lambda: generate_totp(mfa_secret)
    }

    yield user_data

@pytest.fixture
async def cleanup_test_users(db_connection):
    """Cleanup all test users after test"""
    yield
    try:
        await db_connection.execute(
            "DELETE FROM users WHERE email LIKE 'test_%@example.com' OR email LIKE 'admin_%@example.com'"
        )
    except Exception as e:
        print(f"Warning: Failed to cleanup test users: {e}")
