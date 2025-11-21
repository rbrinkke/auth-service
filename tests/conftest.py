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

@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"

@pytest.fixture(scope="function")
async def init_db():
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

    # Mock global redis client logic
    original_init = redis_client.init
    original_close = redis_client.close

    redis_client.init = MagicMock()

    async def dummy_close():
        pass
    redis_client.close = dummy_close

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
    redis_client.init = original_init
    redis_client.close = original_close
    await fake_redis.aclose()
