import sys
import json
import uuid
import pytest
from typing import AsyncGenerator
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

from app.main import app
from app.db.session import get_db
from app.db.base import Base
from app.api.v1.auth import get_redis
from app.core.config import settings
from app.core.redis import redis_client # Import redis_client

TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"

engine = create_async_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False}
)

TestingSessionLocal = async_sessionmaker(
    engine,
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
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
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

    app.dependency_overrides[get_db] = override_get_db

    # Mock Redis
    import fakeredis.aioredis
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)

    # Mock global redis client
    redis_client._client = fake_redis

    async def override_get_redis():
        return fake_redis

    app.dependency_overrides[get_redis] = override_get_redis

    # httpx 0.28.0+ deprecation fix: usage of ASGITransport
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c

    app.dependency_overrides.clear()
    # Reset redis client
    redis_client._client = None
    await fake_redis.aclose()
