from redis.asyncio import Redis
from typing import Optional

class RedisClient:
    _client: Optional[Redis] = None

    @classmethod
    def get_client(cls) -> Redis:
        if cls._client is None:
            raise RuntimeError("Redis client not initialized")
        return cls._client

    @classmethod
    def init(cls, url: str):
        cls._client = Redis.from_url(url, encoding="utf-8", decode_responses=True)

    @classmethod
    async def close(cls):
        if cls._client:
            await cls._client.close()
            cls._client = None

redis_client = RedisClient
