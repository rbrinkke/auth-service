from redis.asyncio import Redis
from fastapi import HTTPException, Request
from app.core.config import settings

class RateLimiter:
    def __init__(self):
        # We don't initialize Redis here anymore to allow dependency injection
        # However, for the app to work without dependency injection in some places,
        # we might want a default, but for "clean architecture" and testing,
        # we should pass the client.
        pass

    async def check_limit(self, redis: Redis, key: str, limit: int, window: int):
        current = await redis.incr(key)
        if current == 1:
            await redis.expire(key, window)

        if current > limit:
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded"
            )

    async def limit(self, redis: Redis, identifier: str, endpoint: str, limit: int, window: int):
        key = f"ratelimit:{endpoint}:{identifier}"
        await self.check_limit(redis, key, limit, window)

# Global rate limiter instance
limiter = RateLimiter()
