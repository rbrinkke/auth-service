from redis.asyncio import Redis
from fastapi import HTTPException, Request, Response
from app.core.config import settings
import time

class RateLimiter:
    def __init__(self):
        pass

    async def check_limit(self, redis: Redis, key: str, limit: int, window: int, response: Response = None):
        current = await redis.incr(key)
        if current == 1:
            await redis.expire(key, window)
            ttl = window
        else:
            ttl = await redis.ttl(key)
            if ttl < 0: ttl = 0 # Should not happen if key exists

        reset_time = int(time.time() + ttl)
        remaining = max(0, limit - current)

        if response:
            response.headers["X-RateLimit-Limit"] = str(limit)
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            response.headers["X-RateLimit-Reset"] = str(reset_time)

        if current > limit:
            headers = {
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(reset_time)
            }
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded",
                headers=headers
            )

    async def limit(self, redis: Redis, identifier: str, endpoint: str, limit: int, window: int, response: Response = None):
        key = f"ratelimit:{endpoint}:{identifier}"
        await self.check_limit(redis, key, limit, window, response)

# Global rate limiter instance
limiter = RateLimiter()
