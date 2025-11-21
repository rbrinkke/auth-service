from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.security import load_rsa_keys
from app.core.exceptions import AuthenticationError
from app.api.v1 import auth, wellknown
from app.db.session import engine
from app.utils.logging import setup_logging
from app.core.redis import redis_client

setup_logging()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    load_rsa_keys()
    redis_client.init(settings.REDIS_URL)
    yield
    # Shutdown
    await redis_client.close()
    await engine.dispose()

app = FastAPI(
    title=settings.APP_NAME,
    lifespan=lifespan,
    openapi_url="/api/v1/openapi.json"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# Exception Handlers
@app.exception_handler(AuthenticationError)
async def auth_exception_handler(request: Request, exc: AuthenticationError):
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={
            "success": False,
            "error": {
                "code": exc.__class__.__name__,
                "message": str(exc)
            }
        }
    )

# Routes
app.include_router(auth.router, prefix="/auth", tags=["Auth"])
app.include_router(wellknown.router, prefix="/.well-known", tags=["Discovery"])

@app.get("/health")
async def health_check():
    return {"status": "ok"}
