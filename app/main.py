from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.security import load_rsa_keys
from app.core.exceptions import AuthenticationError
from app.api.v1 import auth, wellknown, users, admin
from app.db.session import engine
from app.utils.logging import setup_logging
from app.core.redis import redis_client

setup_logging()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for the application.
    Handles startup and shutdown events.
    """
    # Startup
    # 1. Ensure RSA keys exist and are loaded
    load_rsa_keys()

    # 2. Initialize Redis connection pool
    redis_client.init(settings.REDIS_URL)

    yield

    # Shutdown
    # 1. Close Redis connections
    await redis_client.close()

    # 2. Dispose Database engine
    await engine.dispose()

app = FastAPI(
    title=settings.APP_NAME,
    lifespan=lifespan,
    openapi_url="/api/v1/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Middleware
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

# Include Routers
app.include_router(auth.router, prefix="/auth", tags=["Auth"])
app.include_router(users.router, prefix="/users", tags=["Users"])
app.include_router(admin.router, prefix="/admin", tags=["Admin"])
app.include_router(wellknown.router, prefix="/.well-known", tags=["Discovery"])

@app.get("/health")
async def health_check():
    return {"status": "ok"}
