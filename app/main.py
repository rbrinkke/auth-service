from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.security import load_rsa_keys
from app.core.exceptions import (
    AuthenticationError,
    EmailAlreadyExistsError,
    UserNotFoundError,
    InvalidVerificationCodeError,
    OrganizationNotFoundError,
    MembershipNotFoundError
)
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

@app.exception_handler(EmailAlreadyExistsError)
async def email_exists_exception_handler(request: Request, exc: EmailAlreadyExistsError):
    return JSONResponse(
        status_code=status.HTTP_409_CONFLICT,
        content={
            "success": False,
            "error": {
                "code": "EmailAlreadyExistsError",
                "message": str(exc)
            }
        }
    )

@app.exception_handler(UserNotFoundError)
async def user_not_found_exception_handler(request: Request, exc: UserNotFoundError):
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={
            "success": False,
            "error": {
                "code": "UserNotFoundError",
                "message": str(exc)
            }
        }
    )

@app.exception_handler(InvalidVerificationCodeError)
async def invalid_code_exception_handler(request: Request, exc: InvalidVerificationCodeError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "success": False,
            "error": {
                "code": "InvalidVerificationCodeError",
                "message": str(exc)
            }
        }
    )

@app.exception_handler(OrganizationNotFoundError)
async def org_not_found_exception_handler(request: Request, exc: OrganizationNotFoundError):
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={
            "success": False,
            "error": {
                "code": "OrganizationNotFoundError",
                "message": str(exc)
            }
        }
    )

@app.exception_handler(MembershipNotFoundError)
async def membership_not_found_exception_handler(request: Request, exc: MembershipNotFoundError):
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={
            "success": False,
            "error": {
                "code": "MembershipNotFoundError",
                "message": str(exc)
            }
        }
    )

# Include Routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Auth"])
app.include_router(users.router, prefix="/api/v1/users", tags=["Users"])
app.include_router(admin.router, prefix="/api/v1/admin", tags=["Admin"])
app.include_router(wellknown.router, prefix="/.well-known", tags=["Discovery"])

@app.get("/health")
async def health_check():
    return {"status": "ok"}
