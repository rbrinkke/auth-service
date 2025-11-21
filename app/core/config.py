from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Optional

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore"
    )

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://user:password@localhost:5432/idp_db"
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 40

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Security
    PRIVATE_KEY_PATH: str = "./keys/private_key.pem"
    PUBLIC_KEY_PATH: str = "./keys/public_key.pem"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # UPDATED: Strictly required for production security
    MFA_ENCRYPTION_KEY: str  # 32 byte url-safe base64 encoded key

    # Application
    APP_NAME: str = "Enterprise IdP"
    ISSUER_URL: str = "https://idp.example.com"
    CORS_ORIGINS: List[str] = ["http://localhost:3000"]
    LOG_LEVEL: str = "INFO"

    # Rate Limiting
    LOGIN_RATE_LIMIT: int = 5
    LOGIN_RATE_WINDOW: int = 900  # 15 minutes

settings = Settings()
