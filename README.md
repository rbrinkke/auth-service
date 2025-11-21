# Enterprise Identity Provider (IdP)

A production-ready, high-security Authentication Microservice built with FastAPI, SQLAlchemy (Async), Redis, and RS256 JWTs.

## Features

- **Standalone Verification:** Uses RS256 signatures so other services can verify tokens using only the public key.
- **Security First:**
  - Argon2id password hashing.
  - Opaque, hashed, and rotated refresh tokens.
  - Encrypted MFA secrets (Fernet).
  - Rate limiting via Redis.
  - Security headers (HSTS, etc.).
- **Architecture:**
  - Async SQLAlchemy 2.0 with PostgreSQL.
  - Clean Architecture (Services, Repositories/Models, Schemas).
  - Pydantic V2 validation.
  - Redis connection pooling.
- **Observability:**
  - Structured JSON logging.
  - JWKS endpoint for key discovery.

## Tech Stack

- Python 3.11+
- FastAPI
- PostgreSQL + asyncpg
- Redis
- PyJWT (RS256)
- Passlib (Argon2id)
- Alembic (Migrations)

## Setup

### Prerequisites

- Docker & Docker Compose

### Running the Service

1. **Clone the repository**
2. **Start infrastructure**
   ```bash
   docker-compose up --build
   ```
   The service will be available at `http://localhost:8000`.

### Environment Variables

Copy `.env.example` to `.env` and configure:

- `DATABASE_URL`: PostgreSQL connection string.
- `REDIS_URL`: Redis connection string.
- `MFA_ENCRYPTION_KEY`: 32-byte URL-safe base64 key for encrypting TOTP secrets.
- `PRIVATE_KEY_PATH` / `PUBLIC_KEY_PATH`: Paths to RSA keys (auto-generated if missing).

## API Endpoints

### Discovery
- `GET /.well-known/jwks.json`: Public JWK Set for verifying tokens.

### Authentication
- `POST /auth/signup`: Create a new user account.
- `POST /auth/login`: Authenticate user (returns JWT + Refresh Token, or MFA session).
- `POST /auth/mfa/verify`: Complete login with TOTP code.
- `POST /auth/refresh`: Rotate refresh token and get new access token.
- `POST /auth/logout`: Revoke refresh token(s).
- `POST /auth/switch-org`: Issue new access token for a different organization.

## Development

### Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest
```

## Security Notes

- **Keys:** RSA keys are generated on startup if not present. For production, mount them via volumes or secrets manager.
- **MFA:** TOTP secrets are encrypted at rest. Ensure `MFA_ENCRYPTION_KEY` is set and backed up.
- **Rate Limiting:** Enforced on sensitive endpoints to prevent abuse.
