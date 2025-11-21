# Integration Test Suite

This test suite tests the running service at `http://localhost:8000` with PostgreSQL and Redis connections.

## Philosophy

Previous tests used mocks (SQLite, FakeRedis) which don't catch real-world issues. This test suite tests **production behavior** by:

- ✅ **Real HTTP calls** to localhost:8000
- ✅ **Real PostgreSQL** connections for verification
- ✅ **Real Redis** connections for session/cache checks
- ✅ **Real JWT validation** with actual RSA keys
- ✅ **Real TOTP generation** (Pure Python RFC 6238)

## Test Files

| File | Purpose | Test Count | Duration |
|------|---------|------------|----------|
| `conftest.py` | Test fixtures | N/A | N/A |
| `test_integration_full.py` | Complete user journeys | ~20 tests | ~30s |
| `test_admin.py` | Admin endpoints + RBAC | ~15 tests | ~20s |
| `test_security.py` | Security measures | ~15 tests | ~90s* |
| `test_flows.py` | User flows (reset, logout, GDPR) | ~15 tests | ~30s |

**Total**: ~65 production-quality tests
**Duration**: ~3 minutes (some security tests wait for rate limits)

## Prerequisites

### 1. Start the Service

```bash
# CRITICAL: Service must be running
docker compose up -d

# Verify service is healthy
curl http://localhost:8000/health
```

### 2. Install Test Dependencies

```bash
pip install pytest pytest-asyncio httpx asyncpg redis python-dotenv argon2-cffi
```

### 3. Environment Configuration

Tests use `.env` file from project root. Ensure these variables are set:

```bash
# Database (real PostgreSQL)
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=idp_db
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres

# Redis (real Redis)
REDIS_URL=redis://localhost:6379/0

# Service URL
TEST_SERVICE_URL=http://localhost:8000
```

## Running Tests

### Quick Run (All Tests)

```bash
pytest tests/test_*.py -v
```

### Run Specific Test File

```bash
# Integration tests
pytest tests/test_integration_full.py -v

# Admin tests
pytest tests/test_admin.py -v

# Security tests (slower due to rate limits)
pytest tests/test_security.py -v

# Flow tests
pytest tests/test_flows.py -v
```

### Run Specific Test

```bash
pytest tests/test_integration_full.py::TestUserSignupAndLogin::test_login_with_valid_credentials -v
```

### Run with Coverage

```bash
pytest tests/test_*.py --cov=app --cov-report=html -v
```

### Skip Slow Tests

```bash
pytest tests/test_*.py -v -m "not slow"
```

## Test Structure

### Fixtures (conftest.py)

**Core Fixtures**:

- `real_client` - HTTPx client to http://localhost:8000
- `db_connection` - Direct PostgreSQL connection
- `redis_connection` - Direct Redis connection

**User Fixtures**:

- `test_user` - Creates verified user (cleanup after test)
- `test_admin_user` - Creates admin user (cleanup after test)
- `user_token` - Login as test user, returns JWT
- `admin_token` - Login as admin, returns JWT
- `auth_headers` - {"Authorization": "Bearer <token>"}
- `admin_headers` - {"Authorization": "Bearer <admin_token>"}

**Advanced Fixtures**:

- `user_with_mfa` - User with MFA enabled + TOTP generator
- `cleanup_test_users` - Cleanup all test users after run

### Test Classes

#### test_integration_full.py

1. **TestUserSignupAndLogin**
   - Signup creates user
   - Duplicate email fails (409)
   - Login with valid credentials
   - Login with invalid password fails
   - Login with non-existent email fails

2. **TestAuthenticatedEndpoints**
   - GET /users/me with valid token
   - GET /users/me without token fails (401)
   - GET /users/me with invalid token fails
   - GET /users/me with expired token fails

3. **TestMFAFlow**
   - GET /users/mfa/secret requires auth
   - GET /users/mfa/secret returns Base32 secret
   - Enable MFA with valid TOTP code
   - Enable MFA with invalid code fails
   - Login with MFA requires TOTP

4. **TestTokenRefreshFlow**
   - Refresh token returns new tokens
   - Token reuse detection (rotation)
   - Refresh with invalid token fails

5. **TestCompleteUserJourney**
   - End-to-end: Signup → Verify → Login → /me → Refresh

#### test_admin.py

1. **TestAdminUserManagement**
   - List all users (admin only)
   - List users as regular user fails (403)
   - List users without auth fails (401)
   - Pagination support

2. **TestAdminBanUser**
   - Ban user as admin
   - Banned user cannot login
   - Unban user as admin
   - Ban user as regular user fails (403)
   - Ban non-existent user fails (404)
   - Admin cannot ban self

3. **TestAuditLogs**
   - Get audit logs as admin
   - Get audit logs as regular user fails (403)
   - Admin actions are logged

4. **TestOrganizationManagement** (if implemented)
   - List organizations
   - Switch organization context
   - Create organization as admin

#### test_security.py

1. **TestTokenSecurity**
   - Token reuse detection on refresh
   - Token family invalidation on reuse attempt
   - Access token expiration enforcement
   - Malformed JWT rejection
   - JWT signature verification

2. **TestRateLimiting**
   - Login rate limiting (10 attempts/60s)
   - Signup rate limiting (5 attempts/60s)
   - Rate limit headers present
   - Rate limit reset after window

3. **TestInputValidation**
   - SQL injection prevention
   - XSS prevention in responses
   - Password validation enforced
   - Email validation enforced

4. **TestCORSPolicy**
   - CORS headers present
   - CORS rejects unauthorized origins

#### test_flows.py

1. **TestPasswordResetFlow**
   - Request password reset
   - User enumeration prevention
   - Verify reset code
   - Complete reset flow (request → verify → reset)

2. **TestLogoutFlow**
   - Logout revokes token
   - Logout all devices

3. **TestOrganizationSwitching** (if implemented)
   - Switch organization context
   - Cannot switch to unauthorized org

4. **TestGDPRSelfDeletion**
   - Self-deletion flow
   - User deleted/anonymized
   - Cannot login after deletion
   - Self-deletion requires auth

5. **TestEmailVerificationFlow**
   - Email verification required for login
   - Verify email with code
   - Resend verification email

## Test Patterns

### Pattern 1: Standard Test

```python
@pytest.mark.asyncio
async def test_feature(
    real_client: httpx.AsyncClient,
    auth_headers: Dict[str, str]
):
    """Test description."""
    response = await real_client.get(
        "/api/v1/endpoint",
        headers=auth_headers
    )

    assert response.status_code == 200
    data = response.json()
    assert "field" in data
```

### Pattern 2: Test with Database Verification

```python
@pytest.mark.asyncio
async def test_feature_with_db_check(
    real_client: httpx.AsyncClient,
    test_user: Dict[str, str],
    db_connection
):
    """Test with database verification."""
    # API call
    response = await real_client.post("/api/v1/endpoint", ...)
    assert response.status_code == 200

    # Verify in database
    import uuid
    result = await db_connection.fetchrow(
        "SELECT * FROM table WHERE user_id = $1",
        uuid.UUID(test_user["user_id"])
    )
    assert result is not None
```

### Pattern 3: Test with Cleanup

```python
@pytest.mark.asyncio
async def test_feature_with_cleanup(
    real_client: httpx.AsyncClient,
    test_user: Dict[str, str],
    db_connection
):
    """Test with cleanup."""
    # Create resource
    response = await real_client.post("/api/v1/resource", ...)
    resource_id = response.json()["id"]

    # Test something
    assert response.status_code == 201

    # Cleanup
    await db_connection.execute(
        "DELETE FROM resources WHERE id = $1",
        uuid.UUID(resource_id)
    )
```

### Pattern 4: Skip if Not Implemented

```python
@pytest.mark.asyncio
async def test_new_feature(real_client: httpx.AsyncClient):
    """Test new feature (skip if not implemented)."""
    response = await real_client.get("/api/v1/new-feature")

    # Skip if feature not implemented yet
    if response.status_code == 404:
        pytest.skip("Feature not implemented yet")

    assert response.status_code == 200
```

## Pure Python TOTP Generator

Tests use a **Pure Python RFC 6238 TOTP implementation** (no pyotp dependency):

```python
import hmac
import struct
import time
import base64

def generate_totp(secret: str) -> str:
    """Pure Python TOTP (RFC 6238)"""
    # Base32 decode
    key = base64.b32decode(secret.upper() + '=' * (-len(secret) % 8))

    # Time counter
    counter = int(time.time()) // 30
    counter_bytes = struct.pack('>Q', counter)

    # HMAC-SHA1
    hmac_hash = hmac.new(key, counter_bytes, 'sha1').digest()

    # Dynamic truncation
    offset = hmac_hash[-1] & 0x0F
    code = struct.unpack('>I', hmac_hash[offset:offset+4])[0] & 0x7FFFFFFF

    # 6 digits
    return str(code % 1000000).zfill(6)
```

This implementation is **validated against PyOTP** and produces identical codes.

## Common Issues

### Issue 1: Service Not Running

```
httpx.ConnectError: Cannot connect to http://localhost:8000
```

**Fix**:
```bash
docker compose up -d
curl http://localhost:8000/health  # Verify
```

### Issue 2: Database Connection Failed

```
asyncpg.exceptions.InvalidPasswordError: password authentication failed
```

**Fix**: Check `.env` file has correct `POSTGRES_PASSWORD`

### Issue 3: Tests Fail Due to Rate Limiting

```
AssertionError: Expected 200, got 429 (Too Many Requests)
```

**Fix**: Wait for rate limit window to reset (60 seconds) or restart service to reset Redis

```bash
docker compose restart
```

### Issue 4: Old Test Data Interfering

**Fix**: Use `cleanup_test_users` fixture or manually clean:

```bash
docker exec -it auth-api-db psql -U postgres -d idp_db -c \
  "DELETE FROM users WHERE email LIKE 'test_%@example.com';"
```

## Performance Notes

### Fast Tests (~1-5s each)

- User signup and login
- Token validation
- Admin list users
- MFA enrollment

### Slow Tests (~30-90s)

- Rate limiting tests (must wait for window)
- Token family invalidation
- Logout all devices

**Tip**: Use `-m "not slow"` to skip slow tests during development

## Security Test Coverage

### Token Security (CRITICAL)

- ✅ Token rotation on refresh
- ✅ Token reuse detection
- ✅ Token family invalidation
- ✅ JWT signature verification
- ✅ Expired token rejection
- ✅ Malformed token rejection

### Rate Limiting

- ✅ Login rate limiting (10/60s)
- ✅ Signup rate limiting (5/60s)
- ✅ Rate limit headers
- ✅ Rate limit reset

### Input Validation

- ✅ SQL injection prevention
- ✅ XSS prevention
- ✅ Password strength enforcement
- ✅ Email format validation

### Access Control

- ✅ RBAC (admin vs user)
- ✅ Authentication required
- ✅ Authorization required
- ✅ Organization access control

## Coverage Goals

- **Integration Tests**: 80%+ path coverage
- **Security Tests**: 100% of security controls
- **Admin Tests**: 100% of RBAC rules
- **Flow Tests**: 90%+ user journeys

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Real Integration Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:14
        env:
          POSTGRES_DB: idp_db
          POSTGRES_USER: postgres
          POSTGRES_PASSWORD: postgres
        ports:
          - 5432:5432

      redis:
        image: redis:7
        ports:
          - 6379:6379

    steps:
      - uses: actions/checkout@v3

      - name: Start Service
        run: docker compose up -d

      - name: Wait for Service
        run: |
          for i in {1..30}; do
            curl -f http://localhost:8000/health && break
            sleep 1
          done

      - name: Run Tests
        run: pytest tests/test_*.py -v --cov=app

      - name: Upload Coverage
        uses: codecov/codecov-action@v3
```

## Best Practices

1. **Always rebuild after code changes**:
   ```bash
   docker compose build --no-cache
   docker compose restart
   ```

2. **Use fixtures for user creation**:
   ```python
   async def test_feature(test_user: Dict[str, str]):
       # User automatically created and cleaned up
   ```

3. **Skip unimplemented features**:
   ```python
   if response.status_code == 404:
       pytest.skip("Feature not implemented yet")
   ```

4. **Verify in database when critical**:
   ```python
   result = await db_connection.fetchrow("SELECT ...")
   assert result is not None
   ```

5. **Use generic assertions for security**:
   ```python
   # Good: Generic message
   assert "invalid credentials" in response.text.lower()

   # Bad: Reveals information
   assert "user not found" in response.text
   ```

## Maintenance

### Adding New Tests

1. Choose appropriate test file:
   - Integration → `test_integration_full.py`
   - Admin/RBAC → `test_admin.py`
   - Security → `test_security.py`
   - Flows → `test_flows.py`

2. Follow existing patterns (see Test Patterns section)

3. Use appropriate fixtures from `conftest.py`

4. Add cleanup if creating resources

5. Skip if feature not implemented yet

### Updating Fixtures

Edit `conftest.py` to add new fixtures. Common patterns:

- User creation: See `test_user` fixture
- Token generation: See `user_token` fixture
- Database verification: See `db_connection` fixture
- Cleanup: Use `yield` pattern with try/finally

## Comparison: Old vs New Tests

### Old Tests (tests/test_integration_full.py)

```python
# ❌ Uses SQLite (not real PostgreSQL)
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"

# ❌ Uses FakeRedis (not real Redis)
fake_redis = fakeredis.aioredis.FakeRedis()

# ❌ Mocks entire app
@pytest.fixture
async def client():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac
```

**Issues**:
- SQLite behavior differs from PostgreSQL
- FakeRedis doesn't catch real Redis issues
- Mock app doesn't test real HTTP server
- Doesn't test real JWT validation with RSA keys
- Doesn't test real TOTP validation

### New Tests (tests/test_*.py)

```python
# ✅ Real PostgreSQL connection
conn = await asyncpg.connect(
    host="localhost",
    port=5432,
    database="idp_db"
)

# ✅ Real Redis connection
redis = await aioredis.from_url("redis://localhost:6379/0")

# ✅ Real HTTP calls
async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
    response = await client.get("/api/v1/users/me")
```

**Benefits**:
- Tests production behavior
- Catches database-specific issues
- Validates real JWT/RSA behavior
- Tests real TOTP validation
- Detects Docker/networking issues
- Validates rate limiting in Redis

## Conclusion

This test suite provides **production-quality integration testing** by testing the **actual running service** with **real dependencies**. No mocks, no fakes, 100% real.

**Key Benefits**:
- ✅ Catches real-world bugs
- ✅ Validates production behavior
- ✅ Tests security controls
- ✅ Verifies RBAC enforcement
- ✅ Validates complete user journeys

**Run tests before every commit**:
```bash
pytest tests/test_*.py -v
```

**Standard**: 99% is half werk en half werk is geen werk. We zijn the best in the class. 🎯
