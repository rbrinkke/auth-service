#!/bin/bash
set -e

BASE_URL="http://localhost:8000"
RANDOM_ID=$(date +%s)
EMAIL="test${RANDOM_ID}@example.com"
PASSWORD="SecurePass123!"

echo "=== Auth Flow Test ==="
echo

# 1. Signup
echo "1. Testing signup..."
SIGNUP_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/signup" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$EMAIL\", \"password\": \"$PASSWORD\"}")
echo "Signup response: $SIGNUP_RESPONSE"
echo

# Check if signup was successful
SUCCESS=$(echo $SIGNUP_RESPONSE | jq -r '.success')
if [ "$SUCCESS" != "true" ]; then
  echo "❌ Signup failed!"
  exit 1
fi
echo "✅ Signup successful!"
echo

# 2. Manually verify user (since we don't have email service)
echo "2. Manually verifying user in database..."
docker exec auth-service-db-1 psql -U user -d idp_db -c "UPDATE users SET is_verified = true WHERE email = '$EMAIL';"
echo "✅ User verified"
echo

# 3. Login
echo "3. Testing login..."
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$EMAIL\", \"password\": \"$PASSWORD\"}")
echo "Login response: $LOGIN_RESPONSE"
echo

# Extract tokens
ACCESS_TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.data.access_token')
REFRESH_TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.data.refresh_token')

if [ "$ACCESS_TOKEN" = "null" ]; then
  echo "❌ Login failed!"
  exit 1
fi
echo "✅ Login successful!"
echo "Access token (first 50 chars): ${ACCESS_TOKEN:0:50}..."
echo "Refresh token (first 50 chars): ${REFRESH_TOKEN:0:50}..."
echo

# 4. Token refresh
echo "4. Testing token refresh..."
REFRESH_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}")
echo "Refresh response: $REFRESH_RESPONSE"
echo

NEW_ACCESS_TOKEN=$(echo $REFRESH_RESPONSE | jq -r '.data.access_token')
if [ "$NEW_ACCESS_TOKEN" = "null" ]; then
  echo "❌ Token refresh failed!"
  exit 1
fi
echo "✅ Token refresh successful!"
echo "New access token (first 50 chars): ${NEW_ACCESS_TOKEN:0:50}..."
echo

# 5. Logout
echo "5. Testing logout..."
NEW_REFRESH_TOKEN=$(echo $REFRESH_RESPONSE | jq -r '.data.refresh_token')
LOGOUT_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/logout" \
  -H "Authorization: Bearer $NEW_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\": \"$NEW_REFRESH_TOKEN\"}")
echo "Logout response: $LOGOUT_RESPONSE"
echo

if echo $LOGOUT_RESPONSE | jq -e '.data.message' > /dev/null; then
  echo "✅ Logout successful!"
else
  echo "❌ Logout failed!"
  exit 1
fi
echo

echo "========================================="
echo "✅ ALL AUTH FLOW TESTS PASSED!"
echo "========================================="
