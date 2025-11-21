#!/usr/bin/env python3
"""
Create Admin Test User Script
Creates a verified admin user with organization for testing purposes.
"""
import sys
import os
import uuid
from datetime import datetime, timezone

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
import asyncpg
from argon2 import PasswordHasher
from argon2.profiles import RFC_9106_LOW_MEMORY


async def create_admin_user():
    """Create admin user with organization."""

    # Database connection
    DATABASE_URL = os.getenv(
        "DATABASE_URL",
        "postgresql://user:password@localhost:5433/idp_db"
    )

    print("🔗 Connecting to database...")
    conn = await asyncpg.connect(DATABASE_URL)

    try:
        # Admin user details
        admin_email = "admin@example.com"
        admin_password = "Admin123!"
        org_name = "Admin Organization"
        org_slug = "admin-org"

        # Check if admin already exists
        existing_user = await conn.fetchrow(
            "SELECT id, email FROM users WHERE email = $1",
            admin_email
        )

        if existing_user:
            print(f"⚠️  Admin user already exists: {existing_user['email']}")
            print(f"   User ID: {existing_user['id']}")
            return

        # Hash password with Argon2id
        print("🔐 Hashing password with Argon2id...")
        ph = PasswordHasher.from_parameters(RFC_9106_LOW_MEMORY)
        password_hash = ph.hash(admin_password)

        # Generate UUIDs
        user_id = uuid.uuid4()
        org_id = uuid.uuid4()
        member_id = uuid.uuid4()
        now = datetime.now(timezone.utc)

        # Begin transaction
        async with conn.transaction():
            # Create user
            print(f"👤 Creating admin user: {admin_email}")
            await conn.execute(
                """
                INSERT INTO users (id, email, password_hash, is_verified, mfa_enabled, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                """,
                user_id, admin_email, password_hash, True, False, now, now
            )

            # Create organization
            print(f"🏢 Creating organization: {org_name}")
            await conn.execute(
                """
                INSERT INTO organizations (id, name, slug, created_at)
                VALUES ($1, $2, $3, $4)
                """,
                org_id, org_name, org_slug, now
            )

            # Create organization membership with admin roles
            print(f"🔑 Adding admin roles: ['admin', 'owner']")
            await conn.execute(
                """
                INSERT INTO organization_members (id, user_id, org_id, roles, created_at)
                VALUES ($1, $2, $3, $4, $5)
                """,
                member_id, user_id, org_id, ["admin", "owner"], now
            )

        print("\n✅ Admin user created successfully!")
        print(f"\n📋 Admin User Details:")
        print(f"   Email: {admin_email}")
        print(f"   Password: {admin_password}")
        print(f"   User ID: {user_id}")
        print(f"   Organization: {org_name}")
        print(f"   Org ID: {org_id}")
        print(f"   Roles: ['admin', 'owner']")
        print(f"   Verified: Yes")
        print(f"   MFA Enabled: No")

    except Exception as e:
        print(f"❌ Error creating admin user: {e}")
        raise
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(create_admin_user())
