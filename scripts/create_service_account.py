import asyncio
import secrets
import argparse
import sys
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

# Adjust path to include app
sys.path.append(".")

from app.models import ServiceAccount
from app.core.security import hash_password
from app.core.config import settings

async def create_service_account(name: str, scopes: list[str]):
    # DB Connection
    engine = create_async_engine(settings.DATABASE_URL)
    AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with AsyncSessionLocal() as session:
        try:
            # Generate credentials
            client_id = f"service_{secrets.token_hex(8)}"
            client_secret = secrets.token_urlsafe(32)

            # Hash secret
            secret_hash = hash_password(client_secret)

            # Create record
            service_account = ServiceAccount(
                client_id=client_id,
                client_secret_hash=secret_hash,
                name=name,
                scopes=scopes,
                is_active=True
            )
            session.add(service_account)
            await session.commit()

            print("Service Account Created Successfully")
            print("-----------------------------------")
            print(f"Name:          {name}")
            print(f"Client ID:     {client_id}")
            print(f"Client Secret: {client_secret}")
            print(f"Scopes:        {', '.join(scopes)}")
            print("-----------------------------------")
            print("WARNING: Store the Client Secret safely. It will not be shown again.")

        except Exception as e:
            print(f"Error creating service account: {e}")
        finally:
            await engine.dispose()

def main():
    parser = argparse.ArgumentParser(description="Create a new Service Account")
    parser.add_argument("name", help="Name of the service (e.g., 'Billing Service')")
    parser.add_argument("scopes", nargs="+", help="List of allowed scopes (e.g., billing:read billing:write)")

    args = parser.parse_args()

    asyncio.run(create_service_account(args.name, args.scopes))

if __name__ == "__main__":
    main()
