from fastapi import APIRouter
from app.core.security import public_key_to_jwk

router = APIRouter()

@router.get("/jwks.json")
async def jwks():
    """
    Serve the Public Key in JWK Set format.
    Used by other microservices to verify JWT signatures.
    """
    return public_key_to_jwk()
