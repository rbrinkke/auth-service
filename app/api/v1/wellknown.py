from fastapi import APIRouter
from app.core.security import public_key_to_jwk

router = APIRouter()

@router.get("/jwks.json")
async def jwks():
    return public_key_to_jwk()
