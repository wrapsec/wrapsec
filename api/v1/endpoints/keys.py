import secrets
import hashlib
from datetime import datetime, timezone
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from errors.exceptions import NotFoundError, UnauthorizedError

router = APIRouter()

# In-memory key store — will be replaced by DB
_key_store: dict[str, dict] = {}


def _hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


def generate_api_key() -> str:
    return "wsk_live_" + secrets.token_urlsafe(32)


class CreateKeySchema(BaseModel):
    name:       str
    expires_at: str | None = None


@router.post("")
async def create_key(body: CreateKeySchema, request: Request):
    api_key = generate_api_key()
    key_id  = "key_" + secrets.token_hex(6)

    record = {
        "key_id":       key_id,
        "name":         body.name,
        "key_hash":     _hash_key(api_key),
        "created_at":   datetime.now(timezone.utc).isoformat(),
        "expires_at":   body.expires_at,
        "last_used_at": None,
        "revoked":      False,
    }

    _key_store[key_id] = record

    # Return api_key only once — never again
    return JSONResponse(content={
        "key_id":     key_id,
        "name":       body.name,
        "api_key":    api_key,
        "created_at": record["created_at"],
        "expires_at": record["expires_at"],
    }, status_code=201)


@router.get("")
async def list_keys():
    keys = [
        {
            "key_id":       v["key_id"],
            "name":         v["name"],
            "created_at":   v["created_at"],
            "expires_at":   v["expires_at"],
            "last_used_at": v["last_used_at"],
        }
        for v in _key_store.values()
        if not v["revoked"]
    ]
    return JSONResponse(content={"keys": keys})


@router.delete("/{key_id}")
async def delete_key(key_id: str):
    record = _key_store.get(key_id)
    if not record:
        raise NotFoundError("key", key_id)

    record["revoked"]    = True
    record["revoked_at"] = datetime.now(timezone.utc).isoformat()

    return JSONResponse(content={
        "key_id":     key_id,
        "revoked":    True,
        "revoked_at": record["revoked_at"],
    })