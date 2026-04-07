from fastapi import APIRouter

router = APIRouter()


@router.post("")
async def create_key():
    return {"status": "not implemented"}


@router.get("")
async def list_keys():
    return {"status": "not implemented"}


@router.delete("/{key_id}")
async def delete_key(key_id: str):
    return {"status": "not implemented"}