from fastapi import APIRouter

router = APIRouter()


@router.get("/logs")
async def get_audit_logs():
    return {"status": "not implemented"}


@router.get("/stats")
async def get_audit_stats():
    return {"status": "not implemented"}