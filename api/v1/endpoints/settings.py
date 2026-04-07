from fastapi import APIRouter

router = APIRouter()


@router.get("/thresholds")
async def get_thresholds():
    return {"status": "not implemented"}


@router.put("/thresholds")
async def update_thresholds():
    return {"status": "not implemented"}


@router.get("/layers")
async def get_layers():
    return {"status": "not implemented"}


@router.put("/layers")
async def update_layers():
    return {"status": "not implemented"}