from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
from sqlalchemy.ext.asyncio import AsyncSession
from api.v1.dependencies.db import get_db
from db.repositories.settings import SettingsRepository
from config.settings import get_settings
from errors.exceptions import ValidationError

router    = APIRouter()
settings  = get_settings()

THRESHOLD_KEY = "policy_thresholds"
LAYERS_KEY    = "detection_layers"

DEFAULT_THRESHOLDS = {
    "block_threshold":    settings.block_threshold,
    "sanitize_threshold": settings.sanitize_threshold,
}

DEFAULT_LAYERS = {
    "rule_enabled": True,
    "ml_enabled":   True,
    "llm_enabled":  True,
}


class ThresholdsUpdateSchema(BaseModel):
    block_threshold:    float | None = None
    sanitize_threshold: float | None = None

    @model_validator(mode="after")
    def validate_thresholds(self) -> "ThresholdsUpdateSchema":
        block    = self.block_threshold    or settings.block_threshold
        sanitize = self.sanitize_threshold or settings.sanitize_threshold
        if block <= sanitize:
            raise ValidationError(
                f"block_threshold ({block}) must be greater "
                f"than sanitize_threshold ({sanitize})"
            )
        return self


class LayersUpdateSchema(BaseModel):
    rule_enabled: bool | None = None
    ml_enabled:   bool | None = None
    llm_enabled:  bool | None = None


@router.get("/thresholds")
async def get_thresholds(db: AsyncSession = Depends(get_db)):
    repo   = SettingsRepository(db)
    stored = await repo.get(THRESHOLD_KEY)
    return JSONResponse(content=stored or DEFAULT_THRESHOLDS)


@router.put("/thresholds")
async def update_thresholds(
    body: ThresholdsUpdateSchema,
    db:   AsyncSession = Depends(get_db),
):
    repo    = SettingsRepository(db)
    current = await repo.get(THRESHOLD_KEY) or DEFAULT_THRESHOLDS.copy()

    if body.block_threshold is not None:
        current["block_threshold"] = body.block_threshold
    if body.sanitize_threshold is not None:
        current["sanitize_threshold"] = body.sanitize_threshold

    await repo.set(THRESHOLD_KEY, current)

    return JSONResponse(content={
        **current,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })


@router.get("/layers")
async def get_layers(db: AsyncSession = Depends(get_db)):
    repo   = SettingsRepository(db)
    stored = await repo.get(LAYERS_KEY)
    return JSONResponse(content=stored or DEFAULT_LAYERS)


@router.put("/layers")
async def update_layers(
    body: LayersUpdateSchema,
    db:   AsyncSession = Depends(get_db),
):
    repo    = SettingsRepository(db)
    current = await repo.get(LAYERS_KEY) or DEFAULT_LAYERS.copy()

    if body.rule_enabled is not None:
        current["rule_enabled"] = body.rule_enabled
    if body.ml_enabled is not None:
        current["ml_enabled"] = body.ml_enabled
    if body.llm_enabled is not None:
        current["llm_enabled"] = body.llm_enabled

    await repo.set(LAYERS_KEY, current)

    return JSONResponse(content={
        **current,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })