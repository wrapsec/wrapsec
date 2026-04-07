from datetime import datetime, timezone
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
from config.settings import get_settings
from errors.exceptions import ValidationError

router   = APIRouter()
settings = get_settings()

# In-memory settings store — will be replaced by DB in next step
_thresholds = {
    "block_threshold":    settings.block_threshold,
    "sanitize_threshold": settings.sanitize_threshold,
}

_layers = {
    "rule_enabled": True,
    "ml_enabled":   True,
    "llm_enabled":  True,
}


class ThresholdsUpdateSchema(BaseModel):
    block_threshold:    float | None = None
    sanitize_threshold: float | None = None

    @model_validator(mode="after")
    def validate_thresholds(self) -> "ThresholdsUpdateSchema":
        block    = self.block_threshold    or _thresholds["block_threshold"]
        sanitize = self.sanitize_threshold or _thresholds["sanitize_threshold"]
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
async def get_thresholds():
    return JSONResponse(content=_thresholds)


@router.put("/thresholds")
async def update_thresholds(body: ThresholdsUpdateSchema):
    if body.block_threshold is not None:
        _thresholds["block_threshold"] = body.block_threshold
    if body.sanitize_threshold is not None:
        _thresholds["sanitize_threshold"] = body.sanitize_threshold

    return JSONResponse(content={
        **_thresholds,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })


@router.get("/layers")
async def get_layers():
    return JSONResponse(content=_layers)


@router.put("/layers")
async def update_layers(body: LayersUpdateSchema):
    if body.rule_enabled is not None:
        _layers["rule_enabled"] = body.rule_enabled
    if body.ml_enabled is not None:
        _layers["ml_enabled"] = body.ml_enabled
    if body.llm_enabled is not None:
        _layers["llm_enabled"] = body.llm_enabled

    return JSONResponse(content={
        **_layers,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })