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
        block    = self.block_threshold    if self.block_threshold    is not None else settings.block_threshold
        sanitize = self.sanitize_threshold if self.sanitize_threshold is not None else settings.sanitize_threshold

        if block <= 0.0:
            raise ValueError("block_threshold must be greater than 0")
        if sanitize < 0.0:
            raise ValueError("sanitize_threshold must be 0 or greater")
        if block <= sanitize:
            raise ValueError(
                f"block_threshold ({block}) must be greater "
                f"than sanitize_threshold ({sanitize})"
            )
        if block > 1.0:
            raise ValueError("block_threshold cannot exceed 1.0")
        if sanitize >= 1.0:
            raise ValueError("sanitize_threshold must be less than 1.0")

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

LLM_KEY = "llm_settings"

DEFAULT_LLM = {
    "provider":    settings.llm_provider,
    "model":       settings.llm_model,
    "base_url":    settings.llm_base_url,
    "timeout":     settings.llm_timeout,
    "llm_trigger": settings.llm_trigger_threshold,
}


class LLMSettingsSchema(BaseModel):
    provider:    str   | None = None
    model:       str   | None = None
    base_url:    str   | None = None
    timeout:     int   | None = None
    llm_trigger: float | None = None

    @model_validator(mode="after")
    def validate_llm(self) -> "LLMSettingsSchema":
        if self.provider and self.provider not in ("ollama", "openai", "groq"):
            raise ValueError("provider must be ollama, openai, or groq")
        if self.timeout is not None and self.timeout < 5:
            raise ValueError("timeout must be at least 5 seconds")
        if self.timeout is not None and self.timeout > 120:
            raise ValueError("timeout cannot exceed 120 seconds")
        if self.llm_trigger is not None:
            if self.llm_trigger < 0.0 or self.llm_trigger > 1.0:
                raise ValueError("llm_trigger must be between 0.0 and 1.0")
        return self


@router.get("/llm")
async def get_llm_settings(db: AsyncSession = Depends(get_db)):
    repo   = SettingsRepository(db)
    stored = await repo.get(LLM_KEY)
    return JSONResponse(content=stored or DEFAULT_LLM)


@router.put("/llm")
async def update_llm_settings(
    body: LLMSettingsSchema,
    db:   AsyncSession = Depends(get_db),
):
    repo    = SettingsRepository(db)
    current = await repo.get(LLM_KEY) or DEFAULT_LLM.copy()

    if body.provider    is not None: current["provider"]    = body.provider
    if body.model       is not None: current["model"]       = body.model
    if body.base_url    is not None: current["base_url"]    = body.base_url
    if body.timeout     is not None: current["timeout"]     = body.timeout
    if body.llm_trigger is not None: current["llm_trigger"] = body.llm_trigger

    await repo.set(LLM_KEY, current)

    return JSONResponse(content={
        **current,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })

RETENTION_KEY = "audit_retention"


class RetentionSettingsSchema(BaseModel):
    retention_days: int

    @model_validator(mode="after")
    def validate_retention(self) -> "RetentionSettingsSchema":
        if self.retention_days < 7:
            raise ValueError("retention_days must be at least 7")
        if self.retention_days > 3650:
            raise ValueError("retention_days cannot exceed 3650 (10 years)")
        return self


@router.get("/retention")
async def get_retention_settings(db: AsyncSession = Depends(get_db)):
    repo    = SettingsRepository(db)
    stored  = await repo.get(RETENTION_KEY)
    days    = stored.get("retention_days", settings.audit_retention_days) if stored else settings.audit_retention_days
    return JSONResponse(content={
        "retention_days": days,
        "source":         "database" if stored else "environment",
    })


@router.put("/retention")
async def update_retention_settings(
    body: RetentionSettingsSchema,
    db:   AsyncSession = Depends(get_db),
):
    repo = SettingsRepository(db)
    await repo.set(RETENTION_KEY, {"retention_days": body.retention_days})
    return JSONResponse(content={
        "retention_days": body.retention_days,
        "updated_at":     datetime.now(timezone.utc).isoformat(),
    })