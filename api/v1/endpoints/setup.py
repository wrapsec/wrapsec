# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.dependencies.db import get_db
from cache.redis_client import get_redis
from db.repositories.tenant import TenantRepository
from db.repositories.user import UserRepository
from services.auth.password import hash_password, normalize_email, validate_password_strength

logger = logging.getLogger("wrapsec.setup")

router = APIRouter()

# Once initialized this key is set permanently — no expiry needed.
# It is an immutable fact: a system that has users never becomes uninitialized.
_CACHE_KEY = "setup:initialized"


async def _mark_initialized() -> None:
    """Write the initialized flag to Redis. Best-effort — never raises."""
    try:
        await get_redis().set(_CACHE_KEY, "1")
    except Exception as e:
        logger.warning("setup cache write failed: %s", e)


class SetupRequest(BaseModel):
    email:    EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def strong_password(cls, v: str) -> str:
        try:
            validate_password_strength(v)
        except ValueError as e:
            raise ValueError(str(e))
        return v


class SetupStatusResponse(BaseModel):
    initialized: bool


@router.get("/status", response_model=SetupStatusResponse, include_in_schema=False)
async def setup_status(db: AsyncSession = Depends(get_db)):
    """
    Returns whether the system has been initialized (first admin user exists).
    Redis-cached after first initialization — zero DB load on subsequent calls.
    Public endpoint — used by the dashboard to decide whether to show /setup.
    """
    # Fast path — Redis cache hit means already initialized, skip DB entirely
    try:
        cached = await get_redis().get(_CACHE_KEY)
        if cached:
            return SetupStatusResponse(initialized=True)
    except Exception as e:
        logger.warning("setup cache read failed: %s — falling back to DB", e)

    # Cache miss — check DB
    tenant = await TenantRepository(db).get_default()
    if not tenant:
        return SetupStatusResponse(initialized=False)

    count = await UserRepository(db).count_by_tenant(tenant.id)
    initialized = count > 0

    # Warm the cache so future calls skip the DB
    if initialized:
        await _mark_initialized()

    return SetupStatusResponse(initialized=initialized)


@router.post("", status_code=201, include_in_schema=False)
async def complete_setup(body: SetupRequest, db: AsyncSession = Depends(get_db)):
    """
    Creates the first admin user. Only succeeds when no users exist.
    Returns 404 once initialized — indistinguishable from a missing route.
    Public endpoint — accessible without any API key or JWT.
    """
    tenant = await TenantRepository(db).get_default()

    # Return 404 for all failure cases — never reveal system state to unauthenticated callers
    if not tenant:
        raise HTTPException(status_code=404)

    user_repo = UserRepository(db)
    if await user_repo.count_by_tenant(tenant.id) > 0:
        raise HTTPException(status_code=404)

    email = normalize_email(str(body.email))

    await user_repo.create({
        "tenant_id":             tenant.id,
        "dept_id":               None,
        "email":                 email,
        "password_hash":         hash_password(body.password),
        "role":                  "ADMIN",
        "force_password_change": False,
    })
    await db.commit()

    # Cache immediately — all future status checks are Redis-only
    await _mark_initialized()

    logger.info("setup first_admin_created email=%s", email)
    return {"message": "Setup complete. You can now sign in."}
