# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.dependencies.db import get_db
from cache.redis_client import get_redis
from db.repositories.tenant import TenantRepository
from db.repositories.user import UserRepository
from services.auth.password import (
    hash_password,
    normalize_email,
    validate_password_strength,
)

logger = logging.getLogger("wrapsec.setup")

router = APIRouter()

# Once initialized this key is set permanently - no expiry needed.
# It is an immutable fact: a system that has users never becomes uninitialized.
_CACHE_KEY = "setup:initialized"


async def _mark_initialized() -> None:
    """Write the initialized flag to Redis. Best-effort - never raises."""
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
            raise ValueError(str(e)) from None
        return v


class SetupStatusResponse(BaseModel):
    initialized: bool


@router.get("/status", response_model=SetupStatusResponse, include_in_schema=False)
async def setup_status(db: AsyncSession = Depends(get_db)):
    """
    Returns whether the system has been initialized (first admin user exists).
    Redis-cached after first initialization - zero DB load on subsequent calls.
    Public endpoint - used by the dashboard to decide whether to show /setup.
    """
    # Fast path - Redis cache hit means already initialized, skip DB entirely
    try:
        cached = await asyncio.wait_for(get_redis().get(_CACHE_KEY), timeout=2.0)
        if cached:
            return SetupStatusResponse(initialized=True)
    except asyncio.TimeoutError:
        logger.warning("setup cache read timed out - falling back to DB")
    except Exception as e:
        logger.warning("setup cache read failed: %s - falling back to DB", e)

    # Cache miss - check DB
    try:
        tenant = await asyncio.wait_for(TenantRepository(db).get_bootstrap_default(), timeout=5.0)
    except asyncio.TimeoutError:
        logger.warning("setup DB status check timed out - returning not initialized")
        return SetupStatusResponse(initialized=False)

    if not tenant:
        return SetupStatusResponse(initialized=False)

    try:
        # The same predicate the create route gates on. If the two disagreed,
        # this would report a setup page the create route refuses to serve, or
        # hide one it would still serve.
        from db.repositories.user import UserRepository as _UserRepository
        initialized = await asyncio.wait_for(
            _UserRepository(db).any_user_exists(), timeout=5.0,
        )
    except asyncio.TimeoutError:
        logger.warning("setup DB user count timed out - returning not initialized")
        return SetupStatusResponse(initialized=False)

    # Warm the cache so future calls skip the DB
    if initialized:
        await _mark_initialized()

    return SetupStatusResponse(initialized=initialized)


@router.post("", status_code=201, include_in_schema=False)
async def complete_setup(body: SetupRequest, db: AsyncSession = Depends(get_db)):
    """
    Creates the first admin user. Refused once any user exists in any tenant;
    the gate below records why that is the predicate.
    Returns 404 once initialized - indistinguishable from a missing route.
    Public endpoint - accessible without any API key or JWT.
    """
    tenant = await TenantRepository(db).get_bootstrap_default()

    # Return 404 for all failure cases - never reveal system state to unauthenticated callers
    if not tenant:
        raise HTTPException(status_code=404)

    # Serialize concurrent first-run attempts. Without this, two unauthenticated
    # requests in the first-boot window could both pass the "no users yet" check
    # and each create an ADMIN. The transaction-scoped advisory lock releases on
    # the commit/rollback below (PostgreSQL only; the check-and-create still runs
    # on other backends, just without the extra guard).
    bind = db.bind
    if bind is not None and bind.dialect.name == "postgresql":
        await db.execute(text("SELECT pg_advisory_xact_lock(hashtext('wrapsec:setup:first_admin'))"))

    user_repo = UserRepository(db)
    # Gate on whether this deployment has ANY user, not on the membership count
    # of one tenant. Three code paths make the narrower check insufficient:
    #
    #   * `seed_default_tenant` (api/main.py) creates the "default" tenant at
    #     startup, so it exists with zero memberships from first boot;
    #   * `POST /v1/admin/tenants/{tenant_id}/bootstrap-admin` attaches an admin
    #     to an ARBITRARY tenant, so a deployment run entirely through
    #     platform-operator tenants accumulates users while "default" stays
    #     empty -- permanently, not transiently;
    #   * this route is unauthenticated and grants ADMIN of "default".
    #
    # Together those leave an unauthenticated caller able to mint an admin of
    # the default tenant at any point in that deployment's life. Gating on the
    # existence of any user closes it, and strands nobody: `bootstrap-admin`
    # takes an arbitrary tenant_id, so the default tenant's first admin can
    # still be created through an authenticated path.
    if await user_repo.any_user_exists():
        raise HTTPException(status_code=404)

    email = normalize_email(str(body.email))

    user = await user_repo.create({
        "email":                 email,
        "password_hash":         hash_password(body.password),
        "force_password_change": False,
    })
    await user_repo.flush()  # assign user.id before the membership FK references it
    # The first admin's authz is its ADMIN membership in this tenant.
    from db.repositories.membership import MembershipRepository
    await MembershipRepository(db).upsert_for_user(
        user_id=user.id, tenant_id=tenant.id, role="ADMIN", dept_id=None,
    )
    await db.commit()

    # Cache immediately - all future status checks are Redis-only
    await _mark_initialized()

    logger.info("setup first_admin_created email=%s", email)
    return {"message": "Setup complete. You can now sign in."}
