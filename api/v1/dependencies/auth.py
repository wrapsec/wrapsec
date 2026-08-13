# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from fastapi import Request

from cache import keyspace
from domain.entities.principal import (
    ROLE_PERMISSIONS,
    Principal,
)
from domain.enums import PrincipalType
from errors.exceptions import ForbiddenError, UnauthorizedError


def _get_principal_from_state(request: Request) -> Principal:
    """
    Builds a Principal from request.state populated by AuthMiddleware.
    Accepts both API key and JWT auth paths - all state fields are identical.

    Raises UnauthorizedError if request.state is not populated
    (should never happen in practice - middleware runs first).
    """
    principal_type = getattr(request.state, "principal_type", None)
    tenant_id      = getattr(request.state, "tenant_id", None)

    if not principal_type:
        raise UnauthorizedError()

    if principal_type == "user":
        # JWT path - build from state fields directly
        # (UserModel not available here - middleware already validated everything)
        return Principal(
            id          = getattr(request.state, "key_id", ""),       # "user:{uuid}"
            type        = PrincipalType.USER,
            tenant_id   = tenant_id or "",
            dept_id     = getattr(request.state, "dept_id", None),
            roles       = [request.state.user_role] if request.state.user_role else [],
            permissions = ROLE_PERMISSIONS.get(request.state.user_role or "", []),
            is_admin    = getattr(request.state, "is_admin", False),
            email       = getattr(request.state, "key_name", None),
        )
    else:
        # API key path - build from state fields directly
        return Principal(
            id          = getattr(request.state, "key_id", ""),       # "key:{key_id}"
            type        = PrincipalType.API_KEY,
            tenant_id   = tenant_id or "",
            dept_id     = getattr(request.state, "dept_id", None),
            roles       = ["ADMIN"] if getattr(request.state, "is_admin", False) else ["DEVELOPER"],
            permissions = ROLE_PERMISSIONS.get(
                "ADMIN" if getattr(request.state, "is_admin", False) else "DEVELOPER", []
            ),
            is_admin    = getattr(request.state, "is_admin", False),
        )


async def get_current_principal(request: Request) -> Principal:
    """
    FastAPI dependency - builds Principal from request.state.
    Accepts both API key and JWT auth.
    Use on endpoints that accept both (scan, audit, proxy).

    Usage:
        principal: Principal = Depends(get_current_principal)
    """
    return _get_principal_from_state(request)


async def require_jwt(request: Request) -> Principal:
    """
    FastAPI dependency - requires JWT specifically.
    Rejects API key auth with 403 FORBIDDEN.
    Use on all dashboard management endpoints.

    Usage:
        principal: Principal = Depends(require_jwt)
    """
    principal_type = getattr(request.state, "principal_type", None)
    if principal_type != "user":
        raise ForbiddenError("This endpoint requires dashboard (JWT) authentication.")
    return _get_principal_from_state(request)


def require_role(*roles: str):
    """
    FastAPI dependency factory - requires JWT + one of the given roles.
    Always implies require_jwt() - API keys get 403.

    Usage:
        Depends(require_role("ADMIN"))
        Depends(require_role("ADMIN", "DEVELOPER"))
    """
    async def _dependency(request: Request) -> Principal:
        # Must be JWT
        principal_type = getattr(request.state, "principal_type", None)
        if principal_type != "user":
            raise ForbiddenError("This endpoint requires dashboard (JWT) authentication.")

        principal = _get_principal_from_state(request)

        if not principal.has_role(*roles):
            raise ForbiddenError(
                f"Insufficient permissions. Required role: {' or '.join(roles)}."
            )
        return principal

    return _dependency


def require_admin():
    """
    Shorthand for Depends(require_role("ADMIN")).

    Usage:
        principal: Principal = Depends(require_admin())
    """
    return require_role("ADMIN")


def require_any_admin():
    """
    Require admin access from any auth type - JWT ADMIN role or admin API key.
    Use this for endpoints that must be admin-only but are also called
    programmatically via the admin API key (not the dashboard).

    Usage:
        principal: Principal = Depends(require_any_admin())
    """
    async def _dependency(request: Request) -> Principal:
        principal = _get_principal_from_state(request)
        if not principal.is_admin:
            raise ForbiddenError("Admin access required.")
        return principal
    return _dependency


def endpoint_rate_limit(limit_setting: str):
    """
    Dependency factory - per-identity sliding-window rate limit.
    Keyed by key_id (JWT user or API key) with IP fallback.
    Applies on top of the global middleware limit.

    Limit resolution order:
      1. Redis cache  (wrapsec:settings:admin_rate_limits, 60 s TTL)
      2. DB           (settings table, key = admin_rate_limits)
      3. .env default (Settings field named limit_setting)

    Fails open if Redis and DB are both unavailable.
    TESTING env var bypasses cache/DB - always uses .env default.

    Usage:
        _: None = Depends(endpoint_rate_limit("admin_write_rate_limit"))
    """
    async def _dependency(request: Request) -> None:
        import json
        import os

        from api.v1.middleware.auth import get_client_ip
        from cache.rate_limit_store import is_rate_limited
        from config.settings import get_settings
        from errors.exceptions import RateLimitError

        limit = None

        if os.getenv("TESTING") != "true":
            # 1. Redis cache
            try:
                from cache.redis_client import get_redis
                cached = await get_redis().get("wrapsec:settings:admin_rate_limits")
                if cached:
                    limit = json.loads(cached).get(limit_setting)
            except Exception:
                pass

            # 2. DB - also warms the cache on hit
            if limit is None:
                try:
                    from db.repositories.settings import SettingsRepository
                    from db.session import AsyncSessionFactory
                    async with AsyncSessionFactory() as session:
                        stored = await SettingsRepository(session).get("admin_rate_limits")
                        if stored and limit_setting in stored:
                            limit = stored[limit_setting]
                            try:
                                from cache.redis_client import get_redis
                                await get_redis().setex(
                                    "wrapsec:settings:admin_rate_limits", 60, json.dumps(stored)
                                )
                            except Exception:
                                pass
                except Exception:
                    pass

        # 3. .env fallback
        if limit is None:
            limit = getattr(get_settings(), limit_setting)

        identity  = getattr(request.state, "key_id", None) or get_client_ip(request) or "unknown"
        rl_key    = keyspace.endpoint_rate_limit(request.url.path, identity)
        is_limited, _, _ = await is_rate_limited(rl_key, limit=limit)
        if is_limited:
            raise RateLimitError()

    return _dependency
