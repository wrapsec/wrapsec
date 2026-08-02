# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import hashlib
from services.time import utc_now
import hmac
import ipaddress
import logging
import os
from datetime import datetime
from uuid import UUID

from fastapi import Request
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import NullPool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from config.settings import get_settings

logger = logging.getLogger("wrapsec.auth")

_auth_event_engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
_auth_event_sf     = async_sessionmaker(bind=_auth_event_engine, class_=AsyncSession,
                                        expire_on_commit=False)

PUBLIC_PATHS = {
    "/health",
    "/health/ready",
    "/health/live",
    "/metrics",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/v1/auth/login",    # login is public - no auth required
    "/v1/auth/refresh",  # refresh uses httpOnly cookie - no Bearer required
    "/v1/setup",         # first-run setup - public, self-disables after first user created
    "/v1/setup/status",  # initialization check - public
}

# Paths where middleware must NOT log SESSION_EXPIRED
# (refresh service owns its own logging for these paths)
SKIP_AUTH_EVENT_LOGGING = {"/v1/auth/refresh"}

# Paths accessible even when force_password_change = True
FORCE_CHANGE_ALLOWED = {
    "/v1/auth/change-password",
    "/v1/auth/logout",
    "/v1/auth/me",
}

_TESTING = os.getenv("TESTING") == "true"


def _parse_trusted_proxy_nets(raw: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    nets = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            logger.warning("trusted_proxy_ips: ignoring invalid entry %r", entry)
    return nets


def get_client_ip(request: Request) -> str:
    """
    Returns the real client IP, trusting x-forwarded-for only when the
    direct connection IP is listed in TRUSTED_PROXY_IPS. Without a trusted
    proxy guard, any client can set x-forwarded-for to spoof their IP in
    audit logs and bypass IP-based controls.
    """
    direct_ip = (request.client.host if request.client else None) or "unknown"
    forwarded  = request.headers.get("x-forwarded-for", "").split(",")[0].strip()

    if not forwarded:
        return direct_ip

    trusted_raw = get_settings().trusted_proxy_ips
    if not trusted_raw:
        return direct_ip

    try:
        addr = ipaddress.ip_address(direct_ip)
        nets = _parse_trusted_proxy_nets(trusted_raw)
        if any(addr in net for net in nets):
            return forwarded
    except ValueError:
        pass

    return direct_ip


def _unauthorized(request: Request, reason: str) -> JSONResponse:
    """
    Returns 401 JSONResponse. Always logs reason and path.
    Every auth rejection is visible in logs - no silent 401s.
    """
    logger.warning(
        "auth rejected reason=%s path=%s method=%s",
        reason, request.url.path, request.method,
    )
    return JSONResponse(
        status_code=401,
        content={"error": {
            "code":     "UNAUTHORIZED",
            "message":  "Missing or invalid credentials",
            "trace_id": getattr(request.state, "trace_id", None),
        }},
    )


async def _log_session_expired(
    token:          str,
    failure_reason: str,
    path:           str,
) -> None:
    """
    Logs SESSION_EXPIRED to auth_events.

    Attempts to extract user_id and tenant_id from the token payload
    even if the token is expired or invalid (decode without expiry check).
    If extraction fails, logs with NULL context - never skips logging.

    Non-blocking: NullPool session, best-effort, always closes in finally.
    Must NOT be called when no token is present (noise from health checks).
    Must NOT be called for /v1/auth/refresh path (service owns that logging).
    """
    from uuid import UUID as _UUID

    user_id   = None
    tenant_id = None

    # Attempt context extraction from token even if invalid/expired
    try:
        import jwt as _jwt
        from config.settings import get_settings as _get_settings
        _s = _get_settings()
        raw_payload = _jwt.decode(
            token,
            _s.secret_key,
            algorithms = [_s.jwt_algorithm],
            options    = {"verify_exp": False, "verify_aud": False},
        )
        sub = raw_payload.get("sub")
        tid = raw_payload.get("tenant_id")
        if sub:
            try:
                user_id = _UUID(sub)
            except (ValueError, TypeError):
                pass
        if tid:
            try:
                tenant_id = _UUID(tid)
            except (ValueError, TypeError):
                pass
    except Exception as e:
        logger.debug("auth session_expired context extraction failed: %s", e)

    logger.warning(
        "auth_event SESSION_EXPIRED user_id=%s tenant_id=%s reason=%s path=%s",
        user_id, tenant_id, failure_reason, path,
    )

    from db.repositories.auth_event import AuthEventRepository
    from domain.enums import AuthEventAction as _Action, AuthFailureReason as _Reason

    session = _auth_event_sf()
    try:
        repo = AuthEventRepository(session)
        await repo.insert(
            action         = _Action.SESSION_EXPIRED,
            success        = False,
            tenant_id      = tenant_id,
            user_id        = user_id,
            failure_reason = _Reason(failure_reason),
        )
        await session.commit()
    except Exception as e:
        logger.error("auth_event DB logging failed action=session_expired error=%s", e)
    finally:
        await session.close()


_USER_CACHE_TTL = 1800  # seconds - matches JWT access token expiry
_USER_DB_ERROR  = object()  # sentinel: DB/Redis failure, distinct from "user not found"


async def _get_user_cached(user_uuid: UUID, user_id_str: str):
    """
    Returns the user record for JWT auth, using Redis as a read-through cache.
    Cache key: auth:user:{user_id}, TTL: 1800s (JWT expiry).
    Cache is invalidated in logout_all_sessions() whenever token_version changes.

    Return values:
      SimpleNamespace / ORM user - found (cache hit or DB hit)
      None                       - user does not exist in DB
      _USER_DB_ERROR             - DB/Redis failure (caller returns 500-equivalent)
    """
    import json
    from types import SimpleNamespace

    cache_key = f"auth:user:{user_id_str}"

    # Cache read
    if not _TESTING:
        try:
            from cache.redis_client import get_redis
            raw = await get_redis().get(cache_key)
            if raw:
                d = json.loads(raw)
                return SimpleNamespace(**d)
        except Exception as e:
            logger.debug("auth user cache read failed user_id=%s error=%s", user_id_str, e)

    # Cache miss or test mode - DB lookup
    from db.repositories.user import UserRepository
    try:
        engine, session_ctx = await _get_db_session()
        async with session_ctx as session:
            user = await UserRepository(session).get_by_id(user_uuid)
        if engine:
            await engine.dispose()
    except Exception as e:
        logger.error("auth JWT db_lookup_failed user_id=%s error=%s", user_id_str, e)
        return _USER_DB_ERROR

    # Write to cache (production only - skip in tests)
    if user and not _TESTING:
        try:
            from cache.redis_client import get_redis
            payload = {
                "id":                    str(user.id),
                "is_active":             user.is_active,
                "tenant_id":             str(user.tenant_id) if user.tenant_id else None,
                "dept_id":               str(user.dept_id)   if user.dept_id   else None,
                "role":                  user.role,
                "force_password_change": user.force_password_change,
                "token_version":         user.token_version,
                "email":                 user.email,
            }
            await get_redis().set(cache_key, json.dumps(payload), ex=_USER_CACHE_TTL)
        except Exception as e:
            logger.debug("auth user cache write failed user_id=%s error=%s", user_id_str, e)

    return user  # None if not found, ORM object if found


async def _get_db_session():
    """
    Returns an async session appropriate for the current environment.

    Production: uses AsyncSessionFactory (pooled, efficient)
    Testing: uses NullPool engine (no cross-loop pool poisoning)

    NullPool opens/closes a fresh connection each time - slightly slower
    but completely safe when each pytest test function gets its own event loop.
    """
    if _TESTING:
        from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
        from sqlalchemy.pool import NullPool
        engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
        sf     = async_sessionmaker(bind=engine, class_=AsyncSession,
                                     expire_on_commit=False)
        return engine, sf()
    else:
        from db.session import AsyncSessionFactory
        return None, AsyncSessionFactory()


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Dual-identity auth middleware - API key and JWT coexist.

    Header precedence (absolute, no exceptions):
        IF x-api-key present (non-empty after strip) -> API key path
        ELIF Authorization: Bearer ... -> JWT path
        ELSE -> 401

    API key always wins - JWT is ignored even if valid when x-api-key is present.
    All paths set identical request.state fields - downstream code is auth-agnostic.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path in PUBLIC_PATHS:
            request.state.is_admin = False
            return await call_next(request)

        # Always capture network attribution
        request.state.ip_address = get_client_ip(request)
        request.state.user_agent = request.headers.get("user-agent", "")

        # Initialise all state fields
        request.state.key_id         = None
        request.state.key_name       = None
        request.state.key_type       = "live"
        request.state.app_id         = None
        request.state.dept_id        = None
        request.state.tenant_id      = None
        request.state.is_admin       = False
        request.state.principal_type = "api_key"
        request.state.user_id        = None
        request.state.user_role      = None

        # ── Header precedence - absolute rule ─────────────────────────────────
        api_key = request.headers.get("x-api-key", "").strip()
        auth    = request.headers.get("authorization", "").strip()

        if api_key:
            return await self._authenticate_api_key(api_key, request, call_next)
        elif auth.lower().startswith("bearer "):
            return await self._authenticate_jwt(auth[7:], request, call_next)
        else:
            return _unauthorized(request, "missing_credentials")

    # ── API key path ───────────────────────────────────────────────────────────

    async def _authenticate_api_key(
        self, api_key: str, request: Request, call_next
    ) -> Response:
        if hmac.compare_digest(api_key, get_settings().admin_api_key or ""):
            return await self._authenticate_admin_key(request, call_next)

        if api_key.startswith("wsk_live_") or api_key.startswith("wsk_trial_"):
            key_record = await self._get_standard_key(api_key)
            if key_record:
                request.state.principal_type = "api_key"
                request.state.key_id         = f"key:{key_record.key_id}"
                request.state.key_name       = key_record.name
                request.state.key_type       = getattr(key_record, "key_type", "live") or "live"
                request.state.is_admin       = False
                request.state.app_id         = str(key_record.app_id)    if key_record.app_id    else None
                request.state.dept_id        = str(key_record.dept_id)   if key_record.dept_id   else None
                request.state.tenant_id      = str(key_record.tenant_id) if key_record.tenant_id else None
                request.state.user_id        = None
                request.state.user_role      = None
                return await call_next(request)
            else:
                return _unauthorized(request, "invalid_api_key")

        return _unauthorized(request, "unrecognized_key_format")

    async def _authenticate_admin_key(
        self, request: Request, call_next
    ) -> Response:
        """
        Handles the hardcoded admin key.
        Production: fetches real tenant_id from DB.
        Test mode: skips DB fetch -> tenant_id = None (matches original behaviour).
        """
        tenant_id = None

        if not _TESTING:
            try:
                from db.repositories.tenant import TenantRepository
                from db.session import AsyncSessionFactory
                async with AsyncSessionFactory() as session:
                    tenant = await TenantRepository(session).get_default()
                if tenant:
                    tenant_id = str(tenant.id)
                else:
                    logger.error("auth admin_key no_default_tenant path=%s",
                                 request.url.path)
                    return _unauthorized(request, "system_configuration_error")
            except Exception as e:
                logger.error("auth admin_key tenant_fetch_failed path=%s error=%s",
                             request.url.path, e)
                return _unauthorized(request, "system_configuration_error")

        request.state.principal_type = "api_key"
        request.state.key_id         = "key:admin"
        request.state.key_name       = "Admin Key"
        request.state.key_type       = "live"
        request.state.is_admin       = True
        request.state.dept_id        = None
        request.state.tenant_id      = tenant_id
        request.state.app_id         = None
        request.state.user_id        = None
        request.state.user_role      = None

        return await call_next(request)

    # ── JWT path ───────────────────────────────────────────────────────────────

    async def _authenticate_jwt(
        self, token: str, request: Request, call_next
    ) -> Response:
        """
        JWT authentication path.
        Uses NullPool session in test mode to avoid asyncpg pool poisoning.
        Uses AsyncSessionFactory in production for efficiency.
        """
        from services.auth.token import decode_access_token

        # Step 1 - decode and validate JWT
        # ExpiredSignatureError must be caught BEFORE InvalidTokenError
        # (it is a subclass - order is mandatory, never swap)
        skip_logging = request.url.path in SKIP_AUTH_EVENT_LOGGING
        try:
            payload = decode_access_token(token)
        except ExpiredSignatureError:
            if not skip_logging:
                await _log_session_expired(token, "token_expired", request.url.path)
            return _unauthorized(request, "invalid_or_expired_token")
        except InvalidTokenError:
            if not skip_logging:
                await _log_session_expired(token, "token_invalid", request.url.path)
            return _unauthorized(request, "invalid_or_expired_token")

        # M1: reject tokens whose jti was blacklisted by /logout. Runs before
        # any DB lookup so a revoked token cannot even probe user state.
        from services.auth.jti_blacklist import is_blacklisted
        if await is_blacklisted(payload["jti"]):
            if not skip_logging:
                await _log_session_expired(token, "token_revoked", request.url.path)
            return _unauthorized(request, "invalid_or_expired_token")

        # Step 2 - parse sub claim
        user_id_str = payload.get("sub")
        try:
            user_uuid = UUID(user_id_str)
        except (ValueError, TypeError):
            logger.warning("auth JWT invalid_sub_format user_id=%s path=%s",
                           user_id_str, request.url.path)
            return _unauthorized(request, "invalid_token")

        # Step 2a - load user (Redis cache -> DB fallback)
        user = await _get_user_cached(user_uuid, user_id_str)
        if user is _USER_DB_ERROR:
            return _unauthorized(request, "internal_error")

        # Step 2b - existence
        if not user:
            logger.warning("auth JWT user_not_found user_id=%s path=%s",
                           user_id_str, request.url.path)
            return _unauthorized(request, "invalid_token")

        # Step 2c - active
        if not user.is_active:
            logger.warning("auth JWT user_disabled user_id=%s path=%s",
                           user_id_str, request.url.path)
            return _unauthorized(request, "account_disabled")

        # Step 2d - tenant_id present
        if not user.tenant_id:
            logger.error("auth JWT user_missing_tenant user_id=%s path=%s",
                         user_id_str, request.url.path)
            return _unauthorized(request, "invalid_token")

        # Step 3 - cross-validate tenant_id
        if str(user.tenant_id) != payload.get("tenant_id"):
            logger.error(
                "auth JWT tenant_mismatch user_id=%s "
                "token_tenant=%s db_tenant=%s path=%s",
                user_id_str, payload.get("tenant_id"),
                str(user.tenant_id), request.url.path,
            )
            return _unauthorized(request, "invalid_token")

        # Step 3b - dept_id mismatch log (warning only)
        token_dept = payload.get("dept_id")
        db_dept    = str(user.dept_id) if user.dept_id else None
        if token_dept != db_dept:
            logger.warning(
                "auth_event JWT_DEPT_MISMATCH user_id=%s token_dept=%s db_dept=%s",
                user_id_str, token_dept, db_dept,
            )

        # Step 4 - token version check
        if payload.get("ver") != user.token_version:
            logger.warning(
                "auth_event SESSION_EXPIRED user_id=%s reason=session_invalidated "
                "token_ver=%s user_ver=%s path=%s",
                user_id_str, payload.get("ver"),
                user.token_version, request.url.path,
            )
            if not skip_logging:
                await _log_session_expired(token, "session_invalidated", request.url.path)
            return JSONResponse(
                status_code=401,
                content={"error": {
                    "code":     "SESSION_INVALIDATED",
                    "message":  "Session has been invalidated. Please log in again.",
                    "trace_id": getattr(request.state, "trace_id", None),
                }},
            )

        # Step 5 - populate request.state from DB values
        request.state.principal_type = "user"
        request.state.key_id         = f"user:{user.id}"
        request.state.key_name       = user.email
        request.state.key_type       = "live"
        request.state.is_admin       = (user.role == "ADMIN")
        request.state.dept_id        = str(user.dept_id)   if user.dept_id   else None
        request.state.tenant_id      = str(user.tenant_id)
        request.state.app_id         = None
        request.state.user_id        = str(user.id)
        request.state.user_role      = user.role

        # Step 6 - force_password_change enforcement
        if user.force_password_change and request.url.path not in FORCE_CHANGE_ALLOWED:
            return JSONResponse(
                status_code=403,
                content={"error": {
                    "code":    "PASSWORD_CHANGE_REQUIRED",
                    "message": "You must change your password before accessing this resource.",
                    "hint":    "POST /v1/auth/change-password",
                }},
            )

        return await call_next(request)

    # ── Standard key DB validation (unchanged) ────────────────────────────────

    async def _get_standard_key(self, api_key: str):
        try:
            from db.repositories.api_key import ApiKeyRepository
            from db.session import AsyncSessionFactory

            key_hash = hashlib.sha256(api_key.encode()).hexdigest()

            async with AsyncSessionFactory() as session:
                repo   = ApiKeyRepository(session)
                record = await repo.get_by_hash(key_hash)

                if not record or record.revoked:
                    return None

                if record.expires_at is not None:
                    if utc_now() > record.expires_at:
                        return None

                try:
                    record.last_used_at = utc_now()
                    await session.commit()
                except Exception as e:
                    logger.warning("Failed to update last_used_at for %s: %s",
                                   record.key_id, e)

                return record

        except Exception as e:
            logger.error("Key validation failed: %s", e)
            return None
