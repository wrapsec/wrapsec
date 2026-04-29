import hashlib
import logging
import os
from datetime import datetime
from uuid import UUID

from fastapi import Request
from jwt.exceptions import InvalidTokenError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from config.settings import get_settings

logger   = logging.getLogger("wrapsec.auth")
settings = get_settings()

PUBLIC_PATHS = {
    "/health",
    "/health/ready",
    "/health/live",
    "/metrics",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/v1/auth/login",    # login is public — no auth required
    "/v1/auth/refresh",  # refresh uses httpOnly cookie — no Bearer required
}

# Paths accessible even when force_password_change = True
FORCE_CHANGE_ALLOWED = {
    "/v1/auth/change-password",
    "/v1/auth/logout",
    "/v1/auth/me",
}

_TESTING = os.getenv("TESTING") == "true"


def _unauthorized(request: Request, reason: str) -> JSONResponse:
    """
    Returns 401 JSONResponse. Always logs reason and path.
    Every auth rejection is visible in logs — no silent 401s.
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


# Test DB URL — must match conftest.py TEST_DATABASE_URL exactly.
# The middleware uses this in test mode so JWT lookups hit the same
# SQLite DB that the test fixtures populate, not the production PostgreSQL DB.
_TEST_DATABASE_URL = settings.database_url  # PostgreSQL — same as production


async def _get_db_session():
    """
    Returns an async session for JWT user lookup.

    Production: uses AsyncSessionFactory (pooled, efficient)
    Testing:    uses NullPool against the real PostgreSQL database.
                Must NOT use app.dependency_overrides[get_db] — that override
                points at SQLite for non-JWT tests and would cause user_not_found
                for JWT tests where users are in PostgreSQL.
    """
    if _TESTING:
        from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
        from sqlalchemy.pool import NullPool
        engine = create_async_engine(_TEST_DATABASE_URL, poolclass=NullPool)
        sf     = async_sessionmaker(bind=engine, class_=AsyncSession,
                                     expire_on_commit=False)
        return engine, sf()
    else:
        from db.session import AsyncSessionFactory
        return None, AsyncSessionFactory()


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Dual-identity auth middleware — API key and JWT coexist.

    Header precedence (absolute, no exceptions):
        IF x-api-key present (non-empty after strip) → API key path
        ELIF Authorization: Bearer ... → JWT path
        ELSE → 401

    API key always wins — JWT is ignored even if valid when x-api-key is present.
    All paths set identical request.state fields — downstream code is auth-agnostic.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path in PUBLIC_PATHS:
            request.state.is_admin = False
            return await call_next(request)

        # Always capture network attribution
        request.state.ip_address = (
            request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or (request.client.host if request.client else "unknown")
        )
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

        # ── Header precedence — absolute rule ─────────────────────────────────
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
        if api_key == settings.admin_api_key:
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
        Test mode: skips DB fetch → tenant_id = None (matches original behaviour).
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
        from db.repositories.user import UserRepository
        from services.auth.token import decode_access_token

        # Step 1 — decode and validate JWT
        try:
            payload = decode_access_token(token)
        except InvalidTokenError:
            return _unauthorized(request, "invalid_or_expired_token")

        # Step 2 — parse sub claim
        user_id_str = payload.get("sub")
        try:
            user_uuid = UUID(user_id_str)
        except (ValueError, TypeError):
            logger.warning("auth JWT invalid_sub_format user_id=%s path=%s",
                           user_id_str, request.url.path)
            return _unauthorized(request, "invalid_token")

        # Step 2a — load user from DB using environment-appropriate session
        try:
            engine, session_ctx = await _get_db_session()
            async with session_ctx as session:
                repo = UserRepository(session)
                user = await repo.get_by_id(user_uuid)
            if engine:
                await engine.dispose()
        except Exception as e:
            logger.error("auth JWT db_lookup_failed user_id=%s error=%s",
                         user_id_str, e)
            return _unauthorized(request, "internal_error")

        # Step 2b — existence
        if not user:
            logger.warning("auth JWT user_not_found user_id=%s path=%s",
                           user_id_str, request.url.path)
            return _unauthorized(request, "invalid_token")

        # Step 2c — active
        if not user.is_active:
            logger.warning("auth JWT user_disabled user_id=%s path=%s",
                           user_id_str, request.url.path)
            return _unauthorized(request, "account_disabled")

        # Step 2d — tenant_id present
        if not user.tenant_id:
            logger.error("auth JWT user_missing_tenant user_id=%s path=%s",
                         user_id_str, request.url.path)
            return _unauthorized(request, "invalid_token")

        # Step 3 — cross-validate tenant_id
        if str(user.tenant_id) != payload.get("tenant_id"):
            logger.error(
                "auth JWT tenant_mismatch user_id=%s "
                "token_tenant=%s db_tenant=%s path=%s",
                user_id_str, payload.get("tenant_id"),
                str(user.tenant_id), request.url.path,
            )
            return _unauthorized(request, "invalid_token")

        # Step 3b — dept_id mismatch log (warning only)
        token_dept = payload.get("dept_id")
        db_dept    = str(user.dept_id) if user.dept_id else None
        if token_dept != db_dept:
            logger.warning(
                "auth_event JWT_DEPT_MISMATCH user_id=%s token_dept=%s db_dept=%s",
                user_id_str, token_dept, db_dept,
            )

        # Step 4 — token version check
        if payload.get("ver") != user.token_version:
            logger.warning(
                "auth_event SESSION_INVALIDATED user_id=%s "
                "token_ver=%s user_ver=%s path=%s",
                user_id_str, payload.get("ver"),
                user.token_version, request.url.path,
            )
            return JSONResponse(
                status_code=401,
                content={"error": {
                    "code":     "SESSION_INVALIDATED",
                    "message":  "Session has been invalidated. Please log in again.",
                    "trace_id": getattr(request.state, "trace_id", None),
                }},
            )

        # Step 5 — populate request.state from DB values
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

        # Step 6 — force_password_change enforcement
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
                    if datetime.utcnow() > record.expires_at:
                        return None

                try:
                    record.last_used_at = datetime.utcnow()
                    await session.commit()
                except Exception as e:
                    logger.warning("Failed to update last_used_at for %s: %s",
                                   record.key_id, e)

                return record

        except Exception as e:
            logger.error("Key validation failed: %s", e)
            return None
