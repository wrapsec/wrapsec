# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import logging

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.dependencies.auth import require_jwt
from api.v1.dependencies.db import get_db
from api.v1.middleware.auth import get_client_ip
from cache import keyspace
from domain.entities.principal import Principal
from errors.catalog import ErrorCode
from errors.exceptions import (
    AccountDisabledException,
    AccountLockedException,
    AuthenticationError,
    InvalidTokenException,
    SessionInvalidatedException,
)
from errors.response import error_response
from services.auth.service import AuthService
from services.localization import resolve_locale, validate_locale_input
from services.time import to_iso_z, utc_now

logger = logging.getLogger("wrapsec.auth")
router = APIRouter()

auth_service = AuthService()

# ── Cookie settings ────────────────────────────────────────────────────────────
REFRESH_COOKIE_NAME = "refresh_token"

# M5: refresh_cookie Path is resolved per-request. A BFF (dashboard) fronts
# /v1/auth/* under its own prefix (/api/auth/*); the browser only sends the
# cookie to whichever Path the BFF is reachable at. Rather than the BFF
# regex-re-parsing the backend Set-Cookie and re-emitting with a rewritten
# Path (fragile: silent drift when the backend adds SameSite=lax or
# Partitioned), the BFF supplies its Path via X-Refresh-Cookie-Path AND
# proves it is trusted by presenting an Origin in the CORS allowlist.
# Direct callers (SDK using API keys don't need it; browser extension
# calling /v1/* directly) fall through to the configured default
# (settings.refresh_cookie_path, default "/v1/auth"). OWASP-compliant
# tight-scoping preserved.

import re

_REFRESH_COOKIE_PATH_RE = re.compile(r"^/[a-zA-Z0-9/_-]*$")
_MAX_COOKIE_PATH_LEN    = 128


def _valid_cookie_path(candidate: str) -> bool:
    """Path chars only, no traversal, no empty segments, bounded length."""
    if not candidate or len(candidate) > _MAX_COOKIE_PATH_LEN:
        return False
    if not _REFRESH_COOKIE_PATH_RE.match(candidate):
        return False
    return not (".." in candidate or "//" in candidate)


def _resolve_refresh_cookie_path(request: Request | None) -> str:
    """
    Return the Path attribute to use on the refresh_token cookie.

    Uses `X-Refresh-Cookie-Path` if ALL of:
      1. The request has an `Origin` header.
      2. That Origin exists in `settings.cors_allowed_origins` (same
         allowlist that already gates credentialed CORS).
      3. The header value passes _valid_cookie_path.
    Otherwise falls back to `settings.refresh_cookie_path`.

    Notes on threat model: the refresh cookie is issued in response to a
    successful login. Path only affects when THAT session's cookie is sent
    by the browser. An attacker manipulating the header can only mis-scope
    THEIR OWN cookie - no cross-user attack. The Origin gate is
    defense-in-depth against a rogue-Origin caller nudging Path to a value
    that would leak the cookie to an unexpected endpoint.
    """
    from config.settings import get_settings
    _settings = get_settings()
    default   = _settings.refresh_cookie_path

    if request is None:
        return default

    header_path = request.headers.get("x-refresh-cookie-path")
    if not header_path:
        return default

    origin = request.headers.get("origin")
    if not origin or origin not in _settings.cors_allowed_origins:
        return default

    if not _valid_cookie_path(header_path):
        return default

    return header_path


def _set_refresh_cookie(
    response:  Response,
    raw_token: str,
    max_age:   int,
    request:   Request | None = None,
) -> None:
    from config.settings import get_settings
    _settings = get_settings()
    response.set_cookie(
        key      = REFRESH_COOKIE_NAME,
        value    = raw_token,
        httponly = True,
        secure   = _settings.cookie_secure,
        samesite = "strict",
        max_age  = max_age,
        path     = _resolve_refresh_cookie_path(request),
    )


def _clear_refresh_cookie(response: Response, request: Request | None = None) -> None:
    from config.settings import get_settings
    _settings = get_settings()
    # secure flag must match the flag used when the cookie was set; a mismatch
    # means the browser treats them as different cookies and the old one persists.
    # Same rule for Path: clear must target the same Path the cookie was set at.
    response.set_cookie(
        key      = REFRESH_COOKIE_NAME,
        value    = "",
        httponly = True,
        secure   = _settings.cookie_secure,
        samesite = "strict",
        max_age  = 0,
        path     = _resolve_refresh_cookie_path(request),
    )


# ── Schemas ────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email:    EmailStr  # strict RFC 5322 validation via email-validator
    password: str


class LogoutRequest(BaseModel):
    reason: str = "manual"


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password:     str


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.post("/login")
async def login(
    body:    LoginRequest,
    request: Request,
    db:      AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Authenticates a dashboard user with email + password.
    Returns JWT access token in response body.
    Sets refresh token as httpOnly cookie (Path=/v1/auth).

    Email validated by Pydantic (RFC 5322) before reaching service layer.
    Service layer additionally normalizes via normalize_email() (lowercase + strip).

    Errors:
        401 INVALID_CREDENTIALS - wrong email or wrong password (identical message)
        401 ACCOUNT_DISABLED    - is_active = False
        429 ACCOUNT_LOCKED      - too many failed attempts
    """
    import os

    from config.settings import get_settings
    _settings = get_settings()

    ip_address = get_client_ip(request) or None
    user_agent = request.headers.get("user-agent")

    # IP-based rate limit - fires before any DB work or per-email lockout.
    # Separate from the global 60/min; targets credential-stuffing from one IP.
    # Fails open so a Redis outage never blocks legitimate logins.
    if os.getenv("TESTING") != "true":
        try:
            from cache.rate_limit_store import is_rate_limited
            _rl_key = keyspace.login_rate_limit(ip_address or "unknown")
            _limited, _, _ = await is_rate_limited(_rl_key, limit=_settings.login_rate_limit_per_minute)
            if _limited:
                return error_response(
                    ErrorCode.RATE_LIMIT_EXCEEDED,
                    trace_id=getattr(request.state, "trace_id", ""),
                    params={"retry_after": 60},
                )
        except Exception:
            pass  # Fail open - never block login due to Redis unavailability

    try:
        result = await auth_service.login(
            str(body.email), body.password, db,
            ip_address = ip_address or None,
            user_agent = user_agent or None,
        )
    except (AccountLockedException, AuthenticationError, AccountDisabledException):
        # All credential failures return identical 401 - distinguishing locked,
        # wrong password, disabled, or non-existent accounts leaks email existence.
        return error_response(
            ErrorCode.INVALID_CREDENTIALS,
            trace_id=getattr(request.state, "trace_id", ""),
        )

    # Effective locale for the session (User -> Tenant -> System -> English), so
    # the BFF can set the wrapsec_locale cookie next-intl reads. Resolution stays
    # here in WrapSec, not on the frontend.
    from db.repositories.tenant import TenantRepository
    _tenant = await TenantRepository(db).get_by_id(result.user.tenant_id) if result.user.tenant_id else None
    _resolved_locale = resolve_locale(result.user.locale, _tenant.locale if _tenant else None)

    response = JSONResponse(
        status_code=200,
        content={
            "access_token":          result.access_token,
            "token_type":            "bearer",
            "expires_in":            result.expires_in,
            "force_password_change": result.force_password_change,
            "resolved_locale":       _resolved_locale,
            "user": {
                "id":        str(result.user.id),
                "email":     result.user.email,
                "role":      result.user.role,
                "dept_id":   str(result.user.dept_id)   if result.user.dept_id   else None,
                "tenant_id": str(result.user.tenant_id) if result.user.tenant_id else None,
            },
        },
    )
    _set_refresh_cookie(
        response  = response,
        raw_token = result.refresh_token,
        max_age   = _settings.jwt_refresh_token_expire_days * 24 * 3600,
        request   = request,
    )
    return response


@router.post("/refresh")
async def refresh(
    request: Request,
    db:      AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Rotates refresh token and issues new access token.
    Refresh token read from httpOnly cookie - no body required.
    Sets new rotated refresh token as httpOnly cookie.

    Errors:
        401 INVALID_TOKEN       - expired, revoked, or not found
        401 SESSION_INVALIDATED - token_version mismatch
    """
    from config.settings import get_settings
    _settings = get_settings()

    raw_token = request.cookies.get(REFRESH_COOKIE_NAME)
    if not raw_token:
        return error_response(
            ErrorCode.INVALID_TOKEN,
            trace_id=getattr(request.state, "trace_id", ""),
        )

    try:
        result = await auth_service.refresh(raw_token, db)
    except SessionInvalidatedException:
        return error_response(
            ErrorCode.SESSION_INVALIDATED,
            trace_id=getattr(request.state, "trace_id", ""),
        )
    except InvalidTokenException:
        return error_response(
            ErrorCode.INVALID_TOKEN,
            trace_id=getattr(request.state, "trace_id", ""),
        )

    # Re-resolve the locale on every refresh so a tenant/user preference change
    # propagates to a live session without re-login (User -> Tenant -> System ->
    # English). The BFF updates wrapsec_locale from this.
    from db.repositories.tenant import TenantRepository
    _tenant = await TenantRepository(db).get_by_id(result.user.tenant_id) if result.user.tenant_id else None
    _resolved_locale = resolve_locale(result.user.locale, _tenant.locale if _tenant else None)

    response = JSONResponse(
        status_code=200,
        content={
            "access_token":    result.access_token,
            "token_type":      "bearer",
            "expires_in":      result.expires_in,
            "resolved_locale": _resolved_locale,
        },
    )
    _set_refresh_cookie(
        response  = response,
        raw_token = result.refresh_token,
        max_age   = _settings.jwt_refresh_token_expire_days * 24 * 3600,
        request   = request,
    )
    return response


@router.post("/logout")
async def logout(
    request:   Request,
    body:      LogoutRequest = LogoutRequest(),
    db:        AsyncSession  = Depends(get_db),
    principal: Principal     = Depends(require_jwt),
) -> JSONResponse:
    """
    Revokes refresh token AND blacklists the presented access token's jti
    for the remainder of its lifetime (M1). Access token becomes unusable
    immediately - not just after natural expiry. Clears httpOnly cookie.
    Idempotent - safe to call multiple times.

    Optional body: { "reason": "manual" | "inactivity" | "expired" }
    Invalid reason values are normalized to "manual" - never returns 400.

    Auth: JWT Bearer required.
    """
    from domain.enums import LogoutReason

    # Validate and normalize reason - never raise 400 for invalid value
    try:
        logout_reason = LogoutReason(body.reason).value
    except ValueError:
        logout_reason = LogoutReason.MANUAL.value

    raw_token = request.cookies.get(REFRESH_COOKIE_NAME)
    if raw_token:
        await auth_service.logout(raw_token, db, reason=logout_reason)

    # M1: blacklist the access token's jti so it cannot be reused before exp.
    # The middleware has already decoded and validated the token to get here,
    # but we need jti + exp - re-parse the Authorization header token.
    await _blacklist_current_access_token(request)

    response = JSONResponse(
        status_code=200,
        content={"message": "Logged out successfully."},
    )
    _clear_refresh_cookie(response, request=request)
    return response


async def _blacklist_current_access_token(request: Request) -> None:
    """
    Best-effort: extract Bearer token, decode it, blacklist jti for the
    token's remaining lifetime. Any failure is swallowed - logout must
    always succeed even if blacklisting fails.
    """
    from services.auth.jti_blacklist import blacklist_jti
    from services.auth.token import decode_access_token

    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        return

    token = auth_header.split(" ", 1)[1].strip()
    try:
        payload = decode_access_token(token)
    except Exception:
        return  # expired or invalid - nothing to blacklist

    jti = payload.get("jti")
    exp = payload.get("exp")
    if not jti or not exp:
        return

    ttl = int(exp - utc_now().timestamp())
    if ttl <= 0:
        return

    await blacklist_jti(jti, ttl)


async def _me_payload(db: AsyncSession, user) -> dict:
    """Profile response, including the stored locale preference and the effective
    (resolved) locale. resolved_locale applies the User -> Tenant -> System ->
    English precedence, validating each candidate against the allowlist."""
    from db.repositories.tenant import TenantRepository

    tenant        = await TenantRepository(db).get_by_id(user.tenant_id) if user.tenant_id else None
    tenant_locale = tenant.locale if tenant else None
    return {
        "id":                    str(user.id),
        "email":                 user.email,
        "role":                  user.role,
        "dept_id":               str(user.dept_id)   if user.dept_id   else None,
        "tenant_id":             str(user.tenant_id) if user.tenant_id else None,
        "is_active":             user.is_active,
        "force_password_change": user.force_password_change,
        "last_login_at":         to_iso_z(user.last_login_at) if user.last_login_at else None,
        "locale":                user.locale,
        "resolved_locale":       resolve_locale(user.locale, tenant_locale),
    }


class MePatchSchema(BaseModel):
    # Optional preference. Explicit null clears it (inherit tenant/system). An
    # unsupported value is rejected 422 INVALID_ENUM (see services.localization).
    # max_length mirrors the users.locale VARCHAR(35) column and the BCP-47
    # identifier ceiling: a clean HTTP -> allowlist -> DB boundary, and it caps an
    # oversized string before the validator runs.
    locale: str | None = Field(default=None, max_length=35)

    @field_validator("locale")
    @classmethod
    def _valid_locale(cls, v: str | None) -> str | None:
        return validate_locale_input(v)


@router.get("/me")
async def me(
    request:   Request,
    principal: Principal    = Depends(require_jwt),
    db:        AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Returns current user profile.
    Accessible even when force_password_change = True (middleware allowlist).

    Auth: JWT Bearer required.
    """
    from uuid import UUID

    from db.repositories.user import UserRepository

    # principal.id is "user:{uuid}" - strip prefix
    raw_id    = principal.id.replace("user:", "", 1)
    user_uuid = UUID(raw_id)

    repo = UserRepository(db)
    user = await repo.get_by_id(user_uuid)

    if not user:
        return error_response(
            ErrorCode.NOT_FOUND,
            trace_id=getattr(request.state, "trace_id", ""),
            params={"resource": "User"},
        )

    return JSONResponse(status_code=200, content=await _me_payload(db, user))


@router.patch("/me")
async def update_me(
    body:      MePatchSchema,
    request:   Request,
    principal: Principal    = Depends(require_jwt),
    db:        AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Self-service profile preferences. Currently updates the locale preference
    only (validated against the supported-locales allowlist).

    Auth: JWT Bearer required.
    """
    from uuid import UUID

    from db.repositories.user import UserRepository

    raw_id    = principal.id.replace("user:", "", 1)
    user_uuid = UUID(raw_id)

    repo = UserRepository(db)
    data = body.model_dump(exclude_unset=True)  # only fields the client sent
    if data:
        user = await repo.update(user_uuid, data)
        if user is None:
            return error_response(
                ErrorCode.NOT_FOUND,
                trace_id=getattr(request.state, "trace_id", ""),
                params={"resource": "User"},
            )
        await db.commit()
    else:
        user = await repo.get_by_id(user_uuid)
        if user is None:
            return error_response(
                ErrorCode.NOT_FOUND,
                trace_id=getattr(request.state, "trace_id", ""),
                params={"resource": "User"},
            )

    return JSONResponse(status_code=200, content=await _me_payload(db, user))


@router.post("/change-password")
async def change_password(
    body:      ChangePasswordRequest,
    request:   Request,
    principal: Principal    = Depends(require_jwt),
    db:        AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Changes password and invalidates all active sessions.
    Accessible even when force_password_change = True (middleware allowlist).

    Auth: JWT Bearer required.

    Errors:
        400 INVALID_REQUEST  - new password too weak
        401 INVALID_PASSWORD - current password incorrect
    """
    from uuid import UUID

    raw_id    = principal.id.replace("user:", "", 1)
    user_uuid = UUID(raw_id)

    try:
        await auth_service.change_password(
            user_id          = user_uuid,
            current_password = body.current_password,
            new_password     = body.new_password,
            db               = db,
        )
    except AuthenticationError:
        # Current password wrong. The message is normalized to the catalog
        # ("Current password is incorrect."); no email/password detail is echoed.
        return error_response(
            ErrorCode.INVALID_PASSWORD,
            trace_id=getattr(request.state, "trace_id", ""),
        )
    except ValueError as e:
        # validate_password_strength raises ValueError with English rule text.
        # Per rules section 18, raw validator strings are not exposed as user
        # messages; the detail goes to logs until dedicated forms/password keys
        # exist. The client gets the generic INVALID_REQUEST message.
        logger.info(
            "weak new password rejected trace_id=%s: %s",
            getattr(request.state, "trace_id", ""), e,
        )
        return error_response(
            ErrorCode.INVALID_REQUEST,
            trace_id=getattr(request.state, "trace_id", ""),
        )

    response = JSONResponse(
        status_code=200,
        content={"message": "Password changed. All sessions have been invalidated."},
    )
    _clear_refresh_cookie(response, request=request)
    return response
