import logging

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.dependencies.auth import require_jwt
from api.v1.dependencies.db import get_db
from domain.entities.principal import Principal
from errors.exceptions import (
    AccountDisabledException,
    AccountLockedException,
    AuthenticationError,
    InvalidTokenException,
    SessionInvalidatedException,
)
from services.auth.service import AuthService

logger = logging.getLogger("wrapsec.auth")
router = APIRouter()

auth_service = AuthService()

# ── Cookie settings ────────────────────────────────────────────────────────────
REFRESH_COOKIE_NAME = "refresh_token"
REFRESH_COOKIE_PATH = "/v1/auth"
# Browser only sends this cookie to /v1/auth/* endpoints.
# If the API prefix changes, this path must also change.


def _set_refresh_cookie(response: Response, raw_token: str, max_age: int) -> None:
    from config.settings import get_settings
    _settings = get_settings()
    response.set_cookie(
        key      = REFRESH_COOKIE_NAME,
        value    = raw_token,
        httponly = True,
        secure   = (_settings.environment == "production"),
        samesite = "strict",
        max_age  = max_age,
        path     = REFRESH_COOKIE_PATH,
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.set_cookie(
        key      = REFRESH_COOKIE_NAME,
        value    = "",
        httponly = True,
        secure   = False,
        samesite = "strict",
        max_age  = 0,
        path     = REFRESH_COOKIE_PATH,
    )


# ── Schemas ────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email:    EmailStr  # strict RFC 5322 validation via email-validator
    password: str


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
        401 INVALID_CREDENTIALS — wrong email or wrong password (identical message)
        401 ACCOUNT_DISABLED    — is_active = False
        429 ACCOUNT_LOCKED      — too many failed attempts
    """
    from config.settings import get_settings
    _settings = get_settings()

    try:
        result = await auth_service.login(str(body.email), body.password, db)
    except AccountLockedException as e:
        return JSONResponse(
            status_code=429,
            content={"error": {
                "code":        "ACCOUNT_LOCKED",
                "message":     "Too many failed attempts. Account temporarily locked.",
                "retry_after": e.retry_after,
            }},
        )
    except (AuthenticationError, AccountDisabledException) as e:
        return JSONResponse(
            status_code=401,
            content={"error": {
                "code":    e.code,
                "message": e.message,
            }},
        )

    response = JSONResponse(
        status_code=200,
        content={
            "access_token":          result.access_token,
            "token_type":            "bearer",
            "expires_in":            result.expires_in,
            "force_password_change": result.force_password_change,
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
    )
    return response


@router.post("/refresh")
async def refresh(
    request: Request,
    db:      AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Rotates refresh token and issues new access token.
    Refresh token read from httpOnly cookie — no body required.
    Sets new rotated refresh token as httpOnly cookie.

    Errors:
        401 INVALID_TOKEN       — expired, revoked, or not found
        401 SESSION_INVALIDATED — token_version mismatch
    """
    from config.settings import get_settings
    _settings = get_settings()

    raw_token = request.cookies.get(REFRESH_COOKIE_NAME)
    if not raw_token:
        return JSONResponse(
            status_code=401,
            content={"error": {
                "code":    "INVALID_TOKEN",
                "message": "Refresh token missing.",
            }},
        )

    try:
        result = await auth_service.refresh(raw_token, db)
    except SessionInvalidatedException as e:
        return JSONResponse(
            status_code=401,
            content={"error": {
                "code":    "SESSION_INVALIDATED",
                "message": e.message,
            }},
        )
    except InvalidTokenException as e:
        return JSONResponse(
            status_code=401,
            content={"error": {
                "code":    "INVALID_TOKEN",
                "message": e.message,
            }},
        )

    response = JSONResponse(
        status_code=200,
        content={
            "access_token": result.access_token,
            "token_type":   "bearer",
            "expires_in":   result.expires_in,
        },
    )
    _set_refresh_cookie(
        response  = response,
        raw_token = result.refresh_token,
        max_age   = _settings.jwt_refresh_token_expire_days * 24 * 3600,
    )
    return response


@router.post("/logout")
async def logout(
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(require_jwt),
) -> JSONResponse:
    """
    Revokes refresh token. Access token expires naturally (≤30 min).
    Clears httpOnly cookie. Idempotent — safe to call multiple times.

    Auth: JWT Bearer required.
    """
    raw_token = request.cookies.get(REFRESH_COOKIE_NAME)
    if raw_token:
        await auth_service.logout(raw_token, db)

    response = JSONResponse(
        status_code=200,
        content={"message": "Logged out successfully."},
    )
    _clear_refresh_cookie(response)
    return response


@router.get("/me")
async def me(
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

    # principal.id is "user:{uuid}" — strip prefix
    raw_id    = principal.id.replace("user:", "", 1)
    user_uuid = UUID(raw_id)

    repo = UserRepository(db)
    user = await repo.get_by_id(user_uuid)

    if not user:
        return JSONResponse(
            status_code=404,
            content={"error": {"code": "NOT_FOUND", "message": "User not found."}},
        )

    return JSONResponse(
        status_code=200,
        content={
            "id":                    str(user.id),
            "email":                 user.email,
            "role":                  user.role,
            "dept_id":               str(user.dept_id)   if user.dept_id   else None,
            "tenant_id":             str(user.tenant_id) if user.tenant_id else None,
            "is_active":             user.is_active,
            "force_password_change": user.force_password_change,
            "last_login_at":         user.last_login_at.isoformat() if user.last_login_at else None,
        },
    )


@router.post("/change-password")
async def change_password(
    body:      ChangePasswordRequest,
    principal: Principal    = Depends(require_jwt),
    db:        AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Changes password and invalidates all active sessions.
    Accessible even when force_password_change = True (middleware allowlist).

    Auth: JWT Bearer required.

    Errors:
        400 INVALID_REQUEST  — new password too weak
        401 INVALID_PASSWORD — current password incorrect
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
    except AuthenticationError as e:
        return JSONResponse(
            status_code=401,
            content={"error": {"code": "INVALID_PASSWORD", "message": e.message}},
        )
    except ValueError as e:
        # validate_password_strength raises ValueError
        return JSONResponse(
            status_code=400,
            content={"error": {"code": "INVALID_REQUEST", "message": str(e)}},
        )

    response = JSONResponse(
        status_code=200,
        content={"message": "Password changed. All sessions have been invalidated."},
    )
    _clear_refresh_cookie(response)
    return response
