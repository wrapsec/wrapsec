# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
WrapSec exception hierarchy.

Every exception declares a stable `code` (errors/catalog.py::ErrorCode); its
HTTP status, error severity, and localization key are derived from the catalog.

Text is NOT carried here. Per the error-handling rules
(docs/internal/wrapsec_error_handling_localization_rules.md, sections 5 and 24):

- The USER-facing message is owned by the Localization Catalog and resolved by
  the handler from the code's localization key + params. Call sites never
  hand-write user-facing English.
- `params`   -- structured ICU arguments for the localized message.
- `debug_message` -- diagnostic detail, LOGS ONLY, never serialized. A legacy
  positional `message` is accepted for backward compatibility and treated as
  debug detail (it is never returned to the client).
"""

from __future__ import annotations

from typing import Any

from domain.value_objects.trace_id import TraceId
from errors.catalog import ErrorCode, ErrorSeverity, meta_for


def _coerce_code(code: str) -> ErrorCode:
    """Accept a legacy string code; fall back to INTERNAL_ERROR if unknown."""
    try:
        return ErrorCode(code)
    except ValueError:
        return ErrorCode.INTERNAL_ERROR


class WrapSecError(Exception):
    """Base exception for all WrapSec errors."""
    code: ErrorCode = ErrorCode.INTERNAL_ERROR

    def __init__(
        self,
        message:       str | None             = None,
        trace_id:      TraceId | None          = None,
        code:          ErrorCode | str | None  = None,
        *,
        status_code:   int | None              = None,
        debug_message: str | None              = None,
        params:        dict[str, Any] | None   = None,
        invalid_params: list[dict[str, Any]] | None = None,
    ):
        if code is not None:
            self.code = code if isinstance(code, ErrorCode) else _coerce_code(code)
        meta = meta_for(self.code)
        # Catalog is the source of truth for status; an explicit override is
        # honored for backward compatibility with older direct constructions.
        self.status_code:      int           = status_code if status_code is not None else meta.status_code
        self.severity:         ErrorSeverity = meta.severity
        self.localization_key: str           = meta.localization_key

        # Text is presentation: the user message comes from the catalog, never
        # from here. A caller-supplied `message` is diagnostic detail only.
        self.debug_message  = debug_message or message
        self.params         = params or {}
        self.invalid_params = invalid_params or []
        self.trace_id       = trace_id
        super().__init__(self.debug_message or self.code.value)


# -- Validation ------------------------------------------------
class ValidationError(WrapSecError):
    code = ErrorCode.INVALID_REQUEST


class StreamNotSupportedError(WrapSecError):
    code = ErrorCode.STREAM_NOT_SUPPORTED
    def __init__(self, trace_id: TraceId | None = None):
        super().__init__(trace_id=trace_id)


class ModelRequiredError(WrapSecError):
    code = ErrorCode.MODEL_REQUIRED
    def __init__(self, trace_id: TraceId | None = None):
        super().__init__(trace_id=trace_id)


# -- Auth ------------------------------------------------------
class UnauthorizedError(WrapSecError):
    code = ErrorCode.UNAUTHORIZED


class ForbiddenError(WrapSecError):
    code = ErrorCode.FORBIDDEN


class DebugForbiddenError(ForbiddenError):
    def __init__(self):
        super().__init__(debug_message="debug mode requires admin credentials")


# -- Auth - JWT/session ----------------------------------------
class AuthenticationError(WrapSecError):
    """
    Wrong email or wrong password - identical response for both.
    Never reveal which was wrong - prevents user enumeration. Any distinguishing
    detail belongs in debug_message (logs only), never in the response.
    """
    code = ErrorCode.INVALID_CREDENTIALS


class AccountLockedException(WrapSecError):
    """
    Account temporarily locked after too many failed login attempts.
    retry_after: seconds until lockout expires (from Redis TTL). Kept for the
    Retry-After header; deliberately NOT exposed in the user message or params
    (do not reveal lock timing/threshold -- rules section 12).
    """
    code = ErrorCode.ACCOUNT_LOCKED
    def __init__(self, retry_after: int = 0):
        self.retry_after = retry_after
        super().__init__(debug_message=f"account locked, retry_after={retry_after}s")


class AccountDisabledException(WrapSecError):
    """Account exists but is_active = False."""
    code = ErrorCode.ACCOUNT_DISABLED


class InvalidTokenException(WrapSecError):
    """Refresh token not found, already revoked, or expired."""
    code = ErrorCode.INVALID_TOKEN


class SessionInvalidatedException(WrapSecError):
    """
    token_version mismatch - session was invalidated after this token was issued.
    Triggered by: password change, role change, account deactivation, admin reset.
    Client must re-authenticate - redirect to login.
    """
    code = ErrorCode.SESSION_INVALIDATED


class PasswordChangedException(WrapSecError):
    """
    force_password_change = True - user must change password before proceeding.
    Returned on all endpoints except /v1/auth/change-password, /v1/auth/logout,
    /v1/auth/me when this flag is set.
    """
    code = ErrorCode.PASSWORD_CHANGE_REQUIRED


# -- Not Found -------------------------------------------------
class NotFoundError(WrapSecError):
    code = ErrorCode.NOT_FOUND
    def __init__(self, resource: str, identifier: str):
        self.resource   = resource
        self.identifier = identifier
        # Only the resource is user-facing; the identifier stays in logs and is
        # correlated via trace_id (rules section 15).
        super().__init__(
            params={"resource": resource},
            debug_message=f"{resource} not found: {identifier}",
        )


# -- Conflict --------------------------------------------------
class ConflictError(WrapSecError):
    """A resource with the same unique key (e.g. slug) already exists."""
    code = ErrorCode.CONFLICT


# -- Rate Limit ------------------------------------------------
class RateLimitError(WrapSecError):
    code = ErrorCode.RATE_LIMIT_EXCEEDED
    def __init__(self, retry_after: int = 60):
        self.retry_after = retry_after
        super().__init__(params={"retry_after": retry_after})


# -- Detection -------------------------------------------------
class DetectionError(WrapSecError):
    code = ErrorCode.DETECTION_ERROR


# -- LLM -------------------------------------------------------
class LLMUnavailableError(WrapSecError):
    code = ErrorCode.LLM_UNAVAILABLE
    def __init__(self, provider: str = ""):
        self.provider = provider
        # Provider name is internal detail -> debug only, not the user message.
        super().__init__(debug_message=f"LLM provider unavailable: {provider}" if provider else None)


# -- Internal --------------------------------------------------
class InternalError(WrapSecError):
    code = ErrorCode.INTERNAL_ERROR
