# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Error Catalog -- metadata only.

The single registry that maps every machine-readable error code to its
transport metadata: HTTP status, error severity, and the localization key that
resolves the user-facing text. It stores NO text. English (and every future
locale) lives in the localization catalog under repo-root locales/; the backend
loads a generated English map (errors/errors_en.generated.json) for its
convenience `message` field. See docs/internal/i18n_localization_plan.md.

Contract (LOCKED 2026-08-10, do not revisit):
- Codes are a STABLE, PUBLIC, ADD-ONLY contract. Flat SCREAMING_SNAKE. A code
  is never renamed or repurposed once shipped -- SDKs and SIEM alert rules
  branch on them.
- The localization key carries the domain namespace (errors.CONFLICT), never
  the code.
- Error severity (ERROR/WARNING/INFO) is DISTINCT from threat severity
  (CRITICAL/HIGH/MEDIUM/LOW in domain/value_objects/severity.py). It lives under
  error.severity and styles the dashboard (red/yellow/blue) with no custom
  logic. Do not conflate the two.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ErrorSeverity(str, Enum):
    """How the dashboard styles the error. NOT threat severity."""
    ERROR   = "ERROR"      # a server-side fault; something is broken
    WARNING = "WARNING"    # an expected client-side condition (auth, validation, conflict)
    INFO    = "INFO"       # informational; reserved, unused today


class ErrorCode(str, Enum):
    """
    Stable public error codes. ADD-ONLY -- never rename or repurpose a member.
    New codes append here and gain a catalog entry + a locales/en/errors.json
    string in the same change.
    """
    # Generic / internal
    INTERNAL_ERROR           = "INTERNAL_ERROR"
    VALIDATION_ERROR         = "VALIDATION_ERROR"

    # Request shape
    INVALID_REQUEST          = "INVALID_REQUEST"
    STREAM_NOT_SUPPORTED     = "STREAM_NOT_SUPPORTED"
    MODEL_REQUIRED           = "MODEL_REQUIRED"

    # Auth / session
    UNAUTHORIZED             = "UNAUTHORIZED"
    FORBIDDEN                = "FORBIDDEN"
    INVALID_CREDENTIALS      = "INVALID_CREDENTIALS"
    ACCOUNT_LOCKED           = "ACCOUNT_LOCKED"
    ACCOUNT_DISABLED         = "ACCOUNT_DISABLED"
    INVALID_TOKEN            = "INVALID_TOKEN"
    SESSION_INVALIDATED      = "SESSION_INVALIDATED"
    PASSWORD_CHANGE_REQUIRED = "PASSWORD_CHANGE_REQUIRED"

    INVALID_PASSWORD         = "INVALID_PASSWORD"

    # Account-state guards (client-actionable authorization/state conditions)
    CANNOT_DEACTIVATE_SELF   = "CANNOT_DEACTIVATE_SELF"
    LAST_ADMIN               = "LAST_ADMIN"

    # Resource
    NOT_FOUND                = "NOT_FOUND"
    CONFLICT                 = "CONFLICT"
    IDEMPOTENCY_CONFLICT     = "IDEMPOTENCY_CONFLICT"

    # Throttling
    RATE_LIMIT_EXCEEDED      = "RATE_LIMIT_EXCEEDED"

    # Pipeline / upstream
    DETECTION_ERROR          = "DETECTION_ERROR"
    LLM_UNAVAILABLE          = "LLM_UNAVAILABLE"


class ValidationCode(str, Enum):
    """
    Per-field validation codes for the 422 invalid_params array. Also a stable,
    ADD-ONLY public contract (a form field maps a code to a highlighted input).
    """
    REQUIRED        = "REQUIRED"
    INVALID_EMAIL   = "INVALID_EMAIL"
    TOO_LONG        = "TOO_LONG"
    TOO_SHORT       = "TOO_SHORT"
    INVALID_ENUM    = "INVALID_ENUM"
    INVALID_UUID    = "INVALID_UUID"
    INVALID_URL     = "INVALID_URL"
    INVALID_TYPE    = "INVALID_TYPE"
    OUT_OF_RANGE    = "OUT_OF_RANGE"
    INVALID_VALUE   = "INVALID_VALUE"


@dataclass(frozen=True)
class ErrorMeta:
    """Transport metadata for one error code. No text."""
    status_code:     int
    severity:        ErrorSeverity
    localization_key: str


# code -> (status, severity). The localization key is derived as
# "errors.<CODE>" so the code<->key mirror stays mechanical.
_ERROR_SPEC: dict[ErrorCode, tuple[int, ErrorSeverity]] = {
    ErrorCode.INTERNAL_ERROR:           (500, ErrorSeverity.ERROR),
    ErrorCode.VALIDATION_ERROR:         (422, ErrorSeverity.WARNING),
    ErrorCode.INVALID_REQUEST:          (400, ErrorSeverity.WARNING),
    ErrorCode.STREAM_NOT_SUPPORTED:     (400, ErrorSeverity.WARNING),
    ErrorCode.MODEL_REQUIRED:           (400, ErrorSeverity.WARNING),
    ErrorCode.UNAUTHORIZED:             (401, ErrorSeverity.WARNING),
    ErrorCode.FORBIDDEN:                (403, ErrorSeverity.WARNING),
    ErrorCode.INVALID_CREDENTIALS:      (401, ErrorSeverity.WARNING),
    ErrorCode.ACCOUNT_LOCKED:           (429, ErrorSeverity.WARNING),
    ErrorCode.ACCOUNT_DISABLED:         (401, ErrorSeverity.WARNING),
    ErrorCode.INVALID_TOKEN:            (401, ErrorSeverity.WARNING),
    ErrorCode.SESSION_INVALIDATED:      (401, ErrorSeverity.WARNING),
    ErrorCode.PASSWORD_CHANGE_REQUIRED: (403, ErrorSeverity.WARNING),
    ErrorCode.INVALID_PASSWORD:         (401, ErrorSeverity.WARNING),
    # State conflicts, not RBAC-permission denials (the admin has the permission);
    # 409 = the requested state transition conflicts with the current system state.
    ErrorCode.CANNOT_DEACTIVATE_SELF:   (409, ErrorSeverity.WARNING),
    ErrorCode.LAST_ADMIN:               (409, ErrorSeverity.WARNING),
    ErrorCode.NOT_FOUND:                (404, ErrorSeverity.WARNING),
    ErrorCode.CONFLICT:                 (409, ErrorSeverity.WARNING),
    ErrorCode.IDEMPOTENCY_CONFLICT:     (409, ErrorSeverity.WARNING),
    ErrorCode.RATE_LIMIT_EXCEEDED:      (429, ErrorSeverity.WARNING),
    ErrorCode.DETECTION_ERROR:          (500, ErrorSeverity.ERROR),
    ErrorCode.LLM_UNAVAILABLE:          (502, ErrorSeverity.ERROR),
}

ERROR_CATALOG: dict[ErrorCode, ErrorMeta] = {
    code: ErrorMeta(status, severity, f"errors.{code.value}")
    for code, (status, severity) in _ERROR_SPEC.items()
}

# Per-field validation code -> localization key (forms domain).
VALIDATION_CATALOG: dict[ValidationCode, str] = {
    code: f"forms.errors.{code.value}" for code in ValidationCode
}


def meta_for(code: ErrorCode) -> ErrorMeta:
    """Metadata for a code, defaulting to INTERNAL_ERROR for an unknown code."""
    return ERROR_CATALOG.get(code, ERROR_CATALOG[ErrorCode.INTERNAL_ERROR])


# Pydantic v2 error `type` -> our stable ValidationCode. Unmapped types fall
# back to INVALID_VALUE; the email case is disambiguated in the handler from the
# message text (email-validator reports through the generic value_error type).
PYDANTIC_TYPE_TO_VALIDATION: dict[str, ValidationCode] = {
    "missing":             ValidationCode.REQUIRED,
    "string_too_long":     ValidationCode.TOO_LONG,
    "string_too_short":    ValidationCode.TOO_SHORT,
    "enum":                ValidationCode.INVALID_ENUM,
    "literal_error":       ValidationCode.INVALID_ENUM,
    "uuid_parsing":        ValidationCode.INVALID_UUID,
    "uuid_type":           ValidationCode.INVALID_UUID,
    "url_parsing":         ValidationCode.INVALID_URL,
    "url_type":            ValidationCode.INVALID_URL,
    "invalid_url":         ValidationCode.INVALID_URL,
    "string_type":         ValidationCode.INVALID_TYPE,
    "int_parsing":         ValidationCode.INVALID_TYPE,
    "int_type":            ValidationCode.INVALID_TYPE,
    "bool_parsing":        ValidationCode.INVALID_TYPE,
    "bool_type":           ValidationCode.INVALID_TYPE,
    "float_parsing":       ValidationCode.INVALID_TYPE,
    "greater_than":        ValidationCode.OUT_OF_RANGE,
    "greater_than_equal":  ValidationCode.OUT_OF_RANGE,
    "less_than":           ValidationCode.OUT_OF_RANGE,
    "less_than_equal":     ValidationCode.OUT_OF_RANGE,
}
