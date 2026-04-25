from domain.value_objects.trace_id import TraceId


class WrapSecError(Exception):
    """Base exception for all WrapSec errors."""
    def __init__(self, message: str, trace_id: TraceId | None = None):
        self.message  = message
        self.trace_id = trace_id
        super().__init__(message)


# ── Validation ────────────────────────────────────────────────
class ValidationError(WrapSecError):
    code = "INVALID_REQUEST"
    status_code = 400


class StreamNotSupportedError(WrapSecError):
    code = "STREAM_NOT_SUPPORTED"
    status_code = 400
    def __init__(self, trace_id: TraceId | None = None):
        super().__init__(
            "stream is only supported when execution_mode is proxy",
            trace_id
        )


class ModelRequiredError(WrapSecError):
    code = "MODEL_REQUIRED"
    status_code = 400
    def __init__(self, trace_id: TraceId | None = None):
        super().__init__(
            "model is required when execution_mode is proxy",
            trace_id
        )


# ── Auth ──────────────────────────────────────────────────────
class UnauthorizedError(WrapSecError):
    code = "UNAUTHORIZED"
    status_code = 401
    def __init__(self, message: str = "Missing or invalid credentials"):
        super().__init__(message)


class ForbiddenError(WrapSecError):
    code = "FORBIDDEN"
    status_code = 403
    def __init__(self, message: str = "Valid credentials but insufficient scope"):
        super().__init__(message)


class DebugForbiddenError(ForbiddenError):
    def __init__(self):
        super().__init__("debug mode requires admin credentials")


# ── Auth — JWT/session (new for JWT+RBAC) ─────────────────────
class AuthenticationError(WrapSecError):
    """
    Wrong email or wrong password — identical message for both.
    Never reveal which was wrong — prevents user enumeration.
    """
    code        = "INVALID_CREDENTIALS"
    status_code = 401
    def __init__(self, message: str = "Invalid email or password"):
        super().__init__(message)


class AccountLockedException(WrapSecError):
    """
    Account temporarily locked after too many failed login attempts.
    retry_after: seconds until lockout expires (from Redis TTL).
    """
    code        = "ACCOUNT_LOCKED"
    status_code = 429
    def __init__(self, retry_after: int = 0):
        self.retry_after = retry_after
        super().__init__("Too many failed attempts. Account temporarily locked.")


class AccountDisabledException(WrapSecError):
    """Account exists but is_active = False."""
    code        = "ACCOUNT_DISABLED"
    status_code = 401
    def __init__(self):
        super().__init__("Account is disabled. Contact your administrator.")


class InvalidTokenException(WrapSecError):
    """Refresh token not found, already revoked, or expired."""
    code        = "INVALID_TOKEN"
    status_code = 401
    def __init__(self, message: str = "Invalid or expired token"):
        super().__init__(message)


class SessionInvalidatedException(WrapSecError):
    """
    token_version mismatch — session was invalidated after this token was issued.
    Triggered by: password change, role change, account deactivation, admin reset.
    Client must re-authenticate — redirect to login.
    """
    code        = "SESSION_INVALIDATED"
    status_code = 401
    def __init__(self):
        super().__init__("Session has been invalidated. Please log in again.")


class PasswordChangedException(WrapSecError):
    """
    force_password_change = True — user must change password before proceeding.
    Returned on all endpoints except /v1/auth/change-password, /v1/auth/logout,
    /v1/auth/me when this flag is set.
    """
    code        = "PASSWORD_CHANGE_REQUIRED"
    status_code = 403
    def __init__(self):
        super().__init__("You must change your password before accessing this resource.")


# ── Not Found ─────────────────────────────────────────────────
class NotFoundError(WrapSecError):
    code = "NOT_FOUND"
    status_code = 404
    def __init__(self, resource: str, identifier: str):
        super().__init__(f"{resource} not found: {identifier}")


# ── Rate Limit ────────────────────────────────────────────────
class RateLimitError(WrapSecError):
    code = "RATE_LIMIT_EXCEEDED"
    status_code = 429
    def __init__(self):
        super().__init__("Too many requests. Retry after 60 seconds.")


# ── Detection ─────────────────────────────────────────────────
class DetectionError(WrapSecError):
    code = "DETECTION_ERROR"
    status_code = 500
    def __init__(self, message: str = "Internal detection pipeline failure"):
        super().__init__(message)


# ── LLM ───────────────────────────────────────────────────────
class LLMUnavailableError(WrapSecError):
    code = "LLM_UNAVAILABLE"
    status_code = 502
    def __init__(self, provider: str = ""):
        msg = f"LLM provider unavailable: {provider}" if provider else "Upstream LLM provider unreachable"
        super().__init__(msg)


# ── Internal ──────────────────────────────────────────────────
class InternalError(WrapSecError):
    code = "INTERNAL_ERROR"
    status_code = 500
    def __init__(self, message: str = "Unexpected internal error"):
        super().__init__(message)
