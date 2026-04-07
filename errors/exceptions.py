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