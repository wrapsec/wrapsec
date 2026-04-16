"""
WrapSec exception hierarchy.

All exceptions in __all__ are stable public API.
Anything not listed here is internal.

Spec reference: Section 8 (SDK Error Mapping), Section 4 (Public API Surface)
"""

from __future__ import annotations
from typing import Any


class WrapSecError(Exception):
    """
    Base exception for all WrapSec errors.
    Catch this to handle any WrapSec-related failure.
    """

    def __init__(self, message: str, *, status_code: int | None = None, response: Any = None) -> None:
        super().__init__(message)
        self.message     = message
        self.status_code = status_code
        self.response    = response  # raw response dict if available

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.message!r})"


class WrapSecAuthError(WrapSecError):
    """
    Raised on HTTP 401 (invalid/revoked key) or 403 (insufficient permissions).
    Never retried — auth errors are permanent.

    Spec: Section 8, Section 15
    """


class WrapSecRateLimitError(WrapSecError):
    """
    Raised on HTTP 429 (rate limit exceeded).
    Never retried — retrying worsens the situation.

    Spec: Section 8, Section 9
    """


class WrapSecSystemError(WrapSecError):
    """
    Raised on HTTP 5xx, timeout, connection error, or invalid JSON response.
    Retried up to 3 times with exponential backoff before being raised.

    Also used when primary_reason == "SYSTEM_ERROR" in a scan response —
    the CLI exits with code 1 in that case (not code 2).

    Spec: Section 8, Section 9, Section 11.2
    """


class WrapSecBlockError(WrapSecError):
    """
    Available for callers who prefer exception-based flow for BLOCK decisions.

    IMPORTANT: The SDK never raises this automatically.
    client.scan() always returns ScanResult — callers check result.decision.
    Raise this manually if your application prefers exception handling:

        result = client.scan(text)
        if result.decision == "BLOCK":
            raise WrapSecBlockError(result)

    Spec: Section 8
    """

    def __init__(self, result: Any) -> None:
        super().__init__(
            f"Input blocked by WrapSec security policy "
            f"(reason: {getattr(result, 'primary_reason', 'unknown')}, "
            f"trace: {getattr(result, 'trace_id', 'unknown')})"
        )
        self.result = result


__all__ = [
    "WrapSecError",
    "WrapSecAuthError",
    "WrapSecRateLimitError",
    "WrapSecSystemError",
    "WrapSecBlockError",
]
