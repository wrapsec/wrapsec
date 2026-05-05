"""
WrapSec Python SDK — AI Security Gateway client.

Public API surface. Everything listed in __all__ is stable and versioned.
Breaking changes to anything in __all__ require a MAJOR version bump.

Anything NOT in __all__ is internal and may change without notice.
This includes: core/, config/, cli/ internals.

Spec reference: Section 4 (Public API Surface)
"""

from wrapsec.client       import Client
from wrapsec.async_client import AsyncClient
from wrapsec.models       import ScanResult, AuditLog, AuditStats
from wrapsec.exceptions   import (
    WrapSecError,
    WrapSecAuthError,
    WrapSecBlockError,
    WrapSecRateLimitError,
    WrapSecSystemError,
)

__version__ = "1.0.0"

__all__ = [
    # Clients
    "Client",
    "AsyncClient",
    # Models
    "ScanResult",
    "AuditLog",
    "AuditStats",
    # Exceptions
    "WrapSecError",
    "WrapSecAuthError",
    "WrapSecBlockError",
    "WrapSecRateLimitError",
    "WrapSecSystemError",
]
