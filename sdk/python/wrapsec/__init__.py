"""
WrapSec Python SDK - AI Security Gateway client.

Public API surface. Everything listed in __all__ is stable and versioned.
Breaking changes to anything in __all__ require a MAJOR version bump.

Anything NOT in __all__ is internal and may change without notice.
This includes: core/, config/, cli/ internals.

Spec reference: Section 4 (Public API Surface)
"""

from wrapsec.async_client import AsyncClient
from wrapsec.client import Client
from wrapsec.exceptions import (
    WrapSecAuthError,
    WrapSecBlockError,
    WrapSecError,
    WrapSecRateLimitError,
    WrapSecSystemError,
)
from wrapsec.models import (
    AuditLog,
    AuditStats,
    BatchItemResult,
    BatchScanResult,
    ScanResult,
)
from wrapsec.tool_schema import (
    SCAN_TOOL_NAME,
    anthropic_tool,
    openai_tool,
    scan_tool_schema,
)

__version__ = "1.0.0"

__all__ = [
    "SCAN_TOOL_NAME",
    "AsyncClient",
    "AuditLog",
    "AuditStats",
    "BatchItemResult",
    "BatchScanResult",
    # Clients
    "Client",
    # Models
    "ScanResult",
    "WrapSecAuthError",
    "WrapSecBlockError",
    # Exceptions
    "WrapSecError",
    "WrapSecRateLimitError",
    "WrapSecSystemError",
    "anthropic_tool",
    "openai_tool",
    # Agent / function-calling tool manifest
    "scan_tool_schema",
]
