"""
Configuration schema — allowed keys, types, defaults, and validation.

Spec reference: Section 3 (Module Boundaries — config/schema.py),
                Section 13.2 (wrapsec config command reference)
"""

from __future__ import annotations
from dataclasses import dataclass


# Keys the user is allowed to set via `wrapsec config set`
ALLOWED_CONFIG_KEYS: frozenset[str] = frozenset({
    "api_key",
    "base_url",
    "timeout",
})

# Defaults applied when no value is set anywhere in the priority chain
DEFAULTS: dict[str, object] = {
    "base_url": "http://localhost:8000",
    "timeout":  30,
    # api_key has no default — must be set by user
}

# Minimum timeout enforced at both config-write time and request time
# Spec Section 7: timeout=0 causes indefinite hang in requests/httpx
TIMEOUT_MIN = 1


@dataclass
class WrapSecConfig:
    """
    Resolved configuration object returned by config/loader.py.
    All fields are typed — loader returns this, not raw strings.

    Spec: config/loader.py returns a typed config object, not raw strings.
    """

    api_key:  str | None
    base_url: str
    timeout:  int

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        if self.timeout < TIMEOUT_MIN:
            raise ValueError(
                f"timeout must be at least {TIMEOUT_MIN} second, got {self.timeout}"
            )
        if self.base_url:
            self.base_url = self.base_url.rstrip("/")


def validate_config_value(key: str, value: str) -> object:
    """
    Validate and coerce a raw string value for a given config key.
    Called at config-write time (wrapsec config set) and at load time.

    Returns the coerced value on success.
    Raises ValueError with a clear message on failure.

    Spec: Section 13.2 — validation at both CLI and SDK level
    """
    if key not in ALLOWED_CONFIG_KEYS:
        raise ValueError(
            f"Unknown config key: {key!r}. "
            f"Allowed keys: {', '.join(sorted(ALLOWED_CONFIG_KEYS))}"
        )

    if key == "timeout":
        try:
            v = int(value)
        except (ValueError, TypeError):
            raise ValueError(f"timeout must be an integer, got {value!r}")
        if v < TIMEOUT_MIN:
            raise ValueError(
                f"timeout must be at least {TIMEOUT_MIN} second, got {v}"
            )
        return v

    if key == "base_url":
        if not value.startswith(("http://", "https://")):
            raise ValueError(
                f"base_url must start with http:// or https://, got {value!r}"
            )
        return value.rstrip("/")

    if key == "api_key":
        if not value.startswith("wsk_live_"):
            raise ValueError(
                f"api_key must start with 'wsk_live_', got {value[:12]!r}..."
            )
        return value

    return value
