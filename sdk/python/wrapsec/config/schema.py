# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

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

# Fix #3 — API key minimum length.
# "wsk_live_" is 8 chars. A real key must have at least 20 additional chars
# of random entropy after the prefix to be meaningful.
# "wsk_trial_" is 9 chars — same rule applies.
_API_KEY_MIN_TOTAL_LEN = 32
_VALID_API_KEY_PREFIXES = ("wsk_live_", "wsk_trial_", "wrapsec_")


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
        # Fix #3 — validate prefix AND minimum length.
        # Previous check only validated prefix — "wsk_live_" alone (8 chars) would pass.
        # A real WrapSec key has significant random entropy after the prefix.
        # Minimum total length of 32 chars rejects obvious misconfiguration
        # (typos, truncated keys, placeholder values) before the first API call.
        #
        # Accepted prefixes:
        #   wsk_live_   — production live keys
        #   wsk_trial_  — trial/demo keys
        #   wrapsec_   — hardcoded admin key (development only)
        if not any(value.startswith(p) for p in _VALID_API_KEY_PREFIXES):
            raise ValueError(
                f"api_key must start with 'wsk_live_', 'wsk_trial_', or 'wrapsec_'. "
                f"Got: {value[:12]!r}..."
            )
        if len(value) < _API_KEY_MIN_TOTAL_LEN:
            raise ValueError(
                f"api_key appears too short ({len(value)} chars). "
                f"Expected at least {_API_KEY_MIN_TOTAL_LEN} characters. "
                f"Check that the key was copied correctly."
            )
        return value

    return value
