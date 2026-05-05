# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import uuid


class TraceId:
    PREFIX = "req"

    def __init__(self, value: str | None = None):
        if value:
            self._value = value
        else:
            self._value = f"{self.PREFIX}_{self._generate_ulid()}"

    @staticmethod
    def _generate_ulid() -> str:
        """
        Generate a ULID-based identifier.
        Lexicographically sortable by time — better for DB indexing
        and audit log ordering than random hex.
        Falls back to random hex if python-ulid not installed.
        """
        try:
            from ulid import ULID
            return str(ULID()).lower()
        except ImportError:
            # Fallback — full 128-bit random hex for collision safety
            return uuid.uuid4().hex

    @property
    def value(self) -> str:
        return self._value

    @classmethod
    def generate(cls) -> "TraceId":
        return cls()

    _MIN_SUFFIX_LEN = 20
    _MAX_LEN        = 64

    @classmethod
    def from_string(cls, value: str) -> "TraceId":
        prefix = cls.PREFIX + "_"
        if not value.startswith(prefix):
            raise ValueError(f"Invalid trace_id format: {value}")
        suffix = value[len(prefix):]
        if len(suffix) < cls._MIN_SUFFIX_LEN:
            raise ValueError(f"Invalid trace_id format: suffix too short")
        if len(value) > cls._MAX_LEN:
            raise ValueError(f"Invalid trace_id format: value too long")
        if not all(c in "0123456789abcdefghijklmnopqrstuvwxyz-" for c in suffix):
            raise ValueError(f"Invalid trace_id format: invalid characters in suffix")
        return cls(value)

    def __str__(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"TraceId('{self._value}')"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, TraceId):
            return self._value == other._value
        return False

    def __hash__(self) -> int:
        return hash(self._value)