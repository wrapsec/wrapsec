# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Single source of truth for time.

WrapSec stores every event timestamp as TIMESTAMPTZ and works with
timezone-aware UTC datetimes throughout the backend (see the timestamp
architecture decision). This module is the ONLY place that produces "now" and
the ONLY place that formats a datetime for the wire, so the aware-UTC contract
is enforced in one location rather than relied on at every call site.

Contract:
- utc_now()      -> aware datetime in UTC. The sole writer of the current time.
- ensure_utc()   -> normalize any datetime to aware UTC (naive is read as UTC,
                    which is safe because WrapSec has only ever written UTC).
- to_iso_z()     -> ISO-8601 string with a trailing 'Z', millisecond precision,
                    e.g. "2026-08-02T09:15:42.123Z". Used for every API response,
                    export, and outbound webhook/SIEM payload.
- parse_utc_iso()-> parse an ISO-8601 string (with or without 'Z') to aware UTC.

Timezone conversion to a user's or tenant's local zone is exclusively a
presentation concern and does not belong here.
"""

from __future__ import annotations

from datetime import datetime, timezone


def utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def ensure_utc(value: datetime) -> datetime:
    """
    Normalize a datetime to aware UTC.

    A naive value is interpreted as UTC (WrapSec has only ever written UTC), so
    legacy naive values and any that slip through remain correct. An aware value
    in any zone is converted to UTC.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def to_iso_z(value: datetime) -> str:
    """
    Format a datetime as ISO-8601 UTC with a trailing 'Z' and millisecond
    precision, e.g. "2026-08-02T09:15:42.123Z".

    Pydantic v2 serializes aware datetimes as "+00:00"; the wire contract is
    the 'Z' form, so this helper is the canonical formatter for API responses,
    exports, and outbound payloads. The input is normalized to UTC first, so
    the offset is always exactly "+00:00" and the replacement is deterministic.
    """
    aware = ensure_utc(value)
    return aware.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_utc_iso(value: str) -> datetime:
    """
    Parse an ISO-8601 timestamp to an aware UTC datetime.

    Accepts both the 'Z' suffix and an explicit offset. A parsed naive value is
    interpreted as UTC. Raises ValueError on an unparseable string, matching
    datetime.fromisoformat.
    """
    text = value.strip()
    # Python's fromisoformat accepts 'Z' only from 3.11; normalize for older
    # runtimes and to keep the behavior explicit regardless of version.
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    return ensure_utc(datetime.fromisoformat(text))
