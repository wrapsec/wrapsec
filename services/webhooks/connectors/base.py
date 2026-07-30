# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Shared connector primitives (v1.3.0).

ConnectorRequest is the single value every connector returns: the fully
resolved HTTP request a delivery worker should make against a SIEM
ingest API. It is transport-agnostic on purpose -- the worker owns the
HTTP client, timeouts, and status-code interpretation; the connector
only decides url, method, headers, and JSON body.

_epoch_seconds converts the audit-shaped body's ISO `timestamp` field
into epoch seconds for SIEMs that want an explicit event time (Splunk
HEC `time`, etc.). Timestamps in this codebase are naive UTC by design
(TIMESTAMP WITHOUT TIME ZONE); the helper pins them to UTC before
converting so the epoch is correct regardless of the host timezone.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True)
class ConnectorRequest:
    """
    A resolved outbound request for a SIEM ingest endpoint.

    `json_payload` is the JSON body the worker serializes: a dict for
    single-event APIs (Splunk HEC) or a list for array-of-events APIs
    (Datadog logs intake). Headers are complete (auth included) -- the
    worker does not add signing headers for connector deliveries,
    because SIEMs authenticate via the connector's own token/key headers
    rather than the generic webhook-signature HMAC.
    """
    url:          str
    json_payload: dict | list
    method:       str            = "POST"
    headers:      dict[str, str] = field(default_factory=dict)


def _epoch_seconds(iso_timestamp: str | None) -> float | None:
    """
    Parse an ISO timestamp (naive UTC, optional trailing 'Z') into epoch
    seconds. Returns None when the input is missing or unparseable so a
    connector can omit the field and let the SIEM stamp receipt time.
    """
    if not iso_timestamp:
        return None
    raw = iso_timestamp[:-1] if iso_timestamp.endswith("Z") else iso_timestamp
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    # Body timestamps are naive UTC; pin to UTC so .timestamp() does not
    # reinterpret them through the host's local offset.
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()
