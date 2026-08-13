# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Splunk HEC (HTTP Event Collector) connector (v1.3.0).

Turns a WrapSec BLOCK/SANITIZE event into a single HEC event request.
Pure transform, no network I/O -- the delivery worker owns the POST.

HEC contract this connector targets:

  * Endpoint:  POST {base}/services/collector/event
  * Auth:      Authorization: Splunk <hec_token>
  * Body:      one event object:
                 {
                   "time":       <epoch seconds>,   (optional)
                   "host":       "wrapsec",
                   "source":     "wrapsec",
                   "sourcetype": "wrapsec:security",
                   "index":      "<index>",          (optional)
                   "event":      { ...audit-shaped body... }
                 }

The `event` object is the audit-shaped body passed through unchanged
plus the wire `event_type`, so a customer's Splunk sees the same field
set that GET /v1/audit/logs returns (severity + primary_reason
included). No detector scores beyond what audit logs already expose are
added here.

Config keys (all optional; per-endpoint, resolved by the handler):

    sourcetype  default "wrapsec:security"
    source      default "wrapsec"
    host        default "wrapsec"
    index       omitted when unset (HEC routes to the token's default)
"""

from __future__ import annotations

from typing import Any

from services.webhooks.connectors.base import ConnectorRequest, _epoch_seconds

CONNECTOR_TYPE = "splunk_hec"

# HEC single-event ingest path. Appended to the configured base url unless
# the caller already pointed at the collector.
_COLLECTOR_EVENT_PATH = "/services/collector/event"
_COLLECTOR_BASE_PATH = "/services/collector"

_DEFAULT_SOURCETYPE = "wrapsec:security"
_DEFAULT_SOURCE = "wrapsec"
_DEFAULT_HOST = "wrapsec"


def _resolve_url(url: str) -> str:
    """
    Resolve the configured endpoint url to the HEC single-event path.

    Accepts a bare HEC host ("https://hec.example:8088"), the collector
    base ("...:8088/services/collector"), or the full event path already;
    all three land on ".../services/collector/event" exactly once.
    """
    trimmed = url.rstrip("/")
    if trimmed.endswith(_COLLECTOR_EVENT_PATH):
        return trimmed
    if trimmed.endswith(_COLLECTOR_BASE_PATH):
        return trimmed + "/event"
    return trimmed + _COLLECTOR_EVENT_PATH


def build_request(
    url:        str,
    token:      str,
    event_type: str,
    body:       dict[str, Any],
    config:     dict[str, Any] | None = None,
) -> ConnectorRequest:
    """
    Build the HEC event request for one WrapSec event.

    `token` is the decrypted HEC token (stored envelope-encrypted in
    webhook_endpoints.secret_enc). `body` is the audit-shaped event body
    produced by the emitter; it is embedded under `event` unchanged.
    """
    cfg = config or {}

    event = {"event_type": event_type, **body}

    payload: dict[str, Any] = {
        "host":       cfg.get("host") or _DEFAULT_HOST,
        "source":     cfg.get("source") or _DEFAULT_SOURCE,
        "sourcetype": cfg.get("sourcetype") or _DEFAULT_SOURCETYPE,
        "event":      event,
    }

    epoch = _epoch_seconds(body.get("timestamp"))
    if epoch is not None:
        payload["time"] = epoch

    index = cfg.get("index")
    if index:
        payload["index"] = index

    headers = {
        "Authorization": f"Splunk {token}",
        "Content-Type":  "application/json",
    }

    return ConnectorRequest(url=_resolve_url(url), json_payload=payload, headers=headers)
