# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Elastic (Elasticsearch) ECS connector (v1.3.0).

Turns a WrapSec BLOCK/SANITIZE event into a single Bulk API operation
carrying an ECS-normalized document. Pure transform, no network I/O --
the delivery worker owns the POST.

Elasticsearch Bulk API contract this connector targets:

  * Endpoint:  POST {base}/{index}/_bulk
  * Auth:      Authorization: ApiKey <base64 id:api_key>
  * Body:      NDJSON -- an action line then a source line, each a
               compact JSON object, newline-delimited, ending with a
               trailing newline. Never pretty-printed.
  * Content:   application/x-ndjson

Only the `create` action is used. It is required for data streams (the
modern Elastic Security ingest target) and is equally valid for a plain
index, so one action covers both. No _id is set, so Elasticsearch
auto-assigns one and the create always succeeds.

The document is normalized to the Elastic Common Schema (ECS) so it
lands usefully in Elastic Security without a custom ingest pipeline:
`@timestamp`, `ecs.version`, `event.*`, `log.level`, and `message` are
set from the event, and the full audit-shaped body is preserved under a
`wrapsec` namespace so no field is lost and none pollutes the ECS root.
severity maps to log.level the same way the Datadog connector maps it to
status. No detector scores beyond what audit logs already expose are
added here.

Config keys (per-endpoint, resolved by the handler):

    index         REQUIRED. Target index or data stream, e.g.
                  "logs-wrapsec.security-default".
    ecs_version   optional, default "8.11.0".

Auth material (`token`) is the base64-encoded Elasticsearch API key
(the "id:api_key" value already base64-encoded), stored envelope-
encrypted in webhook_endpoints.secret_enc.
"""

from __future__ import annotations

import json
from typing import Any

from services.webhooks.connectors.base import ConnectorRequest

CONNECTOR_TYPE = "elastic_ecs"

_DEFAULT_ECS_VERSION = "8.11.0"

# Compact separators keep each NDJSON line free of the spaces and, more
# importantly, the newlines that would corrupt the line-delimited body.
_COMPACT = (",", ":")

# WrapSec severity -> ECS log.level (ECS log.level is a lowercase string).
_SEVERITY_TO_LOG_LEVEL = {
    "CRITICAL": "critical",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "info",
}

# WrapSec decision -> ECS event.type (controlled vocabulary): a BLOCK is
# a denial, a SANITIZE is a modification of the input.
_DECISION_TO_EVENT_TYPE = {
    "BLOCK":    ["denied"],
    "SANITIZE": ["change"],
}


def _build_uri(base: str, index: str) -> str:
    """Assemble the Bulk API URI for the target index/data stream."""
    return f"{base.rstrip('/')}/{index}/_bulk"


def _build_document(event_type: str, body: dict[str, Any], ecs_version: str) -> dict[str, Any]:
    """
    Build the ECS-normalized source document. The full audit body is
    nested under `wrapsec` so ECS root fields stay clean and typed.
    """
    decision = str(body.get("decision", ""))

    event: dict[str, Any] = {
        "kind":     "alert",
        "category": ["intrusion_detection"],
        "action":   decision.lower() or "unknown",
        "dataset":  "wrapsec.security",
        "module":   "wrapsec",
    }
    event_type_ecs = _DECISION_TO_EVENT_TYPE.get(decision)
    if event_type_ecs:
        event["type"] = event_type_ecs

    doc: dict[str, Any] = {
        "ecs":     {"version": ecs_version},
        "event":   event,
        "message": _build_message(body),
        "wrapsec": {**body, "event_type": event_type},
    }

    timestamp = body.get("timestamp")
    if timestamp:
        doc["@timestamp"] = timestamp

    log_level = _SEVERITY_TO_LOG_LEVEL.get(str(body.get("severity")))
    if log_level:
        doc["log"] = {"level": log_level}

    return doc


def _build_message(body: dict[str, Any]) -> str:
    """Human-readable one-line summary for the Elastic message field."""
    return (
        f"WrapSec {body.get('decision', 'UNKNOWN')} "
        f"severity={body.get('severity', 'UNKNOWN')} "
        f"reason={body.get('primary_reason', 'UNKNOWN')} "
        f"trace={body.get('trace_id', 'UNKNOWN')}"
    )


def build_request(
    url:        str,
    token:      str,
    event_type: str,
    body:       dict[str, Any],
    config:     dict[str, Any] | None = None,
) -> ConnectorRequest:
    """
    Build the Bulk API request for one WrapSec event.

    `token` is the base64-encoded Elasticsearch API key. `body` is the
    audit-shaped event body; it is ECS-normalized and nested under the
    `wrapsec` namespace.

    Raises ValueError when the required config key `index` is missing --
    there is no sane default target, and a bad URI would fail opaquely at
    delivery time.
    """
    cfg = config or {}
    index = cfg.get("index")
    if not index:
        raise ValueError("elastic connector requires config 'index'")

    ecs_version = cfg.get("ecs_version") or _DEFAULT_ECS_VERSION
    doc = _build_document(event_type, body, ecs_version)

    # NDJSON: action line, then source line, then a required trailing
    # newline. Compact separators guarantee no embedded newlines.
    action_line = json.dumps({"create": {}}, separators=_COMPACT)
    source_line = json.dumps(doc, separators=_COMPACT)
    ndjson = f"{action_line}\n{source_line}\n"

    headers = {
        "Authorization": f"ApiKey {token}",
        "Content-Type":  "application/x-ndjson",
    }

    return ConnectorRequest(url=_build_uri(url, index), json_payload=ndjson, headers=headers)
