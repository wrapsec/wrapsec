# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Datadog Logs intake connector (v1.3.0).

Turns a WrapSec BLOCK/SANITIZE event into a single Datadog log entry.
Pure transform, no network I/O -- the delivery worker owns the POST.

Datadog Logs HTTP intake contract this connector targets:

  * Endpoint:  POST {base}/api/v2/logs
  * Auth:      DD-API-KEY: <api_key>
  * Body:      a JSON ARRAY of log objects (one entry here)
  * Log object (HTTPLogItem): `message` is the only required field;
    `ddsource`, `ddtags`, `hostname`, `service` are optional reserved
    fields, and any other top-level keys become searchable log
    attributes/facets.

The audit-shaped body is spread as top-level attributes so a customer's
Datadog gets the same field set GET /v1/audit/logs returns (severity +
primary_reason included), each usable as a facet. The body's ISO
`timestamp` attribute is picked up by Datadog's default date remapper as
the log date; there is no dedicated intake date field. `status` is set
from the WrapSec severity so the log lands at the right level in the
Datadog log stream, matching how standard log shippers map severity.

No detector scores beyond what audit logs already expose are added here.

Config keys (all optional; per-endpoint, resolved by the handler):

    service     default "wrapsec"
    ddsource    default "wrapsec"
    hostname    omitted when unset (Datadog falls back to its own host
                resolution)
    tags        list of extra "key:value" strings appended to ddtags
"""

from __future__ import annotations

from typing import Any

from services.webhooks.connectors.base import ConnectorRequest


CONNECTOR_TYPE = "datadog_logs"

_INTAKE_PATH = "/api/v2/logs"

_DEFAULT_SERVICE = "wrapsec"
_DEFAULT_DDSOURCE = "wrapsec"

# WrapSec severity -> Datadog log status (syslog-style level names that
# Datadog's default status remapper recognizes).
_SEVERITY_TO_STATUS = {
    "CRITICAL": "critical",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "info",
}


def _resolve_url(url: str) -> str:
    """
    Resolve the configured endpoint url to the logs intake path.

    Accepts a bare site intake host
    ("https://http-intake.logs.datadoghq.com") or the full intake url
    already; both land on ".../api/v2/logs" exactly once. The customer
    is responsible for pointing url at the intake host for their Datadog
    site (US1/EU/US3/US5/AP1/gov differ).
    """
    trimmed = url.rstrip("/")
    if trimmed.endswith(_INTAKE_PATH):
        return trimmed
    return trimmed + _INTAKE_PATH


def _build_ddtags(event_type: str, body: dict[str, Any], cfg: dict[str, Any]) -> str:
    """
    Build the comma-separated ddtags string from event context plus any
    operator-supplied extra tags. Datadog expects a single string of
    "key:value" pairs joined by commas.
    """
    tags = [f"event_type:{event_type}"]
    decision = body.get("decision")
    if decision:
        tags.append(f"decision:{decision}")
    severity = body.get("severity")
    if severity:
        tags.append(f"severity:{severity}")
    extra = cfg.get("tags")
    if extra:
        tags.extend(str(t) for t in extra)
    return ",".join(tags)


def build_request(
    url:        str,
    token:      str,
    event_type: str,
    body:       dict[str, Any],
    config:     dict[str, Any] | None = None,
) -> ConnectorRequest:
    """
    Build the Datadog logs-intake request for one WrapSec event.

    `token` is the decrypted Datadog API key (stored envelope-encrypted
    in webhook_endpoints.secret_enc). `body` is the audit-shaped event
    body produced by the emitter; its fields are spread as log
    attributes.
    """
    cfg = config or {}

    # Spread the audit body first so the explicit reserved fields below
    # take precedence over any same-named body key.
    log_item: dict[str, Any] = {
        **body,
        "event_type": event_type,
        "ddsource":   cfg.get("ddsource") or _DEFAULT_DDSOURCE,
        "service":    cfg.get("service") or _DEFAULT_SERVICE,
        "ddtags":     _build_ddtags(event_type, body, cfg),
        "message":    _build_message(event_type, body),
    }

    status = _SEVERITY_TO_STATUS.get(str(body.get("severity")))
    if status:
        log_item["status"] = status

    hostname = cfg.get("hostname")
    if hostname:
        log_item["hostname"] = hostname

    headers = {
        "DD-API-KEY":   token,
        "Content-Type": "application/json",
    }

    # Intake body is an array of log objects, even for a single event.
    return ConnectorRequest(url=_resolve_url(url), json_payload=[log_item], headers=headers)


def _build_message(event_type: str, body: dict[str, Any]) -> str:
    """
    Human-readable one-line summary for the Datadog log stream. Datadog
    indexes `message` for full-text search and shows it as the log line,
    so it carries the decision, severity, reason, and trace at a glance.
    """
    return (
        f"WrapSec {body.get('decision', 'UNKNOWN')} "
        f"severity={body.get('severity', 'UNKNOWN')} "
        f"reason={body.get('primary_reason', 'UNKNOWN')} "
        f"trace={body.get('trace_id', 'UNKNOWN')}"
    )
