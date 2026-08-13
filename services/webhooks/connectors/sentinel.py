# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Microsoft Sentinel / Azure Monitor Logs Ingestion API connector (v1.3.0).

Turns a WrapSec BLOCK/SANITIZE event into a single Logs Ingestion API
record. Pure transform, no network I/O -- the delivery worker owns the
POST and, crucially, the Entra token acquisition (see auth note below).

This targets the current, supported Logs Ingestion API (DCR-based), not
the legacy HTTP Data Collector API, which Microsoft retires on
2026-09-14. The Logs Ingestion contract:

  * Method:   POST
  * URI:      {endpoint}/dataCollectionRules/{dcrImmutableId}
                /streams/{streamName}?api-version=2023-01-01
              where {endpoint} is the DCR logs-ingestion endpoint or a
              data collection endpoint (DCE) for private link.
  * Auth:     Authorization: Bearer <token>
  * Body:     a JSON ARRAY of records matching the DCR stream schema
  * Time:     TimeGenerated is the canonical timestamp column

Auth note (why `token` is opaque here):
  The bearer token is obtained through the Entra client-credentials flow
  (audience https://monitor.azure.com/.default for public cloud). That
  acquisition -- and its caching/refresh -- is a stateful step that
  belongs in the delivery handler, NOT in this pure transform. The
  handler decrypts webhook_endpoints.secret_enc (the app-registration
  client secret), reads tenant_id/client_id from the endpoint config,
  acquires the access token, and passes it here as `token`. This
  connector treats `token` as opaque auth material and only knows to
  place it in a Bearer header -- keeping build_request identical in
  shape to the static-token connectors (Splunk, Datadog).

The audit-shaped body is spread as record columns so a customer's DCR
stream schema can declare typed columns for the WrapSec event fields
(severity + primary_reason included), queryable directly in KQL. No
detector scores beyond what audit logs already expose are added here.
Our body fields are snake_case and do not collide with the reserved
Log Analytics column names (TenantId, Type, Title, id, UniqueId,
_ResourceId, _SubscriptionId).

Required config keys (per-endpoint, resolved by the handler):

    dcr_immutable_id   the DCR immutable id (e.g. "dcr-0a0a...")
    stream_name        the DCR input stream (e.g. "Custom-WrapSec_CL")

Config keys consumed by the handler, NOT this connector: tenant_id,
client_id, and cloud/scope for the token request.
"""

from __future__ import annotations

from typing import Any

from services.webhooks.connectors.base import ConnectorRequest

CONNECTOR_TYPE = "sentinel_logs_ingestion"

# Pinned Logs Ingestion API version (current stable per Microsoft docs).
_API_VERSION = "2023-01-01"


def _build_uri(endpoint: str, dcr_immutable_id: str, stream_name: str) -> str:
    """
    Assemble the Logs Ingestion URI from the endpoint, DCR immutable id,
    and stream name. `endpoint` is the DCR logs-ingestion endpoint (or a
    DCE) with no path; a trailing slash is tolerated.
    """
    base = endpoint.rstrip("/")
    return (
        f"{base}/dataCollectionRules/{dcr_immutable_id}"
        f"/streams/{stream_name}?api-version={_API_VERSION}"
    )


def build_request(
    url:        str,
    token:      str,
    event_type: str,
    body:       dict[str, Any],
    config:     dict[str, Any] | None = None,
) -> ConnectorRequest:
    """
    Build the Logs Ingestion request for one WrapSec event.

    `token` is a bearer access token the handler has already acquired
    from Entra (see module auth note); it is placed in an Authorization
    Bearer header verbatim. `body` is the audit-shaped event body; its
    fields are spread as record columns.

    Raises ValueError when the required config keys `dcr_immutable_id`
    or `stream_name` are missing -- there is no sane default for either,
    and a silent bad URI would fail opaquely at delivery time.
    """
    cfg = config or {}
    dcr_immutable_id = cfg.get("dcr_immutable_id")
    stream_name = cfg.get("stream_name")
    if not dcr_immutable_id or not stream_name:
        raise ValueError(
            "sentinel connector requires config 'dcr_immutable_id' and 'stream_name'"
        )

    # Spread the audit body first so the explicit event_type below takes
    # precedence over any same-named body key.
    record: dict[str, Any] = {**body, "event_type": event_type}

    # TimeGenerated is the Azure-canonical time column. Set it from the
    # body timestamp (ISO 8601, accepted for datetime columns); if absent
    # the ingestion pipeline stamps receipt time.
    timestamp = body.get("timestamp")
    if timestamp:
        record["TimeGenerated"] = timestamp

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
    }

    # Correlate the delivery with our trace on the Microsoft side. trace_id
    # is a UUID string, which is the GUID shape this header expects.
    trace_id = body.get("trace_id")
    if trace_id:
        headers["x-ms-client-request-id"] = str(trace_id)

    # Intake body is an array of records, even for a single event.
    return ConnectorRequest(
        url=_build_uri(url, dcr_immutable_id, stream_name),
        json_payload=[record],
        headers=headers,
    )
