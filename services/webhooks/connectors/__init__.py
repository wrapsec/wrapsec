# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
SIEM connectors for outbound webhook delivery (v1.3.0).

Each connector is a pure transform that turns a WrapSec event
(event_type + audit-shaped body dict) into a ConnectorRequest -- the
url, method, headers, and JSON payload a delivery worker should POST to
a specific SIEM's ingest API. Connectors perform no network I/O and
hold no state; that keeps them trivial to unit test and lets the
concrete DeliveryHandler (v1.3.0 delivery commit) select one by
connector_type and hand it the decrypted auth material.

A connector replaces both the signing step and the body step of
generic HMAC-webhook delivery: SIEMs authenticate with their own
token/key headers (not the webhook-signature HMAC) and expect their own
envelope around the event. The audit-shaped body itself is passed
through unchanged so a customer sees the same field set on the SIEM
channel that GET /v1/audit/logs already returns.

Connector contract (all connectors expose this exact signature so the
handler dispatch is uniform):

    build_request(
        url:        str,          # endpoint base url (webhook_endpoints.url)
        token:      str,          # decrypted auth material (secret_enc)
        event_type: str,          # wrapsec.request.blocked | .sanitized
        body:       dict,         # audit-shaped event body
        config:     dict | None,  # per-endpoint connector options
    ) -> ConnectorRequest
"""

from __future__ import annotations

from services.webhooks.connectors.base import ConnectorRequest

__all__ = ["ConnectorRequest"]
