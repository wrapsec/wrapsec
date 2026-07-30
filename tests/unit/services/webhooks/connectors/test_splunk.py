# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests for services.webhooks.connectors.splunk.

The connector is a customer-visible ingest contract: the HEC envelope
shape, the auth header, and the event-path resolution are what a
customer's Splunk parser and index routing depend on. These tests pin
that contract so a casual edit fails loudly in CI.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from services.webhooks.connectors.base import ConnectorRequest
from services.webhooks.connectors.splunk import CONNECTOR_TYPE, build_request


def _body(**overrides):
    body = {
        "trace_id":       "trace-123",
        "timestamp":      "2026-07-30T12:00:00Z",
        "decision":       "BLOCK",
        "primary_reason": "RULE_DETECTOR",
        "risk_score":     0.91,
        "severity":       "HIGH",
    }
    body.update(overrides)
    return body


# --- Envelope shape ---------------------------------------------------

def test_envelope_wraps_body_under_event_with_defaults():
    req = build_request(
        url="https://hec.example:8088",
        token="tok-abc",
        event_type="wrapsec.request.blocked",
        body=_body(),
    )
    assert isinstance(req, ConnectorRequest)
    assert req.method == "POST"
    assert req.json_payload["host"] == "wrapsec"
    assert req.json_payload["source"] == "wrapsec"
    assert req.json_payload["sourcetype"] == "wrapsec:security"
    assert req.json_payload["event"]["trace_id"] == "trace-123"
    assert req.json_payload["event"]["severity"] == "HIGH"


def test_event_carries_event_type_alongside_body():
    req = build_request(
        url="https://hec.example:8088",
        token="tok-abc",
        event_type="wrapsec.request.sanitized",
        body=_body(decision="SANITIZE"),
    )
    assert req.json_payload["event"]["event_type"] == "wrapsec.request.sanitized"
    # Body fields are preserved unchanged next to the injected event_type.
    assert req.json_payload["event"]["decision"] == "SANITIZE"


def test_body_is_not_mutated_by_build_request():
    body = _body()
    build_request(
        url="https://hec.example:8088",
        token="tok-abc",
        event_type="wrapsec.request.blocked",
        body=body,
    )
    assert "event_type" not in body


# --- Auth + content headers -------------------------------------------

def test_authorization_header_uses_splunk_token_scheme():
    req = build_request(
        url="https://hec.example:8088",
        token="my-secret-hec-token",
        event_type="wrapsec.request.blocked",
        body=_body(),
    )
    assert req.headers["Authorization"] == "Splunk my-secret-hec-token"
    assert req.headers["Content-Type"] == "application/json"


# --- Event-path resolution --------------------------------------------

@pytest.mark.parametrize(
    "given, expected",
    [
        ("https://hec.example:8088", "https://hec.example:8088/services/collector/event"),
        ("https://hec.example:8088/", "https://hec.example:8088/services/collector/event"),
        ("https://hec.example:8088/services/collector",
         "https://hec.example:8088/services/collector/event"),
        ("https://hec.example:8088/services/collector/",
         "https://hec.example:8088/services/collector/event"),
        ("https://hec.example:8088/services/collector/event",
         "https://hec.example:8088/services/collector/event"),
    ],
)
def test_url_resolves_to_single_event_path(given, expected):
    req = build_request(
        url=given,
        token="tok",
        event_type="wrapsec.request.blocked",
        body=_body(),
    )
    assert req.url == expected


# --- Event time -------------------------------------------------------

def test_time_is_epoch_seconds_from_body_timestamp():
    req = build_request(
        url="https://hec.example:8088",
        token="tok",
        event_type="wrapsec.request.blocked",
        body=_body(timestamp="2026-07-30T12:00:00Z"),
    )
    expected = datetime(2026, 7, 30, 12, 0, 0, tzinfo=timezone.utc).timestamp()
    assert req.json_payload["time"] == expected


def test_time_is_omitted_when_timestamp_missing_or_unparseable():
    req_missing = build_request(
        url="https://hec.example:8088",
        token="tok",
        event_type="wrapsec.request.blocked",
        body=_body(timestamp=None),
    )
    assert "time" not in req_missing.json_payload

    req_bad = build_request(
        url="https://hec.example:8088",
        token="tok",
        event_type="wrapsec.request.blocked",
        body=_body(timestamp="not-a-date"),
    )
    assert "time" not in req_bad.json_payload


# --- Config overrides -------------------------------------------------

def test_config_overrides_sourcetype_source_host_and_sets_index():
    req = build_request(
        url="https://hec.example:8088",
        token="tok",
        event_type="wrapsec.request.blocked",
        body=_body(),
        config={
            "sourcetype": "custom:st",
            "source":     "custom-src",
            "host":       "gw-1",
            "index":      "security_idx",
        },
    )
    assert req.json_payload["sourcetype"] == "custom:st"
    assert req.json_payload["source"] == "custom-src"
    assert req.json_payload["host"] == "gw-1"
    assert req.json_payload["index"] == "security_idx"


def test_index_absent_when_not_configured():
    req = build_request(
        url="https://hec.example:8088",
        token="tok",
        event_type="wrapsec.request.blocked",
        body=_body(),
    )
    assert "index" not in req.json_payload


def test_connector_type_constant():
    assert CONNECTOR_TYPE == "splunk_hec"
