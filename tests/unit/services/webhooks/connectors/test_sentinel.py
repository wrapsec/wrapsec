# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests for services.webhooks.connectors.sentinel.

The connector is a customer-visible ingest contract: the DCR stream URI
(with the pinned api-version), the Bearer auth header, the single-record
array body, and TimeGenerated mapping are what a customer's Log
Analytics workspace and DCR depend on. These tests pin that contract so
a casual edit fails loudly in CI.
"""

from __future__ import annotations

import pytest

from services.webhooks.connectors.base import ConnectorRequest
from services.webhooks.connectors.sentinel import CONNECTOR_TYPE, build_request

_CFG = {"dcr_immutable_id": "dcr-0a0a", "stream_name": "Custom-WrapSec_CL"}


def _body(**overrides):
    body = {
        "trace_id":       "11111111-2222-3333-4444-555555555555",
        "timestamp":      "2026-07-30T12:00:00Z",
        "decision":       "BLOCK",
        "primary_reason": "RULE_DETECTOR",
        "risk_score":     0.91,
        "severity":       "HIGH",
    }
    body.update(overrides)
    return body


def _build(url="https://dce.eastus-1.ingest.monitor.azure.com", token="bearer-xyz",
           event_type="wrapsec.request.blocked", body=None, config=_CFG):
    return build_request(
        url=url,
        token=token,
        event_type=event_type,
        body=body if body is not None else _body(),
        config=config,
    )


# --- URI construction -------------------------------------------------

def test_uri_includes_dcr_stream_and_pinned_api_version():
    req = _build()
    assert req.url == (
        "https://dce.eastus-1.ingest.monitor.azure.com"
        "/dataCollectionRules/dcr-0a0a/streams/Custom-WrapSec_CL"
        "?api-version=2023-01-01"
    )


def test_uri_tolerates_trailing_slash_on_endpoint():
    req = _build(url="https://dce.eastus-1.ingest.monitor.azure.com/")
    assert "/dataCollectionRules/dcr-0a0a/streams/Custom-WrapSec_CL" in req.url
    assert req.url.count("//") == 1  # only the scheme's slashes


# --- Required config --------------------------------------------------

def test_missing_dcr_immutable_id_raises():
    with pytest.raises(ValueError, match="dcr_immutable_id"):
        _build(config={"stream_name": "Custom-WrapSec_CL"})


def test_missing_stream_name_raises():
    with pytest.raises(ValueError, match="stream_name"):
        _build(config={"dcr_immutable_id": "dcr-0a0a"})


def test_empty_config_raises():
    with pytest.raises(ValueError):
        _build(config=None)


# --- Body shape -------------------------------------------------------

def test_body_is_single_element_array_of_records():
    req = _build()
    assert isinstance(req, ConnectorRequest)
    assert req.method == "POST"
    assert isinstance(req.json_payload, list)
    assert len(req.json_payload) == 1


def test_record_spreads_body_with_event_type_and_time_generated():
    req = _build()
    rec = req.json_payload[0]
    assert rec["trace_id"] == "11111111-2222-3333-4444-555555555555"
    assert rec["severity"] == "HIGH"
    assert rec["primary_reason"] == "RULE_DETECTOR"
    assert rec["event_type"] == "wrapsec.request.blocked"
    assert rec["TimeGenerated"] == "2026-07-30T12:00:00Z"
    # The original timestamp column is preserved alongside TimeGenerated.
    assert rec["timestamp"] == "2026-07-30T12:00:00Z"


def test_time_generated_omitted_when_timestamp_missing():
    req = _build(body=_body(timestamp=None))
    assert "TimeGenerated" not in req.json_payload[0]


def test_body_is_not_mutated_by_build_request():
    body = _body()
    _build(body=body)
    assert "event_type" not in body
    assert "TimeGenerated" not in body


# --- Auth + headers ---------------------------------------------------

def test_authorization_is_bearer_token():
    req = _build(token="my-access-token")
    assert req.headers["Authorization"] == "Bearer my-access-token"
    assert req.headers["Content-Type"] == "application/json"


def test_client_request_id_set_from_trace_id():
    req = _build()
    assert req.headers["x-ms-client-request-id"] == "11111111-2222-3333-4444-555555555555"


def test_client_request_id_omitted_when_trace_id_missing():
    body = _body()
    del body["trace_id"]
    req = _build(body=body)
    assert "x-ms-client-request-id" not in req.headers


def test_connector_type_constant():
    assert CONNECTOR_TYPE == "sentinel_logs_ingestion"
