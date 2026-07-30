# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests for services.webhooks.connectors.elastic.

The connector is a customer-visible ingest contract: the _bulk URI, the
NDJSON framing (action line + source line + trailing newline, compact),
the ApiKey auth header, and the ECS field mapping are what a customer's
Elasticsearch and Elastic Security depend on. These tests pin that
contract so a casual edit fails loudly in CI.
"""

from __future__ import annotations

import json

import pytest

from services.webhooks.connectors.base import ConnectorRequest
from services.webhooks.connectors.elastic import CONNECTOR_TYPE, build_request


_CFG = {"index": "logs-wrapsec.security-default"}


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


def _build(url="https://es.example:9243", token="apikeyb64",
           event_type="wrapsec.request.blocked", body=None, config=_CFG):
    return build_request(
        url=url,
        token=token,
        event_type=event_type,
        body=body if body is not None else _body(),
        config=config,
    )


def _lines(req):
    """Split the NDJSON body into parsed (action, source) dicts."""
    raw = req.json_payload
    assert isinstance(raw, str)
    assert raw.endswith("\n")
    parts = raw.rstrip("\n").split("\n")
    assert len(parts) == 2
    return json.loads(parts[0]), json.loads(parts[1])


# --- URI + required config --------------------------------------------

def test_uri_targets_index_bulk_endpoint():
    req = _build()
    assert req.url == "https://es.example:9243/logs-wrapsec.security-default/_bulk"


def test_uri_tolerates_trailing_slash():
    req = _build(url="https://es.example:9243/")
    assert req.url == "https://es.example:9243/logs-wrapsec.security-default/_bulk"


def test_missing_index_raises():
    with pytest.raises(ValueError, match="index"):
        _build(config={})


# --- NDJSON framing ---------------------------------------------------

def test_body_is_ndjson_create_action_then_source_with_trailing_newline():
    req = _build()
    assert isinstance(req.json_payload, str)
    assert req.json_payload.endswith("\n")
    action, _source = _lines(req)
    assert action == {"create": {}}


def test_ndjson_lines_are_compact_no_embedded_newlines():
    req = _build()
    # Exactly two newlines: one after the action line, one trailing.
    assert req.json_payload.count("\n") == 2
    # Compact separators: no ", " or ": " spacing.
    assert ", " not in req.json_payload
    assert '": ' not in req.json_payload


# --- ECS mapping ------------------------------------------------------

def test_ecs_core_fields():
    _action, doc = _lines(_build())
    assert doc["@timestamp"] == "2026-07-30T12:00:00Z"
    assert doc["ecs"]["version"] == "8.11.0"
    assert doc["event"]["kind"] == "alert"
    assert doc["event"]["category"] == ["intrusion_detection"]
    assert doc["event"]["action"] == "block"
    assert doc["event"]["type"] == ["denied"]
    assert doc["event"]["dataset"] == "wrapsec.security"
    assert doc["log"]["level"] == "error"
    assert "BLOCK" in doc["message"]


def test_sanitize_maps_to_change_event_type():
    _action, doc = _lines(_build(
        event_type="wrapsec.request.sanitized",
        body=_body(decision="SANITIZE", severity="MEDIUM"),
    ))
    assert doc["event"]["action"] == "sanitize"
    assert doc["event"]["type"] == ["change"]
    assert doc["log"]["level"] == "warning"


def test_full_body_preserved_under_wrapsec_namespace():
    _action, doc = _lines(_build())
    assert doc["wrapsec"]["trace_id"] == "trace-123"
    assert doc["wrapsec"]["primary_reason"] == "RULE_DETECTOR"
    assert doc["wrapsec"]["severity"] == "HIGH"
    assert doc["wrapsec"]["event_type"] == "wrapsec.request.blocked"


def test_timestamp_omitted_when_missing():
    _action, doc = _lines(_build(body=_body(timestamp=None)))
    assert "@timestamp" not in doc


def test_log_level_omitted_for_unknown_severity():
    _action, doc = _lines(_build(body=_body(severity="WEIRD")))
    assert "log" not in doc


def test_ecs_version_override():
    _action, doc = _lines(_build(config={"index": "idx", "ecs_version": "9.0.0"}))
    assert doc["ecs"]["version"] == "9.0.0"


def test_body_is_not_mutated():
    body = _body()
    _build(body=body)
    assert "event_type" not in body
    assert "@timestamp" not in body


# --- Auth -------------------------------------------------------------

def test_apikey_auth_and_ndjson_content_type():
    req = _build(token="abc123==")
    assert req.headers["Authorization"] == "ApiKey abc123=="
    assert req.headers["Content-Type"] == "application/x-ndjson"


def test_connector_type_constant():
    assert CONNECTOR_TYPE == "elastic_ecs"
