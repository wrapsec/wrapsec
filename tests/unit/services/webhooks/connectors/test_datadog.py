# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests for services.webhooks.connectors.datadog.

The connector is a customer-visible ingest contract: the array body,
the DD-API-KEY header, the reserved-field set (message/ddsource/service/
ddtags/status), and the intake path are what a customer's Datadog
pipeline and facets depend on. These tests pin that contract so a
casual edit fails loudly in CI.
"""

from __future__ import annotations

import pytest

from services.webhooks.connectors.base import ConnectorRequest
from services.webhooks.connectors.datadog import CONNECTOR_TYPE, build_request


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


# --- Body shape -------------------------------------------------------

def test_body_is_a_single_element_array_of_log_objects():
    req = build_request(
        url="https://http-intake.logs.datadoghq.com",
        token="dd-key",
        event_type="wrapsec.request.blocked",
        body=_body(),
    )
    assert isinstance(req, ConnectorRequest)
    assert req.method == "POST"
    assert isinstance(req.json_payload, list)
    assert len(req.json_payload) == 1


def test_log_spreads_audit_body_as_attributes():
    req = build_request(
        url="https://http-intake.logs.datadoghq.com",
        token="dd-key",
        event_type="wrapsec.request.blocked",
        body=_body(),
    )
    log = req.json_payload[0]
    assert log["trace_id"] == "trace-123"
    assert log["severity"] == "HIGH"
    assert log["primary_reason"] == "RULE_DETECTOR"
    # The body timestamp is preserved for Datadog's default date remapper.
    assert log["timestamp"] == "2026-07-30T12:00:00Z"
    assert log["event_type"] == "wrapsec.request.blocked"


def test_body_is_not_mutated_by_build_request():
    body = _body()
    build_request(
        url="https://http-intake.logs.datadoghq.com",
        token="dd-key",
        event_type="wrapsec.request.blocked",
        body=body,
    )
    assert "event_type" not in body
    assert "message" not in body
    assert "ddsource" not in body


# --- Reserved fields --------------------------------------------------

def test_reserved_fields_default_to_wrapsec():
    req = build_request(
        url="https://http-intake.logs.datadoghq.com",
        token="dd-key",
        event_type="wrapsec.request.blocked",
        body=_body(),
    )
    log = req.json_payload[0]
    assert log["ddsource"] == "wrapsec"
    assert log["service"] == "wrapsec"


def test_message_summarizes_decision_severity_reason_trace():
    req = build_request(
        url="https://http-intake.logs.datadoghq.com",
        token="dd-key",
        event_type="wrapsec.request.blocked",
        body=_body(),
    )
    msg = req.json_payload[0]["message"]
    assert "BLOCK" in msg
    assert "severity=HIGH" in msg
    assert "reason=RULE_DETECTOR" in msg
    assert "trace=trace-123" in msg


def test_ddtags_carries_event_decision_and_severity():
    req = build_request(
        url="https://http-intake.logs.datadoghq.com",
        token="dd-key",
        event_type="wrapsec.request.sanitized",
        body=_body(decision="SANITIZE", severity="MEDIUM"),
    )
    tags = req.json_payload[0]["ddtags"].split(",")
    assert "event_type:wrapsec.request.sanitized" in tags
    assert "decision:SANITIZE" in tags
    assert "severity:MEDIUM" in tags


# --- Severity -> Datadog status --------------------------------------

@pytest.mark.parametrize(
    "severity, status",
    [
        ("CRITICAL", "critical"),
        ("HIGH",     "error"),
        ("MEDIUM",   "warning"),
        ("LOW",      "info"),
    ],
)
def test_severity_maps_to_datadog_status(severity, status):
    req = build_request(
        url="https://http-intake.logs.datadoghq.com",
        token="dd-key",
        event_type="wrapsec.request.blocked",
        body=_body(severity=severity),
    )
    assert req.json_payload[0]["status"] == status


def test_status_omitted_for_unknown_severity():
    req = build_request(
        url="https://http-intake.logs.datadoghq.com",
        token="dd-key",
        event_type="wrapsec.request.blocked",
        body=_body(severity="WEIRD"),
    )
    assert "status" not in req.json_payload[0]


# --- Auth + content headers -------------------------------------------

def test_dd_api_key_header_and_content_type():
    req = build_request(
        url="https://http-intake.logs.datadoghq.com",
        token="my-dd-api-key",
        event_type="wrapsec.request.blocked",
        body=_body(),
    )
    assert req.headers["DD-API-KEY"] == "my-dd-api-key"
    assert req.headers["Content-Type"] == "application/json"


# --- Intake path resolution -------------------------------------------

@pytest.mark.parametrize(
    "given, expected",
    [
        ("https://http-intake.logs.datadoghq.com",
         "https://http-intake.logs.datadoghq.com/api/v2/logs"),
        ("https://http-intake.logs.datadoghq.com/",
         "https://http-intake.logs.datadoghq.com/api/v2/logs"),
        ("https://http-intake.logs.datadoghq.eu/api/v2/logs",
         "https://http-intake.logs.datadoghq.eu/api/v2/logs"),
    ],
)
def test_url_resolves_to_intake_path(given, expected):
    req = build_request(
        url=given,
        token="dd-key",
        event_type="wrapsec.request.blocked",
        body=_body(),
    )
    assert req.url == expected


# --- Config overrides -------------------------------------------------

def test_config_overrides_service_source_hostname_and_extra_tags():
    req = build_request(
        url="https://http-intake.logs.datadoghq.com",
        token="dd-key",
        event_type="wrapsec.request.blocked",
        body=_body(),
        config={
            "service":  "gateway",
            "ddsource": "wrapsec-prod",
            "hostname": "gw-1",
            "tags":     ["env:prod", "team:secops"],
        },
    )
    log = req.json_payload[0]
    assert log["service"] == "gateway"
    assert log["ddsource"] == "wrapsec-prod"
    assert log["hostname"] == "gw-1"
    tags = log["ddtags"].split(",")
    assert "env:prod" in tags
    assert "team:secops" in tags


def test_hostname_absent_when_not_configured():
    req = build_request(
        url="https://http-intake.logs.datadoghq.com",
        token="dd-key",
        event_type="wrapsec.request.blocked",
        body=_body(),
    )
    assert "hostname" not in req.json_payload[0]


def test_connector_type_constant():
    assert CONNECTOR_TYPE == "datadog_logs"
