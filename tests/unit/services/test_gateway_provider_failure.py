# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
A provider failure in proxy mode must be reported as a failed execution.

The gateway used to answer an unreachable provider with the literal string
"[LLM unavailable]" in the `output` field, and an empty completion with
"[LLM returned empty response]". Both arrived as a successful scan carrying
model content: `llm_invoked` was true, the decision was whatever the scan
found, and nothing distinguished either from a real reply. An integrating
application renders that to its user as the model's answer.

Two properties are covered here, and they pull in opposite directions:

  - There must be no output. A placeholder is worse than nothing, because
    nothing is unambiguous.
  - The scan verdict must SURVIVE. The detectors ran and their answer is real
    evidence; collapsing a provider outage into a BLOCK would report an
    infrastructure failure as an attack, and would poison the audit trail that
    incident review depends on.
"""

from unittest.mock import patch

import pytest

from domain.entities.request import IncomingRequest
from domain.enums import DecisionType, DetectionMode, ExecutionMode
from services.gateway.service import GatewayService


@pytest.fixture
def svc():
    return GatewayService()


def _proxy_request():
    """Benign text, so the input scan cannot BLOCK and skip step 8 entirely."""
    return IncomingRequest(
        input          = "Please summarise the attached quarterly report.",
        detection_mode = DetectionMode.FAST,
        execution_mode = ExecutionMode.PROXY,
        model          = "test-model",
    )


class _Completion:
    def __init__(self, content):
        self.content = content


async def test_an_unreachable_provider_is_reported_as_a_failure(svc):
    called = {"yes": False}

    async def _raise(*_a, **_kw):
        called["yes"] = True
        raise RuntimeError("simulated provider outage")

    with patch("clients.get_llm_client") as _client:
        _client.return_value.complete = _raise
        result = await svc.process(_proxy_request())

    assert called["yes"], (
        "the provider was never called, so nothing about provider failure is "
        "under test here"
    )
    assert result.provider_error == "provider_unavailable"
    assert result.decision.output is None, (
        "a placeholder was returned in place of the model's answer"
    )


async def test_an_empty_completion_is_reported_as_a_failure(svc):
    async def _empty(*_a, **_kw):
        return _Completion("")

    with patch("clients.get_llm_client") as _client:
        _client.return_value.complete = _empty
        result = await svc.process(_proxy_request())

    assert result.provider_error == "provider_empty_response"
    assert result.decision.output is None


async def test_the_scan_verdict_survives_a_provider_failure(svc):
    """
    The detectors ran. Their verdict is not invalidated by what happened after
    them, and must not be rewritten into the fail-closed BLOCK that a DETECTION
    failure produces -- the two are different events and the audit row has to
    tell them apart.
    """
    async def _raise(*_a, **_kw):
        raise RuntimeError("simulated provider outage")

    with patch("clients.get_llm_client") as _client:
        _client.return_value.complete = _raise
        result = await svc.process(_proxy_request())

    assert result.decision.decision != DecisionType.BLOCK
    assert result.decision.primary_reason != "SYSTEM_ERROR", (
        "a provider outage was reported as a detection failure"
    )
    assert result.decision.llm_invoked is True, (
        "the call was attempted; recording otherwise hides the outage from "
        "incident review"
    )


async def test_a_successful_completion_still_returns_its_content(svc):
    """The other direction: the failure path must not have swallowed success."""
    async def _ok(*_a, **_kw):
        return _Completion("The quarterly report shows steady growth.")

    with patch("clients.get_llm_client") as _client:
        _client.return_value.complete = _ok
        result = await svc.process(_proxy_request())

    assert result.provider_error is None
    assert result.decision.output == "The quarterly report shows steady growth."


async def test_a_scan_only_request_never_carries_a_provider_error(svc):
    result = await svc.process(IncomingRequest(
        input          = "Please summarise the attached quarterly report.",
        detection_mode = DetectionMode.FAST,
        execution_mode = ExecutionMode.SCAN_ONLY,
    ))
    assert result.provider_error is None
    assert result.decision.llm_invoked is False


def test_no_placeholder_string_is_returned_as_model_content():
    """
    A source-level guard. The defect was not that the strings existed, but that
    they were returned through the same field as a real completion, where no
    caller could tell them apart. Reintroducing either one restores that.
    """
    from pathlib import Path

    source = Path("services/gateway/service.py").read_text()
    for placeholder in ("[LLM unavailable]", "[LLM returned empty response]"):
        assert f'return "{placeholder}"' not in source, (
            f"{placeholder} is being returned as model content again"
        )
