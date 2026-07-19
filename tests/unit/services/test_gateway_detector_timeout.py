# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
H2 regression: detector timeouts force fail-closed BLOCK.

If a regex-heavy detector (rule or PII input guard) hangs on a ReDoS payload,
the gateway must abort the detector call at detector_timeout_seconds and
route through C1 fail-closed: BLOCK with primary_reason=SYSTEM_ERROR.

These tests simulate the hang by monkey-patching the detector to sleep well
past the configured timeout, then assert the gateway returns BLOCK on time.
The important measurement is that the response comes back after the timeout
- not after the full sleep - which is what proves the wait_for guard fired.
"""

import time
from unittest.mock import patch

import pytest

from domain.entities.request import IncomingRequest
from domain.enums import DecisionType, DetectionMode, ExecutionMode
from services.gateway.service import GatewayService


@pytest.fixture
def svc():
    return GatewayService()


@pytest.fixture
def benign_request():
    return IncomingRequest(
        input          = "Hello, how are you today?",
        detection_mode = DetectionMode.FAST,
        execution_mode = ExecutionMode.SCAN_ONLY,
    )


async def test_rule_detector_hang_triggers_timeout_block(svc, benign_request):
    """
    Rule detector sleeps 5s but timeout is 0.2s -> BLOCK returned in well
    under 5s. A regression that drops the wait_for wrapper would show up
    here as the test taking ~5s (or hanging entirely).
    """
    def _slow_detect(_text):
        time.sleep(5.0)
        raise AssertionError("should have been aborted by timeout")

    with patch("services.gateway.service.get_settings") as mock_settings:
        mock_settings.return_value.block_threshold          = 0.7
        mock_settings.return_value.sanitize_threshold       = 0.4
        mock_settings.return_value.llm_trigger_threshold    = 1.0  # never trigger LLM
        mock_settings.return_value.llm_model                = "test-model"
        mock_settings.return_value.detector_timeout_seconds = 0.2

        with patch.object(svc._rule_detector, "detect", side_effect=_slow_detect):
            start  = time.perf_counter()
            result = await svc.process(benign_request)
            elapsed = time.perf_counter() - start

    assert elapsed < 2.0, f"gateway took {elapsed:.2f}s - wait_for guard not firing"
    assert result.decision.decision       == DecisionType.BLOCK
    assert result.decision.risk_score.value == pytest.approx(1.0)
    assert result.decision.primary_reason == "SYSTEM_ERROR"


async def test_input_guard_hang_triggers_timeout_block(svc, benign_request):
    """
    PII input guard sleeps past the timeout -> BLOCK. This is the case that
    prompted H2: input_guard.inspect() ran synchronously on the event loop
    pre-H2, so a Presidio ReDoS would freeze all coroutines. Now it runs
    off-thread with wait_for.
    """
    def _slow_inspect(_text):
        time.sleep(5.0)
        raise AssertionError("should have been aborted by timeout")

    with patch("services.gateway.service.get_settings") as mock_settings:
        mock_settings.return_value.block_threshold          = 0.7
        mock_settings.return_value.sanitize_threshold       = 0.4
        mock_settings.return_value.llm_trigger_threshold    = 1.0
        mock_settings.return_value.llm_model                = "test-model"
        mock_settings.return_value.detector_timeout_seconds = 0.2

        with patch.object(svc._input_guard, "inspect", side_effect=_slow_inspect):
            start  = time.perf_counter()
            result = await svc.process(benign_request)
            elapsed = time.perf_counter() - start

    assert elapsed < 2.0, f"gateway took {elapsed:.2f}s - input guard wait_for not firing"
    assert result.decision.decision       == DecisionType.BLOCK
    assert result.decision.risk_score.value == pytest.approx(1.0)
    assert result.decision.primary_reason == "SYSTEM_ERROR"
