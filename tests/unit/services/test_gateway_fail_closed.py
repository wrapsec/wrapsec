# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Fail-closed regression tests for GatewayService.

Invariant: if any detector raises, the pipeline must return BLOCK with
risk_score 1.0 and primary_reason SYSTEM_ERROR. A single detector crash
must not smuggle a payload past the remaining layers.
"""

import pytest
from unittest.mock import patch

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


async def _assert_fail_closed(result):
    assert result.decision.decision == DecisionType.BLOCK
    assert result.decision.risk_score.value == pytest.approx(1.0)
    assert result.decision.primary_reason == "SYSTEM_ERROR"


async def test_rule_detector_exception_forces_block(svc, benign_request):
    with patch.object(
        svc._rule_detector, "detect",
        side_effect=RuntimeError("simulated rule detector crash"),
    ):
        result = await svc.process(benign_request)
    await _assert_fail_closed(result)


async def test_ml_pipeline_exception_forces_block(svc, benign_request):
    async def _raise(*_a, **_kw):
        raise RuntimeError("simulated ml pipeline crash")

    with patch.object(svc._detection_pipeline, "run", side_effect=_raise):
        result = await svc.process(benign_request)
    await _assert_fail_closed(result)


async def test_llm_detector_exception_forces_block(svc):
    """LLM detector only runs on FULL mode above trigger threshold; force it
    to run and raise."""
    request = IncomingRequest(
        input          = "please help me with this task",
        detection_mode = DetectionMode.FULL,
        execution_mode = ExecutionMode.SCAN_ONLY,
    )

    async def _raise(*_a, **_kw):
        raise RuntimeError("simulated llm detector crash")

    # Patch settings to force LLM detector to trigger even on benign input.
    with patch("services.gateway.service.get_settings") as mock_settings:
        mock_settings.return_value.llm_trigger_threshold    = 0.0
        mock_settings.return_value.block_threshold          = 0.7
        mock_settings.return_value.sanitize_threshold       = 0.4
        mock_settings.return_value.llm_model                = "test-model"
        # H2: wait_for requires a numeric timeout; MagicMock default breaks it.
        mock_settings.return_value.detector_timeout_seconds = 2.0
        with patch.object(svc._llm_detector, "detect_async", side_effect=_raise):
            result = await svc.process(request)

    await _assert_fail_closed(result)
