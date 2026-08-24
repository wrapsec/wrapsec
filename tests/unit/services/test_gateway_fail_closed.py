# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Fail-closed regression tests for GatewayService.

Invariant: if any detector raises, the pipeline must return BLOCK with
risk_score 1.0 and primary_reason SYSTEM_ERROR. A single detector crash
must not smuggle a payload past the remaining layers.
"""

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


async def test_pii_detector_exception_forces_block(svc):
    """
    The PII guardrail is the one layer that both scores AND rewrites, and it
    swallows its own exceptions -- so a failure came back as a zero-score
    result indistinguishable from clean text. Scored on content alone, a
    prompt carrying personal data then came out ALLOW and was forwarded to
    the provider unredacted: the guardrail failing turned SANITIZE into ALLOW.

    Text that a guardrail could not inspect is refused, not sent.
    """
    request = IncomingRequest(
        input          = "Please email the report to jane.doe@example.com when ready.",
        detection_mode = DetectionMode.FAST,
        execution_mode = ExecutionMode.SCAN_ONLY,
    )

    with patch.object(
        svc._input_guard._pii_detector, "detect",
        side_effect=RuntimeError("simulated pii detector crash"),
    ):
        result = await svc.process(request)

    await _assert_fail_closed(result)


async def test_pii_redactor_exception_forces_block(svc):
    """
    The redactor re-raises rather than return text it could not redact, which
    is only fail-closed if someone acts on it. Its caller caught the re-raise
    and reported clean, so the deliberate refusal became an ALLOW carrying the
    unredacted PII.
    """
    request = IncomingRequest(
        input          = "Please email the report to jane.doe@example.com when ready.",
        detection_mode = DetectionMode.FAST,
        execution_mode = ExecutionMode.SCAN_ONLY,
    )

    with patch.object(
        svc._input_guard._pii_redactor, "redact",
        side_effect=RuntimeError("simulated redactor crash"),
    ):
        result = await svc.process(request)

    await _assert_fail_closed(result)
    assert result.decision.sanitized_input is None, (
        "a failed redaction must never surface text as sanitized"
    )


async def test_guardrail_failure_survives_the_toxicity_step(svc):
    """
    inspect_toxicity REBUILDS the result rather than mutating it, so a field it
    forgets to carry is reset to its default. The failure is recorded at step 1
    and the toxicity step runs at 3.5 -- if the flag does not survive that
    rebuild, a guardrail failure silently becomes a success.
    """
    from engine.detection.base import DetectionResult
    from engine.guardrails.input_guard import InputGuard, InputGuardResult

    failed = InputGuardResult(
        text            = "anything",
        sanitized_text  = None,
        pii_result      = DetectionResult.clean("input_guard"),
        toxicity_result = DetectionResult.clean("toxicity_detector"),
        redacted_types  = [],
        was_sanitized   = False,
        failed          = True,
    )

    carried = InputGuard().inspect_toxicity(failed, DetectionResult.clean("ml_detector"))

    assert carried.failed is True


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
