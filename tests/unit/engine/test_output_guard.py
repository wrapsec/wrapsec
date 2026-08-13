# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Regression tests for engine.guardrails.output_guard.

OutputGuard runs against the LLM response before it is returned to the caller.
Unlike InputGuard, a broken OutputGuard can leak PII out of the system - the
consequence of the wrong decision is data exfiltration, not a false block.
These tests lock in three invariants:

  1. Empty text is a clean ALLOW - never crash, never mistake "" for a threat.
  2. Threshold ordering: score >= block_threshold  -> BLOCK
                         score >= sanitize_threshold -> SANITIZE
                         otherwise                   -> ALLOW
     If the ordering inverts, high-PII responses get returned untouched.
  3. Fail-closed: any internal exception must return decision=BLOCK with
     primary_reason=SYSTEM_ERROR. A permissive fallback here would return
     the raw LLM output whenever the guard hiccups.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from engine.guardrails.output_guard import OutputGuard, OutputGuardResult

# ── helpers ──────────────────────────────────────────────────────────────────

def _settings(block: float = 0.95, sanitize: float = 0.01):
    """Minimal settings stub - only the two thresholds the guard reads."""
    return SimpleNamespace(
        output_block_threshold    = block,
        output_sanitize_threshold = sanitize,
    )


def _detector_result(score: float, threats: list[str] | None = None):
    return SimpleNamespace(
        score   = score,
        threats = threats if threats is not None else [],
    )


# ── empty input ──────────────────────────────────────────────────────────────

def test_empty_text_is_allow_without_calling_detector():
    """
    An empty response cannot leak PII. The guard must ALLOW without invoking
    the detector - both to avoid spending CPU and to sidestep any edge case
    in the detector for empty input.
    """
    guard = OutputGuard()
    # Replace the detector with one that would fail if called - proves it wasn't.
    guard._detector = MagicMock(side_effect=AssertionError("detector must not run"))

    result = guard.inspect("")

    assert result.decision       == "ALLOW"
    assert result.primary_reason == "NO_THREAT_DETECTED"
    assert result.was_sanitized  is False
    assert result.sanitized_text is None
    assert result.pii_score      == 0.0


# ── ALLOW path ───────────────────────────────────────────────────────────────

def test_allow_when_score_below_sanitize_threshold():
    guard = OutputGuard()
    guard._detector = MagicMock()
    guard._detector.detect.return_value = _detector_result(0.001)

    with patch("engine.guardrails.output_guard.get_settings", return_value=_settings()):
        result = guard.inspect("harmless text")

    assert result.decision       == "ALLOW"
    assert result.primary_reason == "NO_THREAT_DETECTED"
    assert result.was_sanitized  is False
    assert result.sanitized_text is None
    # Confidence is inverse of pii_score for ALLOW - close to 1 when clean.
    assert result.confidence     == pytest.approx(0.999)


# ── SANITIZE path ────────────────────────────────────────────────────────────

def test_sanitize_when_score_between_thresholds():
    """
    Between sanitize and block thresholds: response is redacted and returned.
    was_sanitized must be True and redacted_types must be non-empty.
    """
    guard = OutputGuard()
    guard._detector = MagicMock()
    guard._detector.detect.return_value = _detector_result(0.5, threats=["EMAIL"])
    guard._redactor = MagicMock()
    guard._redactor.redact.return_value = ("hello <REDACTED>", ["EMAIL"])

    with patch("engine.guardrails.output_guard.get_settings", return_value=_settings()):
        result = guard.inspect("hello foo@bar.com")

    assert result.decision       == "SANITIZE"
    assert result.primary_reason == "PII_GUARDRAIL_SANITIZE"
    assert result.was_sanitized  is True
    assert result.sanitized_text == "hello <REDACTED>"
    assert result.redacted_types == ["EMAIL"]
    assert result.threats        == ["EMAIL"]


# ── BLOCK path ───────────────────────────────────────────────────────────────

def test_block_when_score_at_or_above_block_threshold():
    """
    Severe PII: score >= block threshold. Response is NOT redacted and NOT
    returned - the LLM output must not reach the client.
    """
    guard = OutputGuard()
    guard._detector = MagicMock()
    guard._detector.detect.return_value = _detector_result(0.99, threats=["SSN"])
    guard._redactor = MagicMock(side_effect=AssertionError("redactor must not run on BLOCK"))

    with patch("engine.guardrails.output_guard.get_settings", return_value=_settings()):
        result = guard.inspect("ssn: 123-45-6789")

    assert result.decision       == "BLOCK"
    assert result.primary_reason == "PII_GUARDRAIL_BLOCK"
    assert result.sanitized_text is None
    assert result.was_sanitized  is False
    assert result.threats        == ["SSN"]


def test_block_at_exact_threshold_boundary():
    """
    Boundary check: score == block_threshold must BLOCK, not SANITIZE.
    Off-by-one here means severe PII patterns get returned redacted rather
    than withheld entirely.
    """
    guard = OutputGuard()
    guard._detector = MagicMock()
    guard._detector.detect.return_value = _detector_result(0.95, threats=["SSN"])

    with patch("engine.guardrails.output_guard.get_settings", return_value=_settings(block=0.95)):
        result = guard.inspect("some text")

    assert result.decision == "BLOCK"


# ── threshold ordering ──────────────────────────────────────────────────────

def test_block_takes_precedence_over_sanitize():
    """
    If block and sanitize thresholds are both crossed, decision must be BLOCK.
    Guards against a code reorder that would let severe PII be redacted-and-
    returned instead of withheld.
    """
    guard = OutputGuard()
    guard._detector = MagicMock()
    guard._detector.detect.return_value = _detector_result(0.99)
    guard._redactor = MagicMock(side_effect=AssertionError("redactor must not run"))

    with patch(
        "engine.guardrails.output_guard.get_settings",
        return_value=_settings(block=0.95, sanitize=0.01),
    ):
        result = guard.inspect("some text")

    assert result.decision == "BLOCK"


# ── fail-closed ──────────────────────────────────────────────────────────────

def test_fail_closed_when_detector_raises():
    """
    CRITICAL: If the PII detector throws (dependency broken, out-of-memory,
    torch issue, etc.), the guard must BLOCK the response - NEVER return
    the raw LLM output. This is the defining behaviour of OutputGuard:
    failure to evaluate == the response cannot be trusted.
    """
    guard = OutputGuard()
    guard._detector = MagicMock()
    guard._detector.detect.side_effect = RuntimeError("presidio down")

    with patch("engine.guardrails.output_guard.get_settings", return_value=_settings()):
        result = guard.inspect("any llm response")

    assert result.decision       == "BLOCK"
    assert result.primary_reason == "SYSTEM_ERROR"
    assert result.sanitized_text is None
    assert result.pii_score      == 0.0
    assert result.confidence     == 0.0


def test_fail_closed_when_settings_raises():
    """
    Fail-closed also applies to config errors. If get_settings() raises
    (e.g. invalid env var during a hot reload), the response must not be
    returned unredacted.
    """
    guard = OutputGuard()
    guard._detector = MagicMock()

    with patch(
        "engine.guardrails.output_guard.get_settings",
        side_effect=RuntimeError("settings blew up"),
    ):
        result = guard.inspect("any llm response")

    assert result.decision       == "BLOCK"
    assert result.primary_reason == "SYSTEM_ERROR"


def test_fail_closed_when_redactor_raises_on_sanitize_path():
    """
    Score falls into SANITIZE range but the redactor itself fails. The guard
    must still BLOCK - returning the raw text would leak the PII that
    triggered SANITIZE in the first place.
    """
    guard = OutputGuard()
    guard._detector = MagicMock()
    guard._detector.detect.return_value = _detector_result(0.5, threats=["EMAIL"])
    guard._redactor = MagicMock()
    guard._redactor.redact.side_effect = RuntimeError("presidio anonymizer failed")

    with patch("engine.guardrails.output_guard.get_settings", return_value=_settings()):
        result = guard.inspect("hello foo@bar.com")

    assert result.decision       == "BLOCK"
    assert result.primary_reason == "SYSTEM_ERROR"
    assert result.sanitized_text is None


# ── result shape ────────────────────────────────────────────────────────────

def test_result_is_output_guard_result_instance():
    """
    The gateway consumes OutputGuardResult by attribute access. Returning a
    dict or None would AttributeError deep in the proxy path.
    """
    guard = OutputGuard()
    guard._detector = MagicMock()
    guard._detector.detect.return_value = _detector_result(0.0)

    with patch("engine.guardrails.output_guard.get_settings", return_value=_settings()):
        result = guard.inspect("hello")

    assert isinstance(result, OutputGuardResult)
