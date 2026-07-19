# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Regression tests for observability.metrics label allowlists.

Metrics allowlists guard label cardinality (never let arbitrary strings into
Prometheus). But a missing valid value is invisible: the reason silently maps
to "unknown" and the by-reason counter is not incremented. That is exactly
what happened for toxicity guardrail reasons - decisions were counted at the
coarse REQUEST_TOTAL level but never appeared in BLOCKED_TOTAL / SANITIZED_TOTAL
by primary_reason, making dashboards under-report toxicity enforcement.

These tests lock in the contract that every reason string produced by
primary_reason.py is present in the metrics allowlist.
"""

from observability.metrics import _VALID_PRIMARY_REASONS


def test_toxicity_reasons_in_allowlist():
    """
    F-7 regression: TOXICITY_GUARDRAIL_BLOCK and TOXICITY_GUARDRAIL_SANITIZE
    must be in the primary_reason allowlist. Otherwise toxicity-driven blocks
    and sanitizes are dropped from BLOCKED_TOTAL / SANITIZED_TOTAL.
    """
    assert "TOXICITY_GUARDRAIL_BLOCK"    in _VALID_PRIMARY_REASONS
    assert "TOXICITY_GUARDRAIL_SANITIZE" in _VALID_PRIMARY_REASONS


def test_pii_reasons_still_in_allowlist():
    """Guard against a future edit that drops PII reasons while adding toxicity."""
    assert "PII_GUARDRAIL_BLOCK"    in _VALID_PRIMARY_REASONS
    assert "PII_GUARDRAIL_SANITIZE" in _VALID_PRIMARY_REASONS


def test_detector_reasons_still_in_allowlist():
    """Same for detector reasons."""
    assert "RULE_DETECTOR" in _VALID_PRIMARY_REASONS
    assert "ML_DETECTOR"   in _VALID_PRIMARY_REASONS
    assert "LLM_DETECTOR"  in _VALID_PRIMARY_REASONS


def test_system_and_benign_reasons_in_allowlist():
    """NO_THREAT_DETECTED and SYSTEM_ERROR are terminal reasons, must not drop."""
    assert "NO_THREAT_DETECTED" in _VALID_PRIMARY_REASONS
    assert "SYSTEM_ERROR"       in _VALID_PRIMARY_REASONS


def test_primary_reason_module_and_allowlist_agree():
    """
    Every literal reason string emitted by compute_primary_reason must be in
    the allowlist. This is the invariant that F-7 broke - primary_reason.py
    grew a new return value (TOXICITY_GUARDRAIL_*) but metrics.py wasn't updated.
    """
    import inspect
    from engine.scoring import primary_reason as pr_mod

    source = inspect.getsource(pr_mod)
    # Extract all "return \"X\"" and "return \"X_Y\"" string literals as the set
    # of reasons the module can emit. This is a coarse but effective check.
    import re
    emitted = set(re.findall(r'return\s+"([A-Z_]+)"', source))

    # Every emitted reason must be in the metrics allowlist.
    missing = emitted - set(_VALID_PRIMARY_REASONS)
    assert not missing, (
        f"primary_reason.py emits {missing} but metrics allowlist does not "
        f"list them - by-reason counters will drop these decisions"
    )
