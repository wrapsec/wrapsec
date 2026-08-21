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
    F-7 regression + v1.0.9: TOXICITY_GUARDRAIL_BLOCK must be in the primary_reason
    allowlist. Otherwise toxicity-driven blocks are dropped from BLOCKED_TOTAL.
    The TOXICITY_GUARDRAIL_SANITIZE tier was removed in v1.0.9 (Bedrock-style
    BLOCK-or-ALLOW semantics) and must NOT appear in the allowlist.
    """
    assert "TOXICITY_GUARDRAIL_BLOCK" in _VALID_PRIMARY_REASONS
    assert "TOXICITY_GUARDRAIL_SANITIZE" not in _VALID_PRIMARY_REASONS


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


def test_system_error_is_in_the_allowlist():
    """
    A fail-closed block -- a detector that crashed or ran out of time -- carries
    SYSTEM_ERROR. Drop it from the allowlist and those blocks do not merely get
    mislabelled: BLOCKED_TOTAL is only incremented when the reason validates, so
    they disappear from the by-reason counter entirely while still appearing as
    BLOCK in REQUEST_TOTAL.

    That is the one distinction operations depends on under load. Traffic
    refused because detection could not keep up looks exactly like traffic
    refused for its content, and the metrics are the only place the two can be
    told apart.
    """
    assert "SYSTEM_ERROR" in _VALID_PRIMARY_REASONS


class TestFailClosedIsDistinguishableInMetrics:
    """
    Being in the allowlist is necessary but not sufficient: it says the label is
    permitted, not that it is emitted. These read the counters back.
    """

    @staticmethod
    def _blocked(reason, mode="scan_only"):
        from prometheus_client import REGISTRY
        return REGISTRY.get_sample_value(
            "wrapsec_blocked_total",
            {"primary_reason": reason, "execution_mode": mode},
        ) or 0.0

    @staticmethod
    def _system_errors(mode="scan_only"):
        from prometheus_client import REGISTRY
        return REGISTRY.get_sample_value(
            "wrapsec_system_errors_total", {"execution_mode": mode},
        ) or 0.0

    def test_a_fail_closed_block_is_counted_under_its_own_reason(self):
        from observability.metrics import record_request

        before_reason = self._blocked("SYSTEM_ERROR")
        before_health = self._system_errors()

        record_request(
            decision="BLOCK", detection_mode="fast", execution_mode="scan_only",
            latency_ms=1.0, threats=[], primary_reason="SYSTEM_ERROR",
        )

        assert self._blocked("SYSTEM_ERROR") == before_reason + 1
        # and on the dedicated ops-health counter, which is what an alert watches
        assert self._system_errors() == before_health + 1

    def test_a_content_block_is_not_counted_as_a_system_error(self):
        """The other direction: a real detection must not inflate the health signal."""
        from observability.metrics import record_request

        before_health = self._system_errors()
        before_reason = self._blocked("RULE_DETECTOR")

        record_request(
            decision="BLOCK", detection_mode="fast", execution_mode="scan_only",
            latency_ms=1.0, threats=[], primary_reason="RULE_DETECTOR",
        )

        assert self._blocked("RULE_DETECTOR") == before_reason + 1
        assert self._system_errors() == before_health

    def test_the_two_do_not_share_a_bucket(self):
        """
        The property that matters for the Scan-All load question: given a mix,
        the by-reason counter can say how many were refused because detection
        failed rather than because anything was found.
        """
        from observability.metrics import record_request

        before_fail    = self._blocked("SYSTEM_ERROR")
        before_content = self._blocked("RULE_DETECTOR")

        for reason in ("SYSTEM_ERROR", "SYSTEM_ERROR", "RULE_DETECTOR"):
            record_request(
                decision="BLOCK", detection_mode="fast", execution_mode="scan_only",
                latency_ms=1.0, threats=[], primary_reason=reason,
            )

        assert self._blocked("SYSTEM_ERROR")  == before_fail + 2
        assert self._blocked("RULE_DETECTOR") == before_content + 1
