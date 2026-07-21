# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
v1.0.9 regression: toxicity guardrail is BLOCK-or-ALLOW only (Bedrock semantics).

Locks in that the PolicyEngine never emits a SANITIZE decision on the strength
of a toxicity score alone, regardless of what value is passed for the
deprecated `toxicity_sanitize_threshold` parameter.
"""

from domain.enums import DecisionType, ThreatCategory
from domain.value_objects.risk_score import RiskScore
from engine.policy.engine import PolicyEngine
from engine.policy.rules import PolicyRules


def _engine():
    return PolicyEngine(rules=PolicyRules(block_threshold=0.7, sanitize_threshold=0.4))


def test_toxicity_at_block_threshold_returns_block():
    decision = _engine().decide(
        risk_score               = RiskScore(0.0),
        threats                  = [],
        toxicity_score           = 0.8,
        toxicity_block_threshold = 0.7,
    )
    assert decision.decision == DecisionType.BLOCK


def test_toxicity_between_old_sanitize_and_block_returns_allow():
    """
    A toxicity score of 0.5 with old thresholds (sanitize=0.4, block=0.7) used
    to produce SANITIZE. v1.0.9 removes that tier - the score is below the
    block threshold, so the toxicity guardrail does not fire and the decision
    falls through to the detection tier (ALLOW here, since risk_score=0).
    """
    decision = _engine().decide(
        risk_score                  = RiskScore(0.0),
        threats                     = [],
        toxicity_score              = 0.5,
        toxicity_block_threshold    = 0.7,
        toxicity_sanitize_threshold = 0.4,  # deprecated - must not fire SANITIZE
    )
    assert decision.decision == DecisionType.ALLOW


def test_toxicity_sanitize_threshold_param_is_noop():
    """
    Passing an extreme toxicity_sanitize_threshold must not change the decision.
    Confirms the parameter is truly a no-op and not accidentally re-enabled.
    """
    baseline = _engine().decide(
        risk_score               = RiskScore(0.0),
        threats                  = [],
        toxicity_score           = 0.5,
        toxicity_block_threshold = 0.7,
    )
    with_extreme_threshold = _engine().decide(
        risk_score                  = RiskScore(0.0),
        threats                     = [],
        toxicity_score              = 0.5,
        toxicity_block_threshold    = 0.7,
        toxicity_sanitize_threshold = 0.0001,  # would previously have triggered SANITIZE
    )
    assert baseline.decision == with_extreme_threshold.decision == DecisionType.ALLOW


def test_pii_sanitize_still_works():
    """PII guardrail's SANITIZE (ANONYMIZE) tier must remain intact after v1.0.9."""
    decision = _engine().decide(
        risk_score             = RiskScore(0.0),
        threats                = [ThreatCategory.PII],
        pii_score              = 0.55,
        pii_block_threshold    = 0.7,
        pii_sanitize_threshold = 0.4,
    )
    assert decision.decision == DecisionType.SANITIZE


def test_pii_takes_priority_over_toxicity():
    """PII guardrail evaluated first - a PII SANITIZE wins over toxicity BLOCK."""
    decision = _engine().decide(
        risk_score               = RiskScore(0.0),
        threats                  = [ThreatCategory.PII, ThreatCategory.TOXICITY],
        pii_score                = 0.55,
        pii_block_threshold      = 0.7,
        pii_sanitize_threshold   = 0.4,
        toxicity_score           = 0.9,
        toxicity_block_threshold = 0.7,
    )
    # PII SANITIZE beats toxicity BLOCK because PII is evaluated first
    assert decision.decision == DecisionType.SANITIZE
