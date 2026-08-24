# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
A PolicyEngine that cannot decide must refuse, not permit.

`decide` wraps its body in `except Exception -> BLOCK`. That was recorded as
verified by inspection, which is not the same as verified: changing the fallback
from BLOCK to ALLOW left the whole unit suite green. The layer that turns a
score into a verdict is the last one before an input is forwarded, so its
failure mode is the difference between refusing a request and permitting one
nothing evaluated.
"""

from unittest.mock import patch

import pytest

from domain.enums import DecisionType
from domain.value_objects.risk_score import RiskScore
from engine.policy.engine import PolicyEngine


@pytest.fixture
def engine():
    return PolicyEngine()


def _raise(*_a, **_kw):
    raise RuntimeError("simulated policy evaluation failure")


def test_an_engine_failure_blocks(engine):
    """
    The failure is injected INSIDE the try block, at the threshold comparison
    the decision is actually made from, rather than by patching `decide` itself
    -- patching the method under test would bypass the handler being covered.
    """
    with patch.object(RiskScore, "value", property(_raise)):
        decision = engine.decide(RiskScore(0.1), [])

    assert decision.decision == DecisionType.BLOCK, (
        "a policy engine that could not evaluate the score permitted the input"
    )


def test_a_clean_score_still_allows(engine):
    """
    The other direction: a fallback that blocks unconditionally would also pass
    the test above while refusing all legitimate traffic.
    """
    decision = engine.decide(RiskScore(0.0), [])
    assert decision.decision == DecisionType.ALLOW
