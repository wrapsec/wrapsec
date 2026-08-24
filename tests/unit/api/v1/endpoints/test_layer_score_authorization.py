# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Per-layer scores are withheld from callers without `settings:read`.

A per-layer score is a TARGETING signal: it says how much each detector
contributed, so an author reworking a payload learns which layer to work
against and how far it has to move. The `debug` block carrying the same numbers
is admin-gated and separately rate-limited at 10/min for exactly that reason,
while `assessment.layers` carried them to every caller with neither control.

What this is NOT, and the tests say so where it matters:

  * Not threshold confidentiality. `risk_score` and `decision` go to every
    caller, and a binary search over them recovers a threshold to six decimal
    places in roughly two dozen probes, reading no layer field. Measured.
  * Not the end of targeting. The CLASSIFICATION stays, deliberately, so a
    caller can still see which layer sits in which bucket. A float becomes
    three states.

Stated plainly because a control defended with a false claim is one somebody
disproves and deletes.
"""

import pytest

from api.v1.endpoints.ai import _build_response, restrict_layer_scores
from domain.entities.decision import GatewayDecision, LayerScores
from domain.enums import DecisionType, DetectionMode, ExecutionMode
from domain.value_objects.risk_score import RiskScore
from domain.value_objects.trace_id import TraceId

BT, ST = 0.70, 0.40


def _body(rule=0.85, ml=0.10, llm=0.0, final=0.85):
    decision = GatewayDecision(
        trace_id       = TraceId.generate(),
        decision       = DecisionType.BLOCK if final >= BT else DecisionType.ALLOW,
        risk_score     = RiskScore(final),
        threats        = [],
        layer_scores   = LayerScores(rule_score=rule, ml_score=ml, llm_score=llm,
                                     pii_score=0.0, toxicity_score=0.0),
        llm_invoked    = False,
        detection_mode = DetectionMode.FAST,
        execution_mode = ExecutionMode.SCAN_ONLY,
        latency_ms     = 1.0,
        primary_reason = "RULE_DETECTOR",
        confidence     = 0.9,
        confidence_band= "HIGH",
    )
    return _build_response(decision, block_threshold=BT, sanitize_threshold=ST)


def _scores(body: dict) -> list:
    return [layer.get("score") for layer in body["assessment"]["layers"]]


# ── the restriction itself ───────────────────────────────────────────────────

def test_authorized_caller_receives_layer_scores():
    body = _body()
    assert all(s is not None for s in _scores(body))


@pytest.mark.parametrize("caller", ["trial key", "VIEWER"])
def test_unauthorized_caller_receives_no_numeric_layer_scores(caller):
    """
    Trial keys and VIEWER resolve the same way: neither holds `settings:read`.
    VIEWER is treated identically to a trial key deliberately -- nothing in the
    implementation distinguishes them for this data, and inventing a difference
    would be a second rule to keep in sync.
    """
    restricted = restrict_layer_scores(_body())
    assert _scores(restricted) == [None] * len(restricted["assessment"]["layers"]), (
        f"{caller} received per-layer scores"
    )
    for layer in restricted["assessment"]["layers"]:
        assert "score" not in layer


def test_everything_except_the_score_survives_the_restriction():
    """
    The assessment stays present and usable. Removing the object, or its
    classification, would break agents and the MCP tool for a signal this was
    never about.
    """
    full, restricted = _body(), restrict_layer_scores(_body())

    assert restricted["decision"]   == full["decision"]
    assert restricted["risk_score"] == full["risk_score"]
    assert restricted["threats"]    == full["threats"]

    a_full, a_res = full["assessment"], restricted["assessment"]
    assert a_res["risk_score"]      == a_full["risk_score"]
    assert a_res["primary_reason"]  == a_full["primary_reason"]
    assert a_res["confidence"]      == a_full["confidence"]
    assert a_res["threats"]         == a_full["threats"]
    assert len(a_res["layers"])     == len(a_full["layers"])
    for before, after in zip(a_full["layers"], a_res["layers"]):
        assert after["name"]     == before["name"]
        assert after["decision"] == before["decision"], "classification is preserved"


def test_the_restriction_does_not_mutate_its_input():
    """
    One call site holds a CACHED body that later requests read again. Mutating
    it would strip scores from the shared entry, so the first unauthorized
    caller would silently restrict every authorized one after it.
    """
    original = _body()
    restrict_layer_scores(original)
    assert all(s is not None for s in _scores(original))


def test_restriction_is_safe_on_a_body_without_an_assessment():
    assert restrict_layer_scores({"decision": "ALLOW"}) == {"decision": "ALLOW"}
    assert restrict_layer_scores({"assessment": None})["assessment"] is None


# ── what remains, stated honestly ────────────────────────────────────────────

def test_the_firing_layer_is_still_identifiable_after_the_restriction():
    """
    Not a defect -- the classification is preserved on purpose. Pinned so the
    control is not later described as something it is not.
    """
    rule_fired = restrict_layer_scores(_body(rule=0.85, ml=0.10))
    ml_fired   = restrict_layer_scores(_body(rule=0.10, ml=0.85, final=0.85))

    def cls(body):
        return {l["name"]: l["decision"] for l in body["assessment"]["layers"]
                if l["name"] in ("rule_score", "ml_score")}

    assert cls(rule_fired) != cls(ml_fired), (
        "which layer fired is still visible -- documented, not claimed otherwise"
    )


def test_risk_score_remains_a_threshold_oracle_for_every_caller():
    """
    The reason the docstring refuses the threshold-confidentiality claim.
    Recovers the block threshold reading only fields every caller gets.
    """
    lo, hi = 0.0, 1.0
    for _ in range(24):
        mid = (lo + hi) / 2
        body = restrict_layer_scores(_body(rule=mid, ml=0.0, final=mid))
        if body["decision"] == DecisionType.BLOCK.value:
            hi = mid
        else:
            lo = mid
    assert abs(hi - BT) < 1e-4, f"recovered {hi}, expected about {BT}"


# ── the debug block is unchanged ─────────────────────────────────────────────

def test_debug_block_still_carries_scores_and_stays_opt_in():
    """
    It remains admin-gated at the handler and rate-limited separately. This
    change must not have quietly become its replacement.
    """
    assert "debug" not in _body()

    with_debug = _build_response(
        _decision_for_debug(), debug=True,
        block_threshold=BT, sanitize_threshold=ST,
    )
    assert with_debug["debug"]["rule_score"] == 0.85
    assert with_debug["debug"]["layer_decisions"]["rule"] == DecisionType.BLOCK.value


def _decision_for_debug():
    return GatewayDecision(
        trace_id       = TraceId.generate(),
        decision       = DecisionType.BLOCK,
        risk_score     = RiskScore(0.85),
        threats        = [],
        layer_scores   = LayerScores(rule_score=0.85, ml_score=0.10, llm_score=0.0,
                                     pii_score=0.0, toxicity_score=0.0),
        llm_invoked    = False,
        detection_mode = DetectionMode.FAST,
        execution_mode = ExecutionMode.SCAN_ONLY,
        latency_ms     = 1.0,
        primary_reason = "RULE_DETECTOR",
        confidence     = 0.9,
        confidence_band= "HIGH",
    )
