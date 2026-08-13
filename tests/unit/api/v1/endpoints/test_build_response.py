# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests for the scan-response Security Assessment object (v1.7.0).

The assessment is an always-present, self-contained structured verdict -- the
decision plus reasons, threats, confidence, and per-layer contributions from the
FULL layer bag (not just the five fixed keys the legacy debug block exposes).
"""

from __future__ import annotations

from api.v1.endpoints.ai import _build_response
from domain.entities.decision import GatewayDecision, LayerScores
from domain.enums import DecisionType, ThreatCategory
from domain.value_objects.risk_score import RiskScore
from domain.value_objects.trace_id import TraceId


def _decision(**over):
    tid = TraceId.generate() if hasattr(TraceId, "generate") else TraceId("t_1")
    kw = {
        "trace_id": tid,
        "decision": DecisionType.BLOCK,
        "risk_score": RiskScore(0.88),
        "threats": [ThreatCategory.JAILBREAK],
        "layer_scores": LayerScores(
            rule_score=0.88, ml_score=0.2, pii_score=0.0, transformer_jailbreak=0.91
        ),
        "primary_reason": "RULE_DETECTOR",
        "confidence": 0.9,
        "confidence_band": "high",
    }
    kw.update(over)
    return GatewayDecision(**kw)


def _resp(d, debug=False):
    return _build_response(d, debug=debug, block_threshold=0.7, sanitize_threshold=0.4)


def test_assessment_always_present_without_debug():
    r = _resp(_decision(), debug=False)
    assert "assessment" in r
    assert "debug" not in r


def test_assessment_is_self_contained_verdict():
    a = _resp(_decision())["assessment"]
    assert a["decision"]        == "BLOCK"
    assert a["risk_score"]      == 0.88
    assert a["risk_level"]      == "HIGH"
    assert a["primary_reason"]  == "RULE_DETECTOR"
    assert a["confidence"]      == 0.9
    assert a["confidence_band"] == "high"
    assert a["threats"]         == ["JAILBREAK"]


def test_layers_expose_full_bag_with_per_layer_decision():
    a = _resp(_decision())["assessment"]
    by_name = {layer["name"]: layer for layer in a["layers"]}
    # the non-fixed transformer key is present -- the legacy debug block's five
    # fixed keys would miss it
    assert "transformer_jailbreak" in by_name
    assert by_name["transformer_jailbreak"]["decision"] == "BLOCK"   # 0.91 >= 0.7
    assert by_name["rule_score"]["decision"] == "BLOCK"              # 0.88 >= 0.7
    assert by_name["ml_score"]["decision"]   == "ALLOW"             # 0.2 < 0.4


def test_debug_block_unchanged_when_requested():
    r = _resp(_decision(), debug=True)
    assert "debug" in r and "assessment" in r
    assert set(r["debug"]) >= {
        "rule_score", "ml_score", "llm_score", "pii_score", "layer_decisions"
    }


def test_assessment_present_with_empty_layers_when_no_scores():
    # detection-failure path: no layer_scores, but the verdict is still present
    a = _resp(_decision(layer_scores=None))["assessment"]
    assert a["decision"] == "BLOCK"
    assert a["layers"]   == []
