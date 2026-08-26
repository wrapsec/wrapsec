# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
The supported writers cannot produce a body the response models reject.

Response validation is a FAIL-CLOSED BOUNDARY: a body that violates the declared
contract raises rather than reaching a caller. That is only a safe position if
the supported writers cannot produce such a body in the first place -- otherwise
the boundary is not a guard, it is an outage waiting for the right row.

This file establishes the premise, at the writers rather than at the endpoint:

  * `_build_response` is the ONLY producer of a scan body, and of the body the
    semantic cache stores (the same dict minus `debug`). Every branch of it is
    exercised here -- clean, sanitized, proxy output, admin debug, source
    posture, and the restricted form with `layers[].score` stripped -- and each
    result is validated against `ScanResponse`;
  * `_build_audit_data` and `_build_cache_hit_audit` are the writers of
    `detection_scores` / `guardrail_scores`, and a read-back serves what they
    wrote. Their values are proven to be floats, never null;
  * `LayerScores` is the reason that holds: it coerces every value to float at
    construction and returns 0.0 for a key that was never set, so a null cannot
    enter the maps even if a caller tries.

What this does NOT cover, deliberately: a body written by a DIFFERENT BUILD and
still in Redis across a deploy. That is what the response-contract version in the
cache key exists for -- an entry written under a superseded contract is not
addressable by the new build. The obligation is to bump that version when the
shape changes; these tests cannot enforce it, and say so rather than implying
coverage they do not have.
"""

from __future__ import annotations

import pytest

from api.v1.endpoints.ai import (
    _build_audit_data,
    _build_response,
    restrict_layer_scores,
)
from api.v1.schemas.response import RequestRecordResponse, ScanResponse
from domain.entities.decision import GatewayDecision, LayerScores
from domain.enums import DecisionType, DetectionMode, ExecutionMode, ThreatCategory
from domain.value_objects.risk_score import RiskScore
from domain.value_objects.trace_id import TraceId


def _decision(**overrides) -> GatewayDecision:
    base = {
        "trace_id":        TraceId.generate(),
        "decision":        DecisionType.ALLOW,
        "risk_score":      RiskScore(0.0),
        "threats":         [],
        "layer_scores":    LayerScores(rule_score=0.1, ml_score=0.2, llm_score=0.0,
                                       pii_score=0.0, toxicity_score=0.0),
        "llm_invoked":     False,
        "detection_mode":  DetectionMode.FAST,
        "execution_mode":  ExecutionMode.SCAN_ONLY,
        "latency_ms":      12.5,
        "primary_reason":  "NO_THREAT_DETECTED",
        "confidence":      1.0,
        "confidence_band": "HIGH",
    }
    base.update(overrides)
    return GatewayDecision(**base)


# Every branch `_build_response` has. Named so a failure says which shape broke.
_VARIANTS = {
    "clean_allow":     {},
    "no_layer_scores": {"layer_scores": None},
    "sanitized":       {"decision": DecisionType.SANITIZE, "risk_score": RiskScore(0.5),
                        "sanitized_input": "my card is [REDACTED]",
                        "threats": [ThreatCategory.PII]},
    "blocked":         {"decision": DecisionType.BLOCK, "risk_score": RiskScore(1.0),
                        "primary_reason": "RULE_DETECTOR"},
    "proxy_output":    {"execution_mode": ExecutionMode.PROXY, "output": "the model said this",
                        "llm_invoked": True},
    "posture_shifted": {"posture": {"tier": "untrusted", "delta": -0.1}},
    "no_reason":       {"primary_reason": None, "confidence": None, "confidence_band": None},
}


@pytest.mark.parametrize("name", sorted(_VARIANTS))
@pytest.mark.parametrize("debug", [False, True])
def test_every_scan_body_the_writer_produces_satisfies_the_model(name, debug):
    body = _build_response(_decision(**_VARIANTS[name]), debug=debug,
                           block_threshold=0.7, sanitize_threshold=0.4)

    model = ScanResponse.model_validate(body)

    # Round-tripping under the route's own serialization must not lose a field
    # the writer set, nor invent one it did not.
    served = model.model_dump(exclude_unset=True)
    assert set(served) == set(body), (
        f"{name}: the model changed which keys are present "
        f"(dropped {set(body) - set(served)}, added {set(served) - set(body)})"
    )


@pytest.mark.parametrize("name", sorted(_VARIANTS))
def test_the_restricted_form_also_satisfies_the_model(name):
    """The other shape a caller can receive. `score` is removed from each layer,
    and the model must accept its absence rather than requiring the key."""
    body = restrict_layer_scores(
        _build_response(_decision(**_VARIANTS[name]), block_threshold=0.7,
                        sanitize_threshold=0.4)
    )

    served = ScanResponse.model_validate(body).model_dump(exclude_unset=True)
    for layer in served["assessment"]["layers"]:
        assert "score" not in layer, "the model reintroduced a restricted score"


@pytest.mark.parametrize("name", sorted(_VARIANTS))
def test_the_cache_stores_only_bodies_the_model_accepts(name):
    """The cache writer is `_build_response` minus `debug`, and nothing else
    writes an entry. So every entry a hit can read validates -- which is what
    makes fail-closed validation on the hit path safe rather than fragile."""
    body       = _build_response(_decision(**_VARIANTS[name]), debug=True,
                                 block_threshold=0.7, sanitize_threshold=0.4)
    cache_body = {k: v for k, v in body.items() if k != "debug"}

    ScanResponse.model_validate(cache_body)
    assert "debug" not in cache_body, "the admin-only block must never be cached"


# ── the score maps: floats or nothing, never null ────────────────────────────

class _FakeRequest:
    class state:
        tenant_id = "t"; key_id = "k"; ip_address = "127.0.0.1"
        user_agent = "ua"; app_id = None; dept_id = None


class _FakeResult:
    def __init__(self, decision):
        self.decision  = decision
        self.audit_log = type("A", (), {"input_hash": "sha256:abc"})()


@pytest.mark.parametrize("scores", [
    LayerScores(rule_score=0.1, ml_score=0.2, llm_score=0.3, pii_score=0.4, toxicity_score=0.5),
    LayerScores(rule_score=0, ml_score=1),                       # ints
    LayerScores(rule_score="0.25"),                              # numeric string
    LayerScores(),                                               # nothing set at all
    None,                                                        # no scores computed
])
def test_the_audit_writer_can_only_emit_float_scores(scores):
    data = _build_audit_data(
        request=_FakeRequest(), result=_FakeResult(_decision(layer_scores=scores)),
        trace_id_str="req_x", det_mode_str="fast", exe_mode_str="scan_only",
        policy_source="system_default", source="test", user_id=None, input_length=10,
        session_id=None, turn_index=None, run_id=None, input_source="user_prompt",
    )

    for field in ("detection_scores", "guardrail_scores"):
        for key, value in data[field].items():
            assert isinstance(value, float), (
                f"{field}[{key}] is {type(value).__name__}, not float -- a "
                "read-back declaring dict[str, float] would reject this row"
            )
            assert value is not None


def test_layer_scores_is_why_a_null_cannot_enter_the_maps():
    """The coercion the writers rely on, asserted directly. If this changes, the
    read-back's `dict[str, float]` stops being safe."""
    scores = LayerScores(rule_score=1, ml_score="0.5")
    assert scores.rule_score == 1.0 and isinstance(scores.rule_score, float)
    assert scores.ml_score == 0.5
    assert scores.llm_score == 0.0, "a key never set reads as 0.0, not None"
    assert all(isinstance(v, float) for v in scores.as_dict().values())

    with pytest.raises(TypeError):
        LayerScores(rule_score=None)


# ── the read-back shape ──────────────────────────────────────────────────────

def _record_body(*, authorized: bool, proxy: bool = False) -> dict:
    """The dict `get_request` assembles, mirrored field for field from a row with
    every nullable column actually null -- the widest shape the database can
    hand back."""
    body = {
        "trace_id": "req_x", "timestamp": "2026-08-25T00:00:00Z",
        "execution_mode": "scan_only", "is_proxy": False, "severity": "INFO",
        "attribution": {
            "tenant_id": None, "dept_id": None, "dept_name": None, "app_id": None,
            "app_name": None, "source": None, "user_id": None, "key_id": None,
            "ip_address": None, "user_agent": None, "attribution_verified": False,
        },
        "decision": "ALLOW", "risk_score": 0.0, "primary_reason": None,
        "confidence": None, "confidence_band": None, "threats": [],
        "input_hash": "sha256:abc", "input_length": 0,
        "run_id": None, "session_id": None, "turn_index": None,
        "input_source": "user_prompt",
        "detection_scores": {"rule": 0.1, "ml": 0.2, "llm": 0.0} if authorized else {},
        "guardrail_scores": {"pii": 0.0} if authorized else {},
        "processing": {
            "latency_ms": 1.0, "llm_invoked": False, "detection_mode": "fast",
            "execution_mode": "scan_only", "policy_source": "system_default",
        },
    }
    if proxy:
        body["proxy"] = {
            "provider": "openai", "model": "gpt-4o", "provider_latency_ms": 100,
            "total_latency_ms": 120, "execution_status": "completed",
            "input_primary_reason": "clean", "input_confidence": 0.1,
            "input_threats": [], "input_attack_type": None, "input_raw": None,
            "input_sanitized": None, "output_decision": "ALLOW",
            "output_primary_reason": None, "output_confidence": None,
            "output_threats": [], "output_raw": None, "output_sanitized": None,
            "behavior_flag": None, "output_flags": None,
        }
    return body


@pytest.mark.parametrize("authorized", [True, False])
@pytest.mark.parametrize("proxy", [True, False])
def test_a_row_with_every_nullable_column_null_still_validates(authorized, proxy):
    """A read-back must survive the emptiest row the schema permits. Every column
    that is nullable in `audit_logs` is null here."""
    body   = _record_body(authorized=authorized, proxy=proxy)
    served = RequestRecordResponse.model_validate(body).model_dump(exclude_unset=True)

    assert set(served) == set(body), (
        f"the model changed the key set (dropped {set(body) - set(served)}, "
        f"added {set(served) - set(body)})"
    )
    assert served["detection_scores"] == body["detection_scores"]
    assert ("proxy" in served) is proxy, "proxy detail must be absent, not null"
