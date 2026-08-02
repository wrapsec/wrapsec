# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Red-team runner: push every corpus case through WrapSec's real decision path
(pipeline -> risk scorer -> policy) in FAST / scan-only mode.

FAST mode never invokes the LLM detector and scan-only never calls the LLM
proxy, so the run is fully offline and deterministic -- no external provider, no
database, no Redis. It reuses GatewayService.process (which returns its decision
without persisting) so the evaluation reflects exactly what production decides.
"""

from __future__ import annotations

from dataclasses import dataclass

from domain.entities.request import IncomingRequest
from domain.enums import DecisionType, DetectionMode, ExecutionMode
from services.gateway.service import GatewayService
from tests.eval.schema import Case, load_corpus

_FLAGGED = {DecisionType.BLOCK, DecisionType.SANITIZE}


@dataclass
class CaseResult:
    case:           Case
    decision:       str            # DecisionType value
    risk_score:     float
    primary_reason: str | None
    flagged:        bool           # BLOCK or SANITIZE (a "catch")
    blocked:        bool           # BLOCK specifically
    correct:        bool           # flagged matches the malicious/benign expectation


def _as_float(score) -> float:
    # risk_score may be a RiskScore value object or a plain float.
    return float(getattr(score, "value", score))


async def _run_one(svc: GatewayService, case: Case) -> CaseResult:
    req = IncomingRequest(
        input          = case.text,
        detection_mode = DetectionMode.FAST,
        execution_mode = ExecutionMode.SCAN_ONLY,
    )
    d = (await svc.process(req)).decision

    flagged     = d.decision in _FLAGGED
    expect_flag = case.label == "malicious"
    return CaseResult(
        case           = case,
        decision       = d.decision.value,
        risk_score     = _as_float(d.risk_score),
        primary_reason = getattr(d, "primary_reason", None),
        flagged        = flagged,
        blocked        = d.decision == DecisionType.BLOCK,
        correct        = flagged == expect_flag,
    )


async def run_corpus(cases: list[Case] | None = None) -> list[CaseResult]:
    """Evaluate every case sequentially (detection is ~ms; sequential keeps the
    shared model access simple and the run deterministic)."""
    cases = cases if cases is not None else load_corpus()
    svc   = GatewayService()
    return [await _run_one(svc, c) for c in cases]
