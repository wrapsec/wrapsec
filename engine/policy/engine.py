# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import logging
from dataclasses import dataclass
from domain.enums import DecisionType, ThreatCategory
from domain.value_objects.risk_score import RiskScore
from engine.policy.rules import PolicyRules

logger = logging.getLogger("wrapsec.engine")


@dataclass
class PolicyDecision:
    decision:   DecisionType
    risk_score: RiskScore
    threats:    list[ThreatCategory]
    rules:      PolicyRules


class PolicyEngine:
    """
    Maps aggregated risk score to a policy decision.

    Guardrail-first enforcement:
      PII and other guardrails are evaluated FIRST.
      A guardrail decision overrides the detection-based decision.
      Guardrail scores never contribute to the detection risk score.

    Detection-based decision (applied only if no guardrail triggers):
      score >= block_threshold    → BLOCK
      score >= sanitize_threshold → SANITIZE
      score <  sanitize_threshold → ALLOW
    """

    def __init__(self, rules: PolicyRules | None = None):
        self.rules = rules or PolicyRules.from_settings()

    def decide(
        self,
        risk_score:                    RiskScore,
        threats:                       list[ThreatCategory],
        block_threshold:               float | None = None,
        sanitize_threshold:            float | None = None,
        pii_score:                     float = 0.0,
        pii_block_threshold:           float | None = None,
        pii_sanitize_threshold:        float | None = None,
        toxicity_score:                float = 0.0,
        toxicity_block_threshold:      float | None = None,
        toxicity_sanitize_threshold:   float | None = None,
    ) -> PolicyDecision:
        """
        Evaluate guardrail-first, then detection-based decision.

        Guardrail priority order:
          1. PII guardrail   (pii_score vs pii_block/sanitize_threshold)
          2. Toxicity guardrail (toxicity_score vs toxicity_block/sanitize_threshold)
          3. Detection-based (risk_score vs block/sanitize_threshold)

        All guardrail thresholds are independent from detection thresholds.
        """
        try:
            score = risk_score.value

            # Detection thresholds — use is-None check; 0.0 is a valid threshold
            bt = self.rules.block_threshold    if block_threshold    is None else block_threshold
            st = self.rules.sanitize_threshold if sanitize_threshold is None else sanitize_threshold

            if bt < st:
                logger.warning(
                    f"PolicyEngine misconfiguration: block_threshold ({bt}) < "
                    f"sanitize_threshold ({st}) — SANITIZE decision is unreachable"
                )

            # PII guardrail thresholds
            pii_bt = pii_block_threshold    if pii_block_threshold    is not None else bt
            pii_st = pii_sanitize_threshold if pii_sanitize_threshold is not None else st

            # Toxicity guardrail thresholds — default to same as detection
            tox_bt = toxicity_block_threshold    if toxicity_block_threshold    is not None else bt
            tox_st = toxicity_sanitize_threshold if toxicity_sanitize_threshold is not None else st

            # ── 1. PII guardrail (highest priority) ──────────
            if pii_score >= pii_bt:
                logger.debug(f"PolicyEngine PII guardrail BLOCK pii_score={pii_score} threshold={pii_bt}")
                return PolicyDecision(decision=DecisionType.BLOCK,   risk_score=risk_score, threats=threats, rules=self.rules)

            if pii_score >= pii_st:
                logger.debug(f"PolicyEngine PII guardrail SANITIZE pii_score={pii_score} threshold={pii_st}")
                return PolicyDecision(decision=DecisionType.SANITIZE, risk_score=risk_score, threats=threats, rules=self.rules)

            # ── 2. Toxicity guardrail ─────────────────────────
            if toxicity_score >= tox_bt:
                logger.debug(f"PolicyEngine toxicity guardrail BLOCK toxicity_score={toxicity_score} threshold={tox_bt}")
                return PolicyDecision(decision=DecisionType.BLOCK,   risk_score=risk_score, threats=threats, rules=self.rules)

            if toxicity_score >= tox_st:
                logger.debug(f"PolicyEngine toxicity guardrail SANITIZE toxicity_score={toxicity_score} threshold={tox_st}")
                return PolicyDecision(decision=DecisionType.SANITIZE, risk_score=risk_score, threats=threats, rules=self.rules)

            # ── 3. Detection-based decision ───────────────────
            if score >= bt:
                decision = DecisionType.BLOCK
            elif score >= st:
                decision = DecisionType.SANITIZE
            else:
                decision = DecisionType.ALLOW

            logger.debug(
                f"PolicyEngine decision: {decision.value} "
                f"score={score} "
                f"threats={[t.value for t in threats]}"
            )

            return PolicyDecision(
                decision   = decision,
                risk_score = risk_score,
                threats    = threats,
                rules      = self.rules,
            )

        except Exception as e:
            logger.error(f"PolicyEngine failed: {e} — defaulting to BLOCK")
            return PolicyDecision(
                decision   = DecisionType.BLOCK,
                risk_score = risk_score,
                threats    = threats,
                rules      = self.rules,
            )

    def update_rules(self, rules: PolicyRules) -> None:
        rules.validate()
        self.rules = rules
        logger.info(
            f"PolicyEngine rules updated — "
            f"block={rules.block_threshold} "
            f"sanitize={rules.sanitize_threshold}"
        )