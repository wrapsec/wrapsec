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
        risk_score:              RiskScore,
        threats:                 list[ThreatCategory],
        block_threshold:         float | None = None,
        sanitize_threshold:      float | None = None,
        pii_score:               float = 0.0,
        pii_block_threshold:     float | None = None,
        pii_sanitize_threshold:  float | None = None,
    ) -> PolicyDecision:
        """
        Evaluate guardrail-first, then detection-based decision.

        Detection thresholds (block_threshold, sanitize_threshold):
          Applied to risk_score from detection layers.

        Guardrail thresholds (pii_block_threshold, pii_sanitize_threshold):
          Applied to pii_score from guardrail layer.
          Independent from detection thresholds.
          Defaults to detection thresholds if not explicitly set,
          but must be configured separately for proper separation of concerns.
        """
        try:
            score = risk_score.value

            # Detection thresholds
            bt = block_threshold    or self.rules.block_threshold
            st = sanitize_threshold or self.rules.sanitize_threshold

            # Guardrail thresholds — independent from detection
            # Default to detection thresholds only if not explicitly configured
            pii_bt = pii_block_threshold    if pii_block_threshold    is not None else bt
            pii_st = pii_sanitize_threshold if pii_sanitize_threshold is not None else st

            # ── Guardrail-first enforcement ──────────────────
            if pii_score >= pii_bt:
                decision = DecisionType.BLOCK
                logger.debug(
                    f"PolicyEngine guardrail override: BLOCK "
                    f"pii_score={pii_score} threshold={pii_bt}"
                )
                return PolicyDecision(
                    decision   = decision,
                    risk_score = risk_score,
                    threats    = threats,
                    rules      = self.rules,
                )

            if pii_score >= pii_st:
                decision = DecisionType.SANITIZE
                logger.debug(
                    f"PolicyEngine guardrail override: SANITIZE "
                    f"pii_score={pii_score} threshold={pii_st}"
                )
                return PolicyDecision(
                    decision   = decision,
                    risk_score = risk_score,
                    threats    = threats,
                    rules      = self.rules,
                )

            # ── Detection-based decision ──────────────────────
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