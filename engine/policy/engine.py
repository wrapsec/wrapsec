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
    Decision logic:
      score >= block_threshold    → BLOCK
      score >= sanitize_threshold → SANITIZE
      score <  sanitize_threshold → ALLOW
    """

    def __init__(self, rules: PolicyRules | None = None):
        self.rules = rules or PolicyRules.from_settings()

    def decide(
        self,
        risk_score:         RiskScore,
        threats:            list[ThreatCategory],
        block_threshold:    float | None = None,
        sanitize_threshold: float | None = None,
    ) -> PolicyDecision:
        try:
            score = risk_score.value

            # Use dynamic thresholds if provided
            bt = block_threshold    or self.rules.block_threshold
            st = sanitize_threshold or self.rules.sanitize_threshold

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