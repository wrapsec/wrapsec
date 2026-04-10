def compute_primary_reason(
    guardrail_triggered: bool,
    guardrail_decision:  str | None,
    rule_score:  float,
    ml_score:    float,
    llm_score:   float,
    pii_score:   float,
    block_threshold:    float = 0.7,
    sanitize_threshold: float = 0.4,
) -> str:
    """
    Determines the dominant factor behind the decision.

    Priority:
      1. Guardrail triggered (PII) → PII_GUARDRAIL_BLOCK or PII_GUARDRAIL_SANITIZE
      2. Highest detector score    → RULE_DETECTOR / ML_DETECTOR / LLM_DETECTOR
      3. No threat detected        → NO_THREAT_DETECTED
    """
    if guardrail_triggered:
        if pii_score >= block_threshold:
            return "PII_GUARDRAIL_BLOCK"
        return "PII_GUARDRAIL_SANITIZE"

    scores = {
        "RULE_DETECTOR": rule_score,
        "ML_DETECTOR":   ml_score,
        "LLM_DETECTOR":  llm_score,
    }

    max_score = max(scores.values())
    if max_score <= 0.0:
        return "NO_THREAT_DETECTED"

    return max(scores, key=scores.get)