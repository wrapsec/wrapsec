def compute_primary_reason(
    guardrail_triggered: bool,
    guardrail_decision:  str | None,
    rule_score:          float,
    ml_score:            float,
    llm_score:           float,
    pii_score:           float,
    block_threshold:     float = 0.7,
    sanitize_threshold:  float = 0.4,
    detection_failed:    bool  = False,
) -> str:
    """
    Determines the dominant factor behind the decision.

    Priority:
      1. System/detection failure   → SYSTEM_ERROR
      2. Guardrail triggered (PII)  → PII_GUARDRAIL_BLOCK or PII_GUARDRAIL_SANITIZE
      3. Highest detector score     → RULE_DETECTOR / ML_DETECTOR / LLM_DETECTOR
      4. No threat detected         → NO_THREAT_DETECTED

    Note: SYSTEM_ERROR takes absolute priority.
    It is critical to distinguish clean input (NO_THREAT_DETECTED)
    from a system failure (SYSTEM_ERROR) in audit logs —
    these require different remediation responses.
    """

    # System failure takes absolute priority
    # Must not be reported as NO_THREAT_DETECTED
    if detection_failed:
        return "SYSTEM_ERROR"

    # Guardrail override
    if guardrail_triggered:
        if pii_score >= block_threshold:
            return "PII_GUARDRAIL_BLOCK"
        return "PII_GUARDRAIL_SANITIZE"

    # Dominant detection layer
    scores = {
        "RULE_DETECTOR": rule_score,
        "ML_DETECTOR":   ml_score,
        "LLM_DETECTOR":  llm_score,
    }

    max_score = max(scores.values())
    if max_score <= 0.0:
        return "NO_THREAT_DETECTED"

    return max(scores, key=scores.get)