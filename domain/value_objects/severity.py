"""
domain/value_objects/severity.py

Severity classification for WrapSec audit events.

Severity is derived from decision + risk_score + primary_reason.
It is stored in audit_logs at write time and used by SIEM/security tool
integrations. It is never returned in scan responses (POST /v1/ai/request
or POST /v1/chat/completions) to avoid giving attackers evasion signals.

Severity levels:
    CRITICAL  — High confidence attack OR any guardrail block
                (guardrail blocks identified by _GUARDRAIL_BLOCK suffix —
                future guardrails like toxicity are automatically covered)
    HIGH      — Detection-based block with lower confidence
                OR SYSTEM_ERROR (ops attention required)
    MEDIUM    — Any sanitization (threat detected but mitigated)
    LOW       — Clean input allowed through

To update the severity model (e.g. adjust CRITICAL threshold, add new
levels), edit compute_severity() below. All callers import from this
module — no other files need to change.
"""

# Threshold above which a detection-based BLOCK is escalated to CRITICAL.
# Adjust via settings in a future iteration if runtime configurability needed.
CRITICAL_RISK_THRESHOLD = 0.9

# Severity levels — ordered from highest to lowest for reference
SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def compute_severity(
    decision:       str,
    risk_score:     float,
    primary_reason: str | None,
) -> str:
    """
    Compute severity from decision, risk_score, and primary_reason.

    Args:
        decision:       BLOCK / SANITIZE / ALLOW
        risk_score:     0.0–1.0 (detection only — guardrail blocks = 0.0)
        primary_reason: e.g. RULE_DETECTOR, PII_GUARDRAIL_BLOCK, SYSTEM_ERROR

    Returns:
        One of: CRITICAL / HIGH / MEDIUM / LOW

    Notes:
        - Guardrail blocks (any type) are always CRITICAL regardless of
          risk_score, because risk_score is always 0.0 on guardrail paths.
          Guardrail blocks are identified by the _GUARDRAIL_BLOCK suffix,
          which covers all current and future guardrail types automatically.
        - SYSTEM_ERROR returns HIGH — not CRITICAL (no confirmed threat)
          but requires immediate ops attention.
        - risk_score = 0.0 does NOT mean safe — always check decision +
          primary_reason per core_concepts.md.
    """
    if decision == "BLOCK":
        # Guardrail block — always CRITICAL regardless of risk_score
        # (risk_score is 0.0 on all guardrail paths by design)
        if primary_reason and primary_reason.endswith("_GUARDRAIL_BLOCK"):
            return "CRITICAL"

        # High confidence detection-based block
        if risk_score >= CRITICAL_RISK_THRESHOLD:
            return "CRITICAL"

        # Lower confidence detection block or SYSTEM_ERROR block
        return "HIGH"

    # SYSTEM_ERROR — scanner failed, needs ops attention
    if primary_reason == "SYSTEM_ERROR":
        return "HIGH"

    if decision == "SANITIZE":
        return "MEDIUM"

    # ALLOW — clean input
    return "LOW"
