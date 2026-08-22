# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
domain/value_objects/severity.py

Severity classification for WrapSec audit events.

Severity is derived from decision + risk_score + primary_reason.
It is stored in audit_logs at write time and used by SIEM/security tool
integrations. It is never returned in scan responses (POST /v1/ai/request
or POST /v1/chat/completions) to avoid giving attackers evasion signals.

Severity levels:
    CRITICAL  - High confidence attack OR any guardrail block
                (guardrail blocks identified by _GUARDRAIL_BLOCK suffix -
                future guardrails like toxicity are automatically covered)
    HIGH      - Detection-based block with lower confidence
    MEDIUM    - Any sanitization (threat detected but mitigated)
    LOW       - Clean input allowed through

To update the severity model (e.g. adjust CRITICAL threshold, add new
levels), edit compute_severity() below. All callers import from this
module - no other files need to change.
"""

# Threshold above which a detection-based BLOCK is escalated to CRITICAL.
# Intentionally hardcoded - this is a classification boundary for SIEM output,
# distinct from block_threshold/sanitize_threshold which gate request decisions.
# If block_threshold changes significantly, review this constant too.
CRITICAL_RISK_THRESHOLD = 0.9

# Severity levels - ordered from highest to lowest for reference
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
        risk_score:     0.0-1.0 (detection only - guardrail blocks = 0.0)
        primary_reason: e.g. RULE_DETECTOR, PII_GUARDRAIL_BLOCK, SYSTEM_ERROR

    Returns:
        One of: CRITICAL / HIGH / MEDIUM / LOW

    Notes:
        - Guardrail blocks (any type) are always CRITICAL regardless of
          risk_score, because risk_score is always 0.0 on guardrail paths.
          Guardrail blocks are identified by the _GUARDRAIL_BLOCK suffix,
          which covers all current and future guardrail types automatically.
        - SYSTEM_ERROR lands in CRITICAL, not HIGH. The intent was HIGH
          (a detector failure is not a confirmed threat), but the fail-closed
          path pairs SYSTEM_ERROR with risk_score=1.0, which meets the
          CRITICAL_RISK_THRESHOLD check above and returns before the
          SYSTEM_ERROR branch below is reached. Documented rather than
          "fixed": changing it would move live alerting, and CRITICAL is
          defensible for a request refused because it could not be inspected.
          Anything keying on severity should know detector failures arrive
          as CRITICAL.
        - risk_score = 0.0 does NOT mean safe - always check decision +
          primary_reason per core_concepts.md.
    """
    if decision == "BLOCK":
        # Guardrail block - always CRITICAL regardless of risk_score
        # (risk_score is 0.0 on all guardrail paths by design)
        if primary_reason and primary_reason.endswith("_GUARDRAIL_BLOCK"):
            return "CRITICAL"

        # High confidence detection-based block
        if risk_score >= CRITICAL_RISK_THRESHOLD:
            return "CRITICAL"

        # Lower confidence detection block or SYSTEM_ERROR block
        return "HIGH"

    # Only reached for non-BLOCK decisions (SANITIZE / ALLOW). BLOCK always
    # returns inside the branch above.
    #
    # SYSTEM_ERROR is not reachable here today: both producers pair it with
    # BLOCK. GatewayService forces BLOCK whenever a detector failed (the same
    # condition that yields SYSTEM_ERROR), and OutputGuard sets BLOCK
    # explicitly when it fails. This branch is kept as a defensive floor so a
    # future producer that reports SYSTEM_ERROR on a non-BLOCK decision is
    # still surfaced as HIGH rather than silently scored LOW.
    if primary_reason == "SYSTEM_ERROR":
        return "HIGH"

    if decision == "SANITIZE":
        return "MEDIUM"

    # ALLOW - clean input
    return "LOW"
