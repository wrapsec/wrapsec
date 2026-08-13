# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import logging
from dataclasses import dataclass, field

from config.settings import get_settings
from engine.guardrails.pii.detector import PIIDetector
from engine.guardrails.pii.redactor import PIIRedactor

logger = logging.getLogger("wrapsec.engine")


@dataclass
class OutputGuardResult:
    """
    Result of running OutputGuard on a provider response.

    Existing fields (unchanged -- existing callers unaffected):
      text           -- original text before any sanitization
      sanitized_text -- redacted text if decision=SANITIZE, else None
      was_sanitized  -- True if any PII was redacted
      redacted_types -- list of PII entity types that were redacted

    New fields (added for proxy mode decision layer):
      decision        -- ALLOW / BLOCK / SANITIZE
      primary_reason  -- reason for the decision
      pii_score       -- raw PII confidence score from detector
      threats         -- list of detected threat types (PII entity names)
      confidence      -- confidence in the output decision (0.0 to 1.0)
    """
    # Existing fields -- do not remove or rename
    text:           str
    sanitized_text: str | None
    was_sanitized:  bool
    redacted_types: list[str]

    # New fields for proxy mode
    decision:       str = "ALLOW"   # ALLOW / BLOCK / SANITIZE
    primary_reason: str = "NO_THREAT_DETECTED"
    pii_score:      float = 0.0
    threats:        list[str] = field(default_factory=list)
    confidence:     float = 1.0


class OutputGuard:
    """
    Checks LLM output for PII before returning to client.
    Redacts any PII found in the output.

    In proxy mode, returns a full ALLOW/BLOCK/SANITIZE decision.
    In scan-only mode, existing callers use only was_sanitized and sanitized_text.

    Decision logic (thresholds from settings - OUTPUT_BLOCK_THRESHOLD / OUTPUT_SANITIZE_THRESHOLD):
      pii_score >= output_block_threshold    -> BLOCK    (severe PII, response not returned)
      pii_score >= output_sanitize_threshold -> SANITIZE (PII redacted, response returned)
      otherwise                              -> ALLOW    (clean, response returned as-is)

    Failure behaviour (fail-closed for output):
      If the guardrail itself fails, decision = BLOCK with primary_reason = SYSTEM_ERROR.
      Output must never reach the client when the guard cannot be evaluated.
    """

    def __init__(self):
        self._detector = PIIDetector()
        self._redactor = PIIRedactor()

    def inspect(self, text: str) -> OutputGuardResult:
        if not text:
            return OutputGuardResult(
                text           = text,
                sanitized_text = None,
                was_sanitized  = False,
                redacted_types = [],
                decision       = "ALLOW",
                primary_reason = "NO_THREAT_DETECTED",
                pii_score      = 0.0,
                threats        = [],
                confidence     = 1.0,
            )

        try:
            settings   = get_settings()
            pii_result = self._detector.detect(text)
            pii_score  = pii_result.score if pii_result else 0.0

            # BLOCK -- severe PII pattern, response must not reach client
            if pii_score >= settings.output_block_threshold:
                logger.warning(
                    f"OutputGuard BLOCK -- pii_score={pii_score:.3f} "
                    f"exceeds block threshold={settings.output_block_threshold}"
                )
                return OutputGuardResult(
                    text           = text,
                    sanitized_text = None,
                    was_sanitized  = False,
                    redacted_types = [],
                    decision       = "BLOCK",
                    primary_reason = "PII_GUARDRAIL_BLOCK",
                    pii_score      = pii_score,
                    threats        = pii_result.threats if pii_result else [],
                    confidence     = pii_score,
                )

            # Below sanitize threshold -- return as-is
            if pii_score < settings.output_sanitize_threshold:
                return OutputGuardResult(
                    text           = text,
                    sanitized_text = None,
                    was_sanitized  = False,
                    redacted_types = [],
                    decision       = "ALLOW",
                    primary_reason = "NO_THREAT_DETECTED",
                    pii_score      = pii_score,
                    threats        = [],
                    confidence     = 1.0 - pii_score,
                )

            # SANITIZE -- PII detected, redact and return
            sanitized, redacted_types = self._redactor.redact(text)

            logger.warning(
                f"OutputGuard SANITIZE -- redacted PII types: {redacted_types}"
            )

            return OutputGuardResult(
                text           = text,
                sanitized_text = sanitized,
                was_sanitized  = True,
                redacted_types = redacted_types,
                decision       = "SANITIZE",
                primary_reason = "PII_GUARDRAIL_SANITIZE",
                pii_score      = pii_score,
                threats        = redacted_types,
                confidence     = pii_score,
            )

        except Exception as e:
            # Fail-closed: if OutputGuard itself fails, block the response.
            # Output must never reach the client when the guard cannot evaluate it.
            logger.error(f"OutputGuard failed -- blocking response: {e}")
            return OutputGuardResult(
                text           = text,
                sanitized_text = None,
                was_sanitized  = False,
                redacted_types = [],
                decision       = "BLOCK",
                primary_reason = "SYSTEM_ERROR",
                pii_score      = 0.0,
                threats        = [],
                confidence     = 0.0,
            )