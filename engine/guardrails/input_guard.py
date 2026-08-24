# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import logging
from dataclasses import dataclass, replace

from engine.detection.base import DetectionResult
from engine.guardrails.pii.detector import PIIDetector
from engine.guardrails.pii.redactor import PIIRedactor
from engine.guardrails.toxicity.detector import ToxicityDetector

logger = logging.getLogger("wrapsec.engine")


@dataclass
class InputGuardResult:
    text:             str
    sanitized_text:   str | None
    pii_result:       DetectionResult
    toxicity_result:  DetectionResult
    redacted_types:   list[str]
    was_sanitized:    bool
    # True when the guardrail could not be evaluated, as opposed to evaluating
    # to "clean". Without the distinction a failure is indistinguishable from a
    # clean result: both carry a zero-score pii_result, so a caller reading only
    # the scores allows text the guardrail never actually inspected. The caller
    # is expected to treat this exactly as it treats a guardrail timeout.
    failed:           bool = False


class InputGuard:
    """
    Orchestrates guardrail checks on input text.

    Guardrails (in evaluation order):
      1. PII - detects + redacts sensitive personal data
      2. Toxicity - extracts toxicity signal from ML result

    Note: Toxicity detector is called AFTER ML detection in service.py.
    InputGuard.inspect_toxicity() is called separately with the ML result.
    """

    def __init__(self):
        self._pii_detector = PIIDetector()
        self._pii_redactor = PIIRedactor()
        self._tox_detector = ToxicityDetector()

    def inspect(self, text: str) -> InputGuardResult:
        """Run PII guardrail. Toxicity is added later via inspect_toxicity()."""
        try:
            pii_result = self._pii_detector.detect(text)

            # The detector swallows its own exceptions and reports them through
            # this flag rather than raising, so the handler below never sees
            # them. Read it here or a detector fault is indistinguishable from
            # a clean scan and the guardrail is silently skipped.
            if pii_result.failed:
                return InputGuardResult(
                    text            = text,
                    sanitized_text  = None,
                    pii_result      = pii_result,
                    toxicity_result = DetectionResult.clean("toxicity_detector"),
                    redacted_types  = [],
                    was_sanitized   = False,
                    failed          = True,
                )

            if not pii_result.triggered:
                return InputGuardResult(
                    text            = text,
                    sanitized_text  = None,
                    pii_result      = pii_result,
                    toxicity_result = DetectionResult.clean("toxicity_detector"),
                    redacted_types  = [],
                    was_sanitized   = False,
                )

            sanitized, redacted_types = self._pii_redactor.redact(text)

            return InputGuardResult(
                text            = text,
                sanitized_text  = sanitized,
                pii_result      = pii_result,
                toxicity_result = DetectionResult.clean("toxicity_detector"),
                redacted_types  = redacted_types,
                was_sanitized   = True,
            )

        except Exception as e:
            # The clean pii_result below is a placeholder, not a verdict. The
            # detector may have raised before scanning anything, and the
            # redactor re-raises rather than hand back text it could not
            # redact -- so neither can be read as "no PII found". `failed` is
            # what says so. Returning the placeholder alone reported clean for
            # text nobody inspected, and the caller forwarded it unredacted.
            logger.error(f"InputGuard PII failed: {e}")
            return InputGuardResult(
                text            = text,
                sanitized_text  = None,
                pii_result      = DetectionResult.clean("input_guard"),
                toxicity_result = DetectionResult.clean("toxicity_detector"),
                redacted_types  = [],
                was_sanitized   = False,
                failed          = True,
            )

    def inspect_toxicity(
        self,
        guard_result: "InputGuardResult",
        ml_result:    DetectionResult,
    ) -> "InputGuardResult":
        """
        Extract toxicity signal from the ML result and attach to guard_result.
        Called after ML detection completes in service.py.
        Returns updated InputGuardResult with toxicity_result populated.
        """
        try:
            toxicity_result = self._tox_detector.detect_from_ml(ml_result)

            return InputGuardResult(
                text            = guard_result.text,
                sanitized_text  = guard_result.sanitized_text,
                pii_result      = guard_result.pii_result,
                toxicity_result = toxicity_result,
                redacted_types  = guard_result.redacted_types,
                was_sanitized   = guard_result.was_sanitized,
                # Carried forward, not recomputed. This rebuilds the result
                # rather than mutating it, so a field left out here is silently
                # reset to its default -- and a PII guardrail that failed at
                # step 1 would report success by the time this returns.
                failed          = guard_result.failed,
            )
        except Exception as e:
            # Flagged, not swallowed. Returning the prior result unchanged left
            # its clean toxicity placeholder in place with nothing recording
            # that the guardrail had not run, so content it would have blocked
            # was judged on the detection layers alone.
            #
            # The ML failure case is already covered upstream -- this signal is
            # derived from ml_result, so a failed ML layer sets detection_failed
            # before this runs. This covers a fault in the derivation itself.
            logger.error(f"InputGuard toxicity failed: {e}")
            return replace(guard_result, failed=True)