# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from abc import ABC, abstractmethod
from dataclasses import dataclass

from domain.enums import ThreatCategory


@dataclass
class DetectionResult:
    score:      float
    threats:    list[ThreatCategory]
    triggered:  bool
    detector:   str
    details:    dict | None = None
    # True when the detector could not produce a verdict, as opposed to
    # producing a verdict of "nothing found". Both carry score 0.0, so without
    # this flag the two are indistinguishable and a broken detector reads as a
    # clean one. Callers must treat a failed result as a detection failure, not
    # as a low score.
    failed:     bool = False

    @classmethod
    def clean(cls, detector: str) -> "DetectionResult":
        """A real verdict: the detector ran and found nothing."""
        return cls(
            score     = 0.0,
            threats   = [],
            triggered = False,
            detector  = detector,
        )

    @classmethod
    def failure(cls, detector: str) -> "DetectionResult":
        """
        Not a verdict: the detector could not run.

        Scored 0.0 like `clean()` because there is no signal to report, and
        flagged so no caller mistakes the absence of a signal for the absence of
        a threat.
        """
        return cls(
            score     = 0.0,
            threats   = [],
            triggered = False,
            detector  = detector,
            failed    = True,
        )


class BaseDetector(ABC):
    """
    Abstract base class for all detectors.
    All detectors must be stateless and side-effect free.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Detector name - used in logs and traces."""

    @abstractmethod
    def detect(self, text: str) -> DetectionResult:
        """
        Run detection on input text.

        Must never raise. On failure return `DetectionResult.failure()`, NOT
        `clean()`: the caller's fail-closed handling triggers on the flag, and
        `clean()` says the detector ran and found nothing. Returning `clean()`
        from an exception handler reports a broken detector as a safe one, and
        the request is then judged on whatever layers remain.
        """