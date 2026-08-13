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

    @classmethod
    def clean(cls, detector: str) -> "DetectionResult":
        return cls(
            score     = 0.0,
            threats   = [],
            triggered = False,
            detector  = detector,
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
        Must never raise - return DetectionResult.clean() on failure.
        """