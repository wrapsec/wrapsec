# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
BasePreprocessor -- text-normalising and text-augmenting hooks that run
before any detector in the DetectionPipeline.

The pipeline runs an empty preprocessor list by default (added in
v1.1.0 as B5), so this file only defines the contract. Concrete
preprocessors ship in later releases:

  v1.6.0  OCR         extracts text from image attachments and appends it
                      to the prompt so detectors reason over both channels.
  v1.6.0  Transcript  pulls speech-to-text from audio attachments.
  v1.7.0  Language    canonicalises Unicode confusables and homoglyphs.

Preprocessors must be stateless, side-effect free, and never raise. A
preprocessor that fails should log and return the input unchanged so
that one broken hook cannot deny an entire request.
"""

from abc import ABC, abstractmethod


class BasePreprocessor(ABC):
    """
    Text-in, text-out transformation that runs before detection.

    Kept synchronous for the same reason as BaseDetector: preprocessors
    run under asyncio.to_thread in the pipeline. Any preprocessor that
    needs I/O (OCR against a local model, remote transcription API)
    still exposes a sync interface and blocks -- the pipeline's thread
    pool absorbs the wait.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Preprocessor name - used in logs and traces."""

    @abstractmethod
    def preprocess(self, text: str) -> str:
        """
        Transform the input text and return the (possibly augmented) result.
        Must never raise - return the input unchanged on any error.
        """
