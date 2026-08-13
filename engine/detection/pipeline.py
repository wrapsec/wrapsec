# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
DetectionPipeline -- owns Tier 1 (TF-IDF) and Tier 2 (transformer) detector lifecycle.

GatewayService creates one DetectionPipeline instance at startup and calls run() per request.
The pipeline is profile-aware: the DetectorProfile determines which models to load and
which rule pattern set to use. In v1 only the "general" profile exists.

Score combination: highest-risk-wins enforcement logic.
    combined_score = max(tfidf_score, transformer_score)
This is NOT ensemble confidence averaging. The goal is to catch threats that one tier
misses -- not to average uncertainty across both tiers.

Threat union: sorted(set(tfidf_threats | transformer_threats))
Sorted by .value for deterministic ordering across runs (affects test assertions and
audit log serialization).

Parallel execution:
    Both detectors run concurrently via asyncio.to_thread.
    Transformer is wrapped in asyncio.wait_for with profile.tier2_timeout (default 1.5s).
    Timeout and transformer failures are treated as degraded detection, not system failures.
    TF-IDF result is always used regardless of transformer outcome.
"""

from __future__ import annotations

import asyncio
import logging
from enum import Enum

from domain.enums import ThreatCategory
from engine.detection.base import DetectionResult
from engine.detection.ml_detector import MLDetector
from engine.detection.preprocessors import BasePreprocessor
from engine.detection.profiles import DetectorProfile
from engine.detection.transformer_detector import TransformerDetector

logger = logging.getLogger("wrapsec.engine.pipeline")


class DetectorStatus(str, Enum):
    HEALTHY     = "healthy"
    DEGRADED    = "degraded"      # model unavailable -- using fallback tier only
    UNAVAILABLE = "unavailable"   # detector disabled by configuration


class DetectionPipeline:
    """
    Two-tier ML detection pipeline.

    Tier 1: TF-IDF + LogisticRegression (MLDetector) -- always runs, ~1ms, zero extra deps.
    Tier 2: DeBERTa-v3 transformer (TransformerDetector) -- semantic detection, ~20-50ms CPU.

    Both tiers load at startup. If Tier 2 fails to load, detection continues via Tier 1 only
    and status() reports transformer_detector as DEGRADED.

    In v2, passing a different DetectorProfile switches both the model files and the rule
    pattern set without any changes to this class or GatewayService.
    """

    def __init__(
        self,
        profile:       DetectorProfile,
        preprocessors: list[BasePreprocessor] | None = None,
    ):
        self._profile       = profile
        self._tfidf         = MLDetector(model_path=profile.tier1_model)
        self._transformer   = TransformerDetector(model_id=profile.tier2_model)
        # Preprocessors run before every detector. Empty in v1.1.0; the slot
        # exists so v1.6.0 OCR and later hooks can be added without changing
        # the pipeline shape or GatewayService.
        self._preprocessors = list(preprocessors) if preprocessors else []

        if not self._transformer.is_ready:
            logger.warning(
                "Transformer model unavailable -- running in degraded detection mode. "
                "model=%s profile=%s",
                profile.tier2_model, profile.name,
            )

    async def run(self, text: str) -> DetectionResult:
        """
        Run every preprocessor (if any), then both detection tiers in parallel,
        and return the combined result. Preprocessor failures and transformer
        timeouts are handled gracefully -- TF-IDF still runs even if a
        preprocessor or the transformer fails.
        """
        text = await self._run_preprocessors(text)

        tfidf_coro = asyncio.to_thread(self._tfidf.detect, text)

        if self._transformer.is_ready:
            transformer_coro = asyncio.wait_for(
                asyncio.to_thread(self._transformer.detect, text),
                timeout=self._profile.tier2_timeout,
            )
            results = await asyncio.gather(
                tfidf_coro,
                transformer_coro,
                return_exceptions=True,
            )

            tfidf_result = (
                results[0]
                if not isinstance(results[0], Exception)
                else DetectionResult.clean("ml_detector")
            )
            if isinstance(results[0], Exception):
                logger.error("TF-IDF detection failed: %s", results[0])

            if isinstance(results[1], asyncio.TimeoutError):
                logger.warning(
                    "Transformer inference timed out (%.1fs) -- using tfidf result only",
                    self._profile.tier2_timeout,
                )
                transformer_result = DetectionResult.clean("transformer_detector")
            elif isinstance(results[1], Exception):
                logger.error("Transformer inference failed: %s", results[1])
                transformer_result = DetectionResult.clean("transformer_detector")
            else:
                transformer_result = results[1]
        else:
            tfidf_result       = await tfidf_coro
            transformer_result = DetectionResult.clean("transformer_detector")

        return self._combine(tfidf_result, transformer_result)

    async def _run_preprocessors(self, text: str) -> str:
        """
        Apply preprocessors sequentially, off the event loop. A failing
        preprocessor logs and is skipped; the chain never denies a request.
        """
        if not self._preprocessors:
            return text
        for pp in self._preprocessors:
            try:
                text = await asyncio.to_thread(pp.preprocess, text)
            except Exception as exc:
                logger.warning(
                    "Preprocessor %s failed, skipping: %s", pp.name, exc,
                )
        return text

    def _combine(
        self,
        tfidf_result:       DetectionResult,
        transformer_result: DetectionResult,
    ) -> DetectionResult:
        """
        Highest-risk-wins: take the max score and union of threats.
        Threat list is sorted by .value for deterministic serialization.
        """
        if transformer_result.score >= tfidf_result.score:
            dominant = transformer_result
        else:
            dominant = tfidf_result

        combined_score = dominant.score

        combined_threats: list[ThreatCategory] = sorted(
            set(tfidf_result.threats) | set(transformer_result.threats),
            key=lambda t: t.value,
        )

        # Merge details from both tiers for observability
        combined_details: dict = {}
        if tfidf_result.details:
            combined_details["tfidf"] = tfidf_result.details
        if transformer_result.details:
            combined_details["transformer"] = transformer_result.details

        return DetectionResult(
            score     = combined_score,
            threats   = combined_threats,
            triggered = combined_score > 0.0,
            detector  = "ml_detector",   # keeps downstream layer name consistent
            details   = combined_details if combined_details else None,
        )

    def status(self) -> dict[str, DetectorStatus]:
        return {
            "tfidf_detector":       (
                DetectorStatus.HEALTHY
                if self._tfidf.is_ready
                else DetectorStatus.DEGRADED
            ),
            "transformer_detector": (
                DetectorStatus.HEALTHY
                if self._transformer.is_ready
                else DetectorStatus.DEGRADED
            ),
        }
