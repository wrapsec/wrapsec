# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
B5 in v1.1.0 -- preprocessor slot in DetectionPipeline.

Empty list (default) must be a no-op. A preprocessor must be able to
mutate the text seen by the detectors. A failing preprocessor must not
deny a request; detection continues on the last successful text.
"""

import pytest
from unittest.mock import patch

from engine.detection.base import DetectionResult
from engine.detection.pipeline import DetectionPipeline
from engine.detection.preprocessors import BasePreprocessor
from engine.detection.profiles import get_profile


class _RecordingPreprocessor(BasePreprocessor):
    """Appends a marker so tests can assert the preprocessor ran."""

    def __init__(self, marker: str) -> None:
        self._marker = marker
        self.calls: list[str] = []

    @property
    def name(self) -> str:
        return f"recording_{self._marker}"

    def preprocess(self, text: str) -> str:
        self.calls.append(text)
        return f"{text} [{self._marker}]"


class _ExplodingPreprocessor(BasePreprocessor):
    @property
    def name(self) -> str:
        return "exploding"

    def preprocess(self, text: str) -> str:
        raise RuntimeError("boom")


def _make_pipeline(preprocessors=None) -> DetectionPipeline:
    """
    Build a pipeline with stubbed detectors so tests do not touch the
    filesystem or transformers cache. Both detectors are constructed with
    __init__ bypassed and is_ready coerced via property patching in each
    test as needed.
    """
    def _stub_ml_init(self, model_path):
        self._ready = False

    def _stub_tx_init(self, model_id):
        self._ready = False

    with patch(
        "engine.detection.pipeline.MLDetector.__init__", _stub_ml_init
    ), patch(
        "engine.detection.pipeline.TransformerDetector.__init__", _stub_tx_init
    ):
        pipeline = DetectionPipeline(get_profile("general"), preprocessors=preprocessors)
    return pipeline


@pytest.mark.asyncio
async def test_empty_preprocessor_list_is_default():
    p = _make_pipeline()
    # accessing private state is fine here -- this test exists to lock the default
    assert p._preprocessors == []


@pytest.mark.asyncio
async def test_preprocessor_runs_before_detection():
    recorder = _RecordingPreprocessor("ocr")
    p = _make_pipeline(preprocessors=[recorder])

    p._tfidf._ready = True
    with patch.object(
        p._tfidf, "detect", return_value=DetectionResult.clean("ml_detector")
    ) as tfidf_detect:
        await p.run("hello world")

    tfidf_detect.assert_called_once_with("hello world [ocr]")
    assert recorder.calls == ["hello world"]


@pytest.mark.asyncio
async def test_preprocessors_chain_in_order():
    first  = _RecordingPreprocessor("a")
    second = _RecordingPreprocessor("b")
    p = _make_pipeline(preprocessors=[first, second])

    p._tfidf._ready = True
    with patch.object(
        p._tfidf, "detect", return_value=DetectionResult.clean("ml_detector")
    ) as tfidf_detect:
        await p.run("x")

    tfidf_detect.assert_called_once_with("x [a] [b]")


@pytest.mark.asyncio
async def test_failing_preprocessor_is_skipped_not_fatal():
    p = _make_pipeline(preprocessors=[_ExplodingPreprocessor()])

    p._tfidf._ready = True
    with patch.object(
        p._tfidf, "detect", return_value=DetectionResult.clean("ml_detector")
    ) as tfidf_detect:
        result = await p.run("original text")

    tfidf_detect.assert_called_once_with("original text")
    assert result.score == 0.0
