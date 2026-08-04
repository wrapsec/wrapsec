# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Detection-side consumer of engine.normalization.

Runs a single detector across a NormalizedInput's canonical form plus its
decode-views and returns the strongest signal (highest score). This is the
"scan every representation, take the max" pattern used by mature security
filters (cf. WAF transformation pipelines): obfuscation that slips past the raw
text is caught on the canonical form or a decoded view.

Dependency direction runs detection -> normalization, never the reverse: this
module imports only the NormalizedInput value type. It performs no policy
decision and mutates nothing -- it selects the max-scoring DetectionResult the
supplied detector already produced.
"""

from __future__ import annotations

from typing import Awaitable, Callable

from engine.detection.base import DetectionResult
from engine.normalization import NormalizedInput


async def evaluate_views(
    scan_one: Callable[[str], Awaitable[DetectionResult]],
    ni: NormalizedInput,
) -> DetectionResult:
    """Scan the canonical text and every decode-view with `scan_one`, returning
    the highest-scoring DetectionResult.

    The canonical result is kept on ties (strict `>`), so a view is credited
    only when it strictly raises the score -- no view is blamed for a signal the
    canonical text already carried. With no views this is exactly one call, so
    benign traffic pays no extra detection pass.

    `scan_one` adapts any detector to a uniform `str -> await DetectionResult`
    shape; the caller wraps a sync detector (e.g. via asyncio.to_thread) or
    passes an async one directly. The callable must not raise (detectors return
    DetectionResult.clean() on failure); this function adds no error handling of
    its own and leaves the caller's existing timeout/fail-closed wrapping intact.
    """
    texts = ni.texts()               # canonical first, then views (canonical always present)
    best = await scan_one(texts[0])
    for text in texts[1:]:
        result = await scan_one(text)
        if result.score > best.score:
            best = result
    return best
