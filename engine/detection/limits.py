# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Input-size caps for regex-based detectors.

Python's re module has no timeout facility, so a single adversarial payload
against a pattern with catastrophic backtracking can pin a worker thread
indefinitely. We defuse that by refusing to feed more than
MAX_REGEX_INPUT_LENGTH bytes into any regex detector. Anything past the cap
is silently truncated.

64 KiB is chosen because:
  * Typical prompts and completions are < 8 KiB. Legitimate documents,
    RAG chunks and pasted stack traces fit under 64 KiB.
  * Even a pathological O(2^n) pattern is bounded to a few seconds on
    64 KiB of input on modern hardware; larger inputs are what turn
    that into a minutes-or-hours DoS.

The cap is intentionally per-detector rather than global so that non-regex
layers (ML, transformer, LLM) can still see the full payload.
"""


MAX_REGEX_INPUT_LENGTH = 65536


def clamp_for_regex(text: str) -> str:
    if len(text) <= MAX_REGEX_INPUT_LENGTH:
        return text
    return text[:MAX_REGEX_INPUT_LENGTH]
