# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""The gateway's side of the WrapSec detection API.

One place where content is judged, so every boundary the gateway protects
reaches the same decision path with the same failure behaviour.

FAIL CLOSED, AND FOR THE RIGHT REASON. If the API is unreachable, times out, or
returns a system error, the content has NOT been inspected. The gateway cannot
tell a clean payload from a hostile one at that point, and forwarding it would
mean the security control was optional all along. Every failure here becomes a
block, and the decision records that it was a failure rather than a verdict, so
an operator can tell "we judged this dangerous" from "we could not judge it".

SIZE IS A SECURITY LIMIT, NOT A TRUNCATION INSTRUCTION. Content past the bound
is blocked rather than partially scanned. Scanning the first N characters and
forwarding the whole thing reports a verdict that does not cover what was sent,
which is worse than no verdict because it looks like one.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Protocol

logger = logging.getLogger(__name__)

# What the caller asked us to judge, in the vocabulary the detection API uses for
# provenance. A tool definition and a tool result are both content the gateway
# did not author, and they are classified as such so the posture layer can judge
# them more strictly than something a user typed.
SOURCE_TOOL_DEFINITION = "external_content"
SOURCE_TOOL_RESULT     = "tool_output"
SOURCE_TOOL_ARGUMENT   = "user_prompt"


@dataclass(frozen=True)
class Verdict:
    """One decision about one piece of content."""

    blocked:   bool
    sanitized: str | None
    reason:    str
    trace_id:  str
    # True when the gateway could not obtain a verdict at all. Distinct from a
    # BLOCK: one says the content is dangerous, the other says the control did
    # not run. Both refuse; only one is evidence about the content.
    failed:    bool = False

    @property
    def allowed(self) -> bool:
        return not self.blocked


class ScannerProtocol(Protocol):
    """What an interceptor needs. Kept narrow so tests can supply their own."""

    async def scan(self, text: str, *, source: str, trace_id: str) -> Verdict: ...


class Scanner:
    """Scans through the WrapSec API using the existing client."""

    def __init__(self, client: Any, *, mode: str = "fast", max_chars: int = 8000) -> None:
        self._client    = client
        self._mode      = mode
        self._max_chars = max_chars

    async def scan(self, text: str, *, source: str, trace_id: str) -> Verdict:
        if not text:
            # Nothing to judge. Not a failure, and not a block: an empty
            # description is not evidence of anything.
            return Verdict(blocked=False, sanitized=None, reason="NO_CONTENT", trace_id=trace_id)

        if len(text) > self._max_chars:
            logger.warning(
                "content of %d characters exceeds the %d-character scan bound; blocking "
                "(trace %s)", len(text), self._max_chars, trace_id,
            )
            return Verdict(
                blocked=True, sanitized=None, reason="CONTENT_TOO_LARGE",
                trace_id=trace_id, failed=True,
            )

        try:
            result = await self._client.scan(
                text, mode=self._mode, input_source=source,
            )
        except Exception as exc:
            # Unreachable, timed out, refused: the content is unjudged.
            logger.error("scan failed, blocking unjudged content (trace %s): %s", trace_id, exc)
            return Verdict(
                blocked=True, sanitized=None, reason="SYSTEM_ERROR",
                trace_id=trace_id, failed=True,
            )

        return _verdict_from(result, trace_id)


def _verdict_from(result: Any, trace_id: str) -> Verdict:
    """Translate a scan result into the gateway's own terms.

    The API reports a detector fault on the result rather than raising, so that
    flag has to be read. Without it a failed scan arrives looking like a clean
    one, which is the failure mode this whole module exists to avoid.
    """
    reported = getattr(result, "trace_id", None) or trace_id

    if getattr(result, "is_system_error", None) and result.is_system_error():
        return Verdict(blocked=True, sanitized=None, reason="SYSTEM_ERROR",
                       trace_id=reported, failed=True)

    if getattr(result, "is_blocked", None) and result.is_blocked():
        return Verdict(blocked=True, sanitized=None,
                       reason=getattr(result, "primary_reason", "BLOCKED") or "BLOCKED",
                       trace_id=reported)

    sanitized = None
    if getattr(result, "is_sanitized", None) and result.is_sanitized():
        sanitized = getattr(result, "sanitized_input", None)

    return Verdict(blocked=False, sanitized=sanitized,
                   reason=getattr(result, "primary_reason", "ALLOWED") or "ALLOWED",
                   trace_id=reported)
