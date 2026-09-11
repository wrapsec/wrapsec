# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Constant-time comparison of caller-supplied credential material.

`hmac.compare_digest` accepts str only when BOTH operands are ASCII. Given
anything else it raises:

    TypeError: comparing strings with non-ASCII characters is not supported

The presented half of these comparisons is a request header, so its content is
chosen by the caller. An unauthenticated request carrying `x-api-key: café`
therefore turned a credential check into an unhandled exception -- answered as a
500 with a traceback in the logs, where the correct answer is an ordinary
authentication failure. It fails in the safe direction (nothing is
authenticated) but it is still a defect: an anonymous caller can generate
server errors and log volume at will, and a malformed credential is a 401, not
an internal error.

The fix compares BYTES. That is the canonical use of `compare_digest` -- the
str form is the special case, not the other way round -- so the constant-time
property is preserved exactly. Nothing here short-circuits, lowers to `==`, or
inspects the values before comparing.

Encoding is UTF-8 with `surrogateescape`, so even a header carrying bytes that
are not valid UTF-8 (which a framework may hand over as lone surrogates) is
comparable rather than raising a second, different exception on encode.
"""

from __future__ import annotations

import hmac


def constant_time_equals(presented: str | bytes | None, expected: str | bytes | None) -> bool:
    """True when both are present and equal, compared in constant time.

    A missing or empty `expected` is False rather than a comparison: there is no
    secret to match, and calling `compare_digest` against an empty value would
    authenticate an empty credential.
    """
    if not presented or not expected:
        return False

    return hmac.compare_digest(_as_bytes(presented), _as_bytes(expected))


def _as_bytes(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8", "surrogateescape")
