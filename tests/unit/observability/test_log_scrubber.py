# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
H7: refresh token log scrubber regression.

Refresh tokens must never appear verbatim in log streams. Design keeps the
raw value in the httpOnly cookie and only the SHA-256 hash in the DB - but
one careless `logger.info(response.headers)` or exception traceback that
embeds a Request/Response object leaks the token. These tests pin the
scrubber's behaviour so the defense-in-depth cannot regress silently.
"""

import io
import json
import logging

import pytest

from observability.logging import (
    JSONFormatter,
    SensitiveDataFilter,
    scrub_sensitive,
)

# ── scrub_sensitive ─────────────────────────────────────────────

@pytest.mark.parametrize("token", [
    "abcdef1234567890abcdef1234567890",
    "wsk_live_" + "z" * 40,
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.PAYLOAD.SIGNATURE",
])
def test_scrub_refresh_cookie_value(token: str):
    line = f"cookies: refresh_token={token}; Path=/v1/auth; HttpOnly"
    out  = scrub_sensitive(line)
    assert token not in out
    assert "refresh_token=[REDACTED]" in out
    assert "Path=/v1/auth" in out  # non-sensitive part preserved


def test_scrub_set_cookie_header_full_value():
    line = "Set-Cookie: refresh_token=SECRET-VALUE-HERE; Path=/v1/auth; HttpOnly"
    out  = scrub_sensitive(line)
    assert "SECRET-VALUE-HERE" not in out
    assert out.lower().startswith("set-cookie: [redacted]")


def test_scrub_bearer_authorization_header():
    line = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def"
    out  = scrub_sensitive(line)
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in out
    assert "Bearer [REDACTED]" in out


def test_scrub_short_bearer_not_matched():
    """8-char lower bound avoids clobbering benign 'bearer x' text."""
    assert scrub_sensitive("bearer x") == "bearer x"


def test_scrub_idempotent():
    text = "refresh_token=abcdef1234567890abcdef1234567890"
    once = scrub_sensitive(text)
    twice = scrub_sensitive(once)
    assert once == twice


def test_scrub_empty_string():
    assert scrub_sensitive("") == ""


def test_scrub_leaves_unrelated_text_unchanged():
    assert scrub_sensitive("hello world") == "hello world"


# ── SensitiveDataFilter on the logging pipeline ─────────────────

@pytest.fixture
def scrubbed_logger():
    """Attach the SensitiveDataFilter to a fresh logger + capturing handler."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JSONFormatter())

    log = logging.getLogger("test.scrubber.pipeline")
    log.setLevel(logging.DEBUG)
    log.propagate = False
    for h in list(log.handlers):
        log.removeHandler(h)
    log.addHandler(handler)
    for f in list(log.filters):
        log.removeFilter(f)
    log.addFilter(SensitiveDataFilter())

    yield log, stream

    for h in list(log.handlers):
        log.removeHandler(h)
    for f in list(log.filters):
        log.removeFilter(f)


def _last_json(stream: io.StringIO) -> dict:
    lines = [ln for ln in stream.getvalue().splitlines() if ln.strip()]
    return json.loads(lines[-1])


TOKEN = "xk9d8f7g6h5j4k3l2m1n0p9o8i7u6y5t4r3e2w1q"


def test_filter_redacts_refresh_token_in_message(scrubbed_logger):
    log, stream = scrubbed_logger
    log.info(f"outgoing response: Set-Cookie: refresh_token={TOKEN}; HttpOnly")
    entry = _last_json(stream)
    assert TOKEN not in entry["message"]
    assert TOKEN not in stream.getvalue()


def test_filter_redacts_refresh_token_via_lazy_args(scrubbed_logger):
    log, stream = scrubbed_logger
    log.info("cookie value = refresh_token=%s", TOKEN)
    entry = _last_json(stream)
    assert TOKEN not in entry["message"]
    assert TOKEN not in stream.getvalue()


def test_filter_redacts_bearer_in_exception_traceback(scrubbed_logger):
    log, stream = scrubbed_logger
    try:
        raise RuntimeError(f"upstream call failed: Authorization: Bearer {TOKEN}")
    except RuntimeError:
        log.exception("proxy failure")
    entry = _last_json(stream)
    assert TOKEN not in entry["exception"]
    assert TOKEN not in stream.getvalue()


def test_filter_does_not_break_records_that_have_no_secret(scrubbed_logger):
    log, stream = scrubbed_logger
    log.info("user %s logged in", "alice")
    entry = _last_json(stream)
    assert entry["message"] == "user alice logged in"


def test_filter_survives_broken_record(scrubbed_logger):
    """A record whose getMessage() raises must not take down the logger."""
    log, stream = scrubbed_logger

    class Bomb:
        def __str__(self) -> str:
            raise RuntimeError("boom")

    log.info("normal payload %s", Bomb())
    # No assertion beyond "the process is still standing".
