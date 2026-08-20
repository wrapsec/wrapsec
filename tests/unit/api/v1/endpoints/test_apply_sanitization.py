# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Sanitized proxy messages must be rewritten without disturbing their neighbours.

The failure this guards against: an earlier implementation scanned the messages
as one joined blob and split the sanitized result back apart on newlines, so any
message that itself contained a newline shifted the split and content was
remapped onto the wrong message. Replacements are now addressed by the message's
position, so a message's redactions can only ever land on that message.
"""

from api.v1.endpoints.proxy import _apply_sanitized_segments


def test_replacements_land_on_their_own_message():
    messages = [
        {"role": "user",      "content": "first line\nmy SSN is 123-45-6789"},
        {"role": "assistant", "content": "understood"},
        {"role": "user",      "content": "email me at alice@example.com"},
    ]

    out = _apply_sanitized_segments(messages, {
        0: "first line\nmy SSN is [SSN REDACTED]",
        2: "email me at [EMAIL REDACTED]",
    })

    # Each message keeps its own structure and gets only its own redaction.
    assert out[0]["content"].startswith("first line\n")
    assert "123-45-6789"      not in out[0]["content"]
    assert "alice@example.com" not in out[2]["content"]
    # No bleed between messages.
    assert "first line"  not in out[2]["content"]
    assert "123-45-6789" not in out[2]["content"]
    # A message that was not replaced is untouched.
    assert out[1]["content"] == "understood"


def test_an_assistant_message_can_be_rewritten():
    """Assistant turns are scanned, so they must also be sanitizable."""
    messages = [
        {"role": "user",      "content": "clean"},
        {"role": "assistant", "content": "my SSN is 123-45-6789"},
    ]

    out = _apply_sanitized_segments(messages, {1: "my SSN is [SSN REDACTED]"})

    assert out[1]["content"] == "my SSN is [SSN REDACTED]"
    assert out[0]["content"] == "clean"


def test_the_callers_list_is_not_mutated():
    messages = [{"role": "user", "content": "raw"}]

    out = _apply_sanitized_segments(messages, {0: "[REDACTED]"})

    assert out[0]["content"]      == "[REDACTED]"
    assert messages[0]["content"] == "raw"


def test_no_replacements_returns_the_messages_unchanged():
    messages = [{"role": "user", "content": "raw"}]
    assert _apply_sanitized_segments(messages, {}) is messages


def test_an_out_of_range_index_is_ignored():
    """A stale index must not raise or append a phantom message."""
    messages = [{"role": "user", "content": "raw"}]

    out = _apply_sanitized_segments(messages, {5: "nowhere"})

    assert len(out) == 1
    assert out[0]["content"] == "raw"
