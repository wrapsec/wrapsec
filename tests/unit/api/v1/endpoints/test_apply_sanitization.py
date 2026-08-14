# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
B4: proxy scan-all sanitization must preserve per-message boundaries even when a
user message contains embedded newlines. The old implementation split the joined
sanitized blob by "\\n" and remapped positionally, which corrupted content when
any message itself had a newline. The fix re-redacts each user message
independently.
"""

from api.v1.endpoints.proxy import _apply_sanitization


def test_scan_all_preserves_boundaries_with_multiline_messages():
    messages = [
        {"role": "user",      "content": "first line\nmy SSN is 123-45-6789"},  # multiline + PII
        {"role": "assistant", "content": "understood"},
        {"role": "user",      "content": "email me at alice@example.com"},
    ]
    out = _apply_sanitization(messages, sanitized="unused-for-scan-all", scan_all=True)

    # Message 0 keeps its own newline/structure; its PII is redacted in place.
    assert out[0]["content"].startswith("first line\n")
    assert "123-45-6789" not in out[0]["content"]
    # Message 2 is redacted independently; message 0's content did NOT bleed into it.
    assert "alice@example.com" not in out[2]["content"]
    assert "first line" not in out[2]["content"]
    assert "123-45-6789" not in out[2]["content"]
    # Non-user messages are untouched.
    assert out[1]["content"] == "understood"
    # The original list is not mutated (deep copy).
    assert messages[0]["content"] == "first line\nmy SSN is 123-45-6789"


def test_scan_last_only_replaces_last_user_message():
    messages = [
        {"role": "user",      "content": "clean history"},
        {"role": "assistant", "content": "ok"},
        {"role": "user",      "content": "raw last message"},
    ]
    out = _apply_sanitization(messages, sanitized="[REDACTED] last message", scan_all=False)
    assert out[2]["content"] == "[REDACTED] last message"
    assert out[0]["content"] == "clean history"   # earlier messages untouched
