# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests for security/webhook_signing.py

Covers the sign/build_headers/verify contract, rotation, and the
replay-window guard. No I/O, no DB.
"""
from __future__ import annotations

import base64
import hmac
from hashlib import sha256

import pytest

from security.webhook_signing import (
    DEFAULT_TIMESTAMP_TOLERANCE_S,
    SIGNATURE_VERSION,
    build_headers,
    sign,
    verify,
)


SECRET_A = b"secret-active-1234567890"
SECRET_B = b"secret-old-abcdefghijklm"
SECRET_C = b"unrelated-key-xyz"

MSG_ID   = "msg_01HXYZ"
BODY     = b'{"event":"wrapsec.request.blocked","severity":"CRITICAL"}'
TS       = 1_753_500_000


def test_sign_matches_manual_hmac() -> None:
    """
    The wire format must be reproducible by a receiver that only knows
    the shared secret and the three headers. Compute it by hand.
    """
    signed_string = f"{MSG_ID}.{TS}.".encode("utf-8") + BODY
    expected      = "v1," + base64.b64encode(
        hmac.new(SECRET_A, signed_string, sha256).digest()
    ).decode("ascii")

    assert sign(SECRET_A, MSG_ID, TS, BODY) == expected


def test_sign_is_deterministic() -> None:
    assert sign(SECRET_A, MSG_ID, TS, BODY) == sign(SECRET_A, MSG_ID, TS, BODY)


def test_sign_diverges_on_any_input_change() -> None:
    baseline = sign(SECRET_A, MSG_ID, TS, BODY)
    assert baseline != sign(SECRET_B, MSG_ID, TS, BODY)      # secret
    assert baseline != sign(SECRET_A, "other", TS, BODY)     # id
    assert baseline != sign(SECRET_A, MSG_ID, TS + 1, BODY)  # timestamp
    assert baseline != sign(SECRET_A, MSG_ID, TS, BODY + b"x")  # body


def test_build_headers_shape() -> None:
    headers = build_headers([SECRET_A], MSG_ID, BODY, timestamp=TS)
    assert set(headers) == {"webhook-id", "webhook-timestamp", "webhook-signature"}
    assert headers["webhook-id"]        == MSG_ID
    assert headers["webhook-timestamp"] == str(TS)
    assert headers["webhook-signature"].startswith(f"{SIGNATURE_VERSION},")


def test_build_headers_rotation_emits_multiple_signatures() -> None:
    """
    During rotation the emitter passes [active, old_unexpired] and
    both signatures must appear space-separated in the header.
    """
    headers = build_headers([SECRET_A, SECRET_B], MSG_ID, BODY, timestamp=TS)
    parts   = headers["webhook-signature"].split(" ")

    assert len(parts) == 2
    assert parts[0] == sign(SECRET_A, MSG_ID, TS, BODY)
    assert parts[1] == sign(SECRET_B, MSG_ID, TS, BODY)


def test_build_headers_defaults_timestamp_to_now() -> None:
    import time
    before  = int(time.time())
    headers = build_headers([SECRET_A], MSG_ID, BODY)
    after   = int(time.time())

    ts = int(headers["webhook-timestamp"])
    assert before <= ts <= after


def test_build_headers_rejects_empty_secrets() -> None:
    with pytest.raises(ValueError):
        build_headers([], MSG_ID, BODY, timestamp=TS)


def test_verify_accepts_own_signature() -> None:
    headers = build_headers([SECRET_A], MSG_ID, BODY, timestamp=TS)
    assert verify(
        [SECRET_A],
        MSG_ID,
        headers["webhook-timestamp"],
        headers["webhook-signature"],
        BODY,
        now = TS,
    )


def test_verify_accepts_signature_from_any_provided_secret() -> None:
    """
    Receiver may hold [current, old]; either should verify a delivery
    that was signed with one of them.
    """
    headers = build_headers([SECRET_B], MSG_ID, BODY, timestamp=TS)  # signed with old
    assert verify(
        [SECRET_A, SECRET_B],  # receiver tries current then old
        MSG_ID,
        headers["webhook-timestamp"],
        headers["webhook-signature"],
        BODY,
        now = TS,
    )


def test_verify_rejects_wrong_secret() -> None:
    headers = build_headers([SECRET_A], MSG_ID, BODY, timestamp=TS)
    assert not verify(
        [SECRET_C],
        MSG_ID,
        headers["webhook-timestamp"],
        headers["webhook-signature"],
        BODY,
        now = TS,
    )


def test_verify_rejects_tampered_body() -> None:
    headers = build_headers([SECRET_A], MSG_ID, BODY, timestamp=TS)
    assert not verify(
        [SECRET_A],
        MSG_ID,
        headers["webhook-timestamp"],
        headers["webhook-signature"],
        BODY + b" tampered",
        now = TS,
    )


def test_verify_rejects_wrong_msg_id() -> None:
    headers = build_headers([SECRET_A], MSG_ID, BODY, timestamp=TS)
    assert not verify(
        [SECRET_A],
        "different_msg",
        headers["webhook-timestamp"],
        headers["webhook-signature"],
        BODY,
        now = TS,
    )


def test_verify_rejects_stale_timestamp() -> None:
    """
    Signature is technically valid but timestamp is outside the replay
    window. This defeats capture-and-replay attacks even if the attacker
    has a real signature.
    """
    headers = build_headers([SECRET_A], MSG_ID, BODY, timestamp=TS)
    stale   = TS + DEFAULT_TIMESTAMP_TOLERANCE_S + 1
    assert not verify(
        [SECRET_A],
        MSG_ID,
        headers["webhook-timestamp"],
        headers["webhook-signature"],
        BODY,
        now = stale,
    )


def test_verify_accepts_at_tolerance_edge() -> None:
    headers = build_headers([SECRET_A], MSG_ID, BODY, timestamp=TS)
    assert verify(
        [SECRET_A],
        MSG_ID,
        headers["webhook-timestamp"],
        headers["webhook-signature"],
        BODY,
        now = TS + DEFAULT_TIMESTAMP_TOLERANCE_S,
    )


def test_verify_rejects_future_timestamp_beyond_tolerance() -> None:
    """
    Clock-skew both directions must be bounded. A signature dated well
    in the future is as suspicious as one in the distant past.
    """
    headers = build_headers([SECRET_A], MSG_ID, BODY, timestamp=TS)
    assert not verify(
        [SECRET_A],
        MSG_ID,
        headers["webhook-timestamp"],
        headers["webhook-signature"],
        BODY,
        now = TS - DEFAULT_TIMESTAMP_TOLERANCE_S - 1,
    )


def test_verify_returns_false_on_malformed_timestamp() -> None:
    assert not verify(
        [SECRET_A],
        MSG_ID,
        "not-a-number",
        "v1,AAAA",
        BODY,
        now = TS,
    )


def test_verify_returns_false_on_malformed_signature() -> None:
    assert not verify(
        [SECRET_A],
        MSG_ID,
        str(TS),
        "v1,not!!!base64",
        BODY,
        now = TS,
    )


def test_verify_returns_false_on_empty_secrets() -> None:
    headers = build_headers([SECRET_A], MSG_ID, BODY, timestamp=TS)
    assert not verify(
        [],
        MSG_ID,
        headers["webhook-timestamp"],
        headers["webhook-signature"],
        BODY,
        now = TS,
    )


def test_verify_ignores_unknown_version_prefix() -> None:
    """
    A future v2 entry must not crash a v1-only receiver -- it just
    doesn't match. Mixed headers stay backward compatible.
    """
    v1_sig  = sign(SECRET_A, MSG_ID, TS, BODY)
    mixed   = f"v2,fake-future-signature {v1_sig}"

    assert verify([SECRET_A], MSG_ID, str(TS), mixed, BODY, now=TS)
