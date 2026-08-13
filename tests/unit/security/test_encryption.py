# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Regression tests for security.encryption.

This module encrypts provider API keys (OpenAI, Groq, etc.) at rest in
proxy_provider_configs. A regression here means either:

  - keys get decrypted with the wrong secret and silently return corrupted
    strings (which then fail auth against the provider), or
  - a tampered ciphertext is accepted, defeating the point of GCM's
    authentication tag.

These tests lock in six invariants:

  1. Round-trip works for common inputs (ASCII, unicode, long keys).
  2. Every ciphertext is unique (fresh nonce) even for identical plaintext -
     otherwise the same DB write leaks equality of the underlying secrets.
  3. Wrong secret raises ValueError, never returns garbage.
  4. Tampered ciphertext raises ValueError (GCM auth tag catches it).
  5. Malformed input (invalid base64, truncated blob) raises ValueError.
  6. mask() never leaks the middle of a secret.
"""

import base64

import pytest

from security.encryption import decrypt, encrypt, mask

SECRET = "a" * 32   # matches SECRET_KEY min length in production settings


# ── round-trip ───────────────────────────────────────────────────────────────

def test_roundtrip_ascii():
    plaintext = "sk-proj-abcdefghijklmnop"
    ct        = encrypt(plaintext, SECRET)
    assert ct != plaintext
    assert decrypt(ct, SECRET) == plaintext


def test_roundtrip_empty_string():
    """An empty provider key should still round-trip cleanly."""
    ct = encrypt("", SECRET)
    assert decrypt(ct, SECRET) == ""


def test_roundtrip_unicode():
    """
    Provider display names or descriptions may contain unicode - the encrypt
    codepath uses .encode('utf-8'), so a codec bug here would silently
    mangle multibyte chars on decrypt.
    """
    plaintext = "clef-secrete-éàü-\U0001f511"
    ct        = encrypt(plaintext, SECRET)
    assert decrypt(ct, SECRET) == plaintext


def test_roundtrip_long_input():
    """
    Some provider keys are long (256+ chars). Length correctness matters
    because a truncation bug would break auth without an obvious symptom.
    """
    plaintext = "K" * 4096
    ct        = encrypt(plaintext, SECRET)
    assert decrypt(ct, SECRET) == plaintext


# ── nonce uniqueness ────────────────────────────────────────────────────────

def test_two_encryptions_of_same_plaintext_differ():
    """
    Encrypting the same plaintext twice MUST produce different ciphertexts.
    If the nonce were static, an attacker with DB read access could tell
    which providers share the same key just by comparing ciphertext.
    """
    plaintext = "sk-abc123"
    ct1 = encrypt(plaintext, SECRET)
    ct2 = encrypt(plaintext, SECRET)
    assert ct1 != ct2
    # Both must still decrypt to the same plaintext.
    assert decrypt(ct1, SECRET) == plaintext
    assert decrypt(ct2, SECRET) == plaintext


def test_ciphertext_uses_v2_envelope_prefix():
    """
    v1.1.0 (B3) always emits v2-format envelope ciphertext. Callers that
    grep the DB for legacy 'v1' rows rely on the marker to decide what
    still needs migrating.
    """
    ct = encrypt("sk-abc123", SECRET)
    assert ct.startswith("v2:")


def test_ciphertext_body_is_valid_base64():
    """
    The body after the 'v2:' marker is base64. Any bug that produces raw
    bytes would break psycopg TEXT-column inserts.
    """
    ct   = encrypt("sk-abc123", SECRET)
    body = ct[len("v2:"):]
    # Must decode without error - proves valid base64.
    base64.b64decode(body.encode("utf-8"))


def test_v2_ciphertext_carries_wrapped_dek_plus_gcm_frame():
    """
    v2 layout: wrapped_dek(60) + nonce(12) + ciphertext + tag(16).
    Guards against a silent frame-size change that would prevent decrypt.
    """
    from security.kek import DerivedSecretKEK
    ct   = encrypt("hi", SECRET)
    raw  = base64.b64decode(ct[len("v2:"):].encode("utf-8"))
    assert len(raw) >= DerivedSecretKEK.WRAPPED_LEN + 12 + 16


# ── wrong key ────────────────────────────────────────────────────────────────

def test_decrypt_wrong_key_raises_valueerror():
    """
    A rotated SECRET_KEY must not silently decrypt old ciphertext into
    garbage - callers rely on the raised ValueError to surface the rotation
    problem to operators.
    """
    ct = encrypt("sk-abc123", SECRET)
    with pytest.raises(ValueError):
        decrypt(ct, secret_key="b" * 32)


def test_decrypt_wrong_key_error_message_is_generic():
    """
    Error must not distinguish 'wrong key' from 'tampered ciphertext' -
    that distinction would leak which secret_key the server currently uses
    to any caller that can trigger a decrypt error.
    """
    ct = encrypt("sk-abc123", SECRET)
    with pytest.raises(ValueError) as ei:
        decrypt(ct, secret_key="b" * 32)
    # Same message as the tamper case (see next test).
    assert "Decryption failed" in str(ei.value)


# ── tampering ────────────────────────────────────────────────────────────────

def _v2_body_bytes(ct: str) -> bytearray:
    """Helper: base64-decode the body of a v2 ciphertext into a mutable buffer."""
    return bytearray(base64.b64decode(ct[len("v2:"):].encode("utf-8")))


def _reassemble_v2(raw: bytes) -> str:
    return "v2:" + base64.b64encode(bytes(raw)).decode("utf-8")


def test_decrypt_tampered_ciphertext_raises():
    """
    GCM authentication tag must catch any modification to the ciphertext.
    Flip one byte in the middle - decrypt must raise, not silently return
    corrupted plaintext.
    """
    from security.kek import DerivedSecretKEK
    ct  = encrypt("sk-abc123", SECRET)
    raw = _v2_body_bytes(ct)
    # Flip a byte inside the ciphertext region (after wrapped_dek + nonce).
    offset = DerivedSecretKEK.WRAPPED_LEN + 12 + 3
    raw[offset] ^= 0xFF
    with pytest.raises(ValueError):
        decrypt(_reassemble_v2(raw), SECRET)


def test_decrypt_tampered_nonce_raises():
    """
    Flipping a byte in the per-record nonce also breaks decryption.
    """
    from security.kek import DerivedSecretKEK
    ct  = encrypt("sk-abc123", SECRET)
    raw = _v2_body_bytes(ct)
    raw[DerivedSecretKEK.WRAPPED_LEN] ^= 0xFF   # first byte of nonce
    with pytest.raises(ValueError):
        decrypt(_reassemble_v2(raw), SECRET)


def test_decrypt_tampered_wrapped_dek_raises():
    """
    Tampering with the wrapped DEK must fail at KEK unwrap - a separate
    integrity boundary from the data-key GCM tag.
    """
    ct  = encrypt("sk-abc123", SECRET)
    raw = _v2_body_bytes(ct)
    raw[0] ^= 0xFF   # inside the wrapped-DEK prefix
    with pytest.raises(ValueError):
        decrypt(_reassemble_v2(raw), SECRET)


def test_decrypt_tampered_gcm_tag_raises():
    """The GCM tag is the last 16 bytes. Flipping there must raise."""
    ct  = encrypt("sk-abc123", SECRET)
    raw = _v2_body_bytes(ct)
    raw[-1] ^= 0xFF
    with pytest.raises(ValueError):
        decrypt(_reassemble_v2(raw), SECRET)


# ── malformed input ─────────────────────────────────────────────────────────

def test_decrypt_invalid_base64_raises_valueerror():
    """
    A caller passing raw (non-base64) input must get ValueError, not
    binascii.Error - the wrapping is what lets services layer catch it
    uniformly.
    """
    with pytest.raises(ValueError):
        decrypt("!!!not-base64!!!", SECRET)


def test_decrypt_too_short_input_raises_valueerror():
    """
    A blob shorter than the nonce (12 bytes) can't possibly be valid.
    Must raise ValueError rather than crashing inside AESGCM.decrypt.
    """
    short = base64.b64encode(b"tiny").decode("utf-8")
    with pytest.raises(ValueError):
        decrypt(short, SECRET)


# ── v1 backward compat ──────────────────────────────────────────────────────

def _make_v1_ciphertext(plaintext: str, secret_key: str) -> str:
    """
    Reproduce the pre-v1.1.0 single-key AES-GCM format so we can prove
    decrypt() still reads rows written before B3.
    """
    import hashlib
    import os

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = hashlib.pbkdf2_hmac(
        "sha256",
        secret_key.encode("utf-8"),
        b"wrapsec-proxy-enc-salt-v1",
        iterations=100_000,
        dklen=32,
    )
    nonce = os.urandom(12)
    ct    = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("utf-8")


def test_decrypt_reads_legacy_v1_ciphertext():
    """
    Provider keys written before v1.1.0 have no 'v2:' marker. decrypt()
    must still return the plaintext so existing installs keep working
    while the Alembic re-encrypt migration hasn't landed yet.
    """
    v1 = _make_v1_ciphertext("sk-legacy-key-1234", SECRET)
    assert not v1.startswith("v2:")
    assert decrypt(v1, SECRET) == "sk-legacy-key-1234"


def test_decrypt_v1_wrong_key_raises():
    """Legacy path must also raise on wrong key, not return garbage."""
    v1 = _make_v1_ciphertext("sk-legacy", SECRET)
    with pytest.raises(ValueError):
        decrypt(v1, secret_key="c" * 32)


# ── mask() ───────────────────────────────────────────────────────────────────

def test_mask_hides_middle_of_secret():
    """
    Dashboard displays masked keys. Must show first 4 + last 4, never the
    middle. Any leak of the middle segment defeats the point of masking.
    """
    plaintext = "sk-abcdefghijklmnop"
    masked    = mask(plaintext)
    assert masked.startswith("sk-a")
    assert masked.endswith("mnop")
    assert "defghijklm" not in masked
    assert "..." in masked


def test_mask_short_input_returns_stars_only():
    """
    For inputs <= 8 chars, showing first-4 / last-4 would leak most of the
    secret. mask() returns fixed asterisks instead.
    """
    assert mask("short")    == "****"
    assert mask("12345678") == "****"
    assert mask("")         == "****"


def test_mask_boundary_at_nine_chars():
    """
    Exactly 9 characters is the smallest input that shows first-4 + last-4.
    Guards against an off-by-one that would either leak a short key or
    fail to mask a 9-char secret.
    """
    masked = mask("123456789")
    assert masked == "1234...6789"
