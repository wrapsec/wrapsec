# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
AES-256-GCM envelope encryption for sensitive values stored in the database.

v1.0.x used a single AES key derived from SECRET_KEY to encrypt every
value directly ("v1 format"). v1.1.0 introduces envelope encryption
(B3): every ciphertext carries its own random Data Encryption Key (DEK),
wrapped by a Key Encryption Key (KEK). The KEK is currently derived
from SECRET_KEY (see security.kek.DerivedSecretKEK) but the abstraction
lets v1.5+ swap in AWS KMS, GCP KMS, or HashiCorp Vault without any
call-site change.

Wire format:
  v2:  b"v2" || wrapped_dek(60) || nonce(12) || ciphertext || tag(16)
       whole payload base64-encoded, with a leading "v2:" ASCII marker
       so the format is greppable in the DB.
  v1:  base64(nonce(12) || ciphertext || tag(16))     -- legacy, still readable

New writes always emit v2. Reads auto-detect by prefix, so existing
provider keys keep working through the transition. Alembic migration
0002 re-encrypts existing v1 rows into v2 on upgrade.
"""

from __future__ import annotations

import base64
import binascii
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from security.kek import DerivedSecretKEK

_NONCE_LEN = 12
_TAG_LEN   = 16
_DEK_LEN   = 32
_V2_PREFIX = "v2:"


def encrypt(plaintext: str, secret_key: str) -> str:
    """
    Envelope-encrypt a plaintext string. Returns a v2-format ciphertext:
    a "v2:" prefix followed by a base64 blob containing the wrapped DEK
    and the AES-256-GCM ciphertext. Safe to store in the database.
    """
    kek         = DerivedSecretKEK(secret_key)
    dek         = os.urandom(_DEK_LEN)
    wrapped_dek = kek.wrap(dek)

    nonce = os.urandom(_NONCE_LEN)
    ct    = AESGCM(dek).encrypt(nonce, plaintext.encode("utf-8"), None)

    payload = wrapped_dek + nonce + ct
    return _V2_PREFIX + base64.b64encode(payload).decode("utf-8")


def decrypt(encrypted: str, secret_key: str) -> str:
    """
    Decrypt a value produced by encrypt() (v2) or the pre-v1.1.0 direct
    scheme (v1). Raises ValueError on wrong key, tampered ciphertext, or
    malformed input -- callers rely on that single exception type.
    """
    try:
        if encrypted.startswith(_V2_PREFIX):
            return _decrypt_v2(encrypted[len(_V2_PREFIX):], secret_key)
        return _decrypt_v1(encrypted, secret_key)
    except (InvalidTag, ValueError, binascii.Error) as exc:
        raise ValueError(
            "Decryption failed: data may be corrupt or key may have changed."
        ) from exc


def _decrypt_v2(b64_payload: str, secret_key: str) -> str:
    raw = base64.b64decode(b64_payload.encode("utf-8"))
    kek = DerivedSecretKEK(secret_key)
    wrapped_len = kek.wrapped_length
    if len(raw) < wrapped_len + _NONCE_LEN + _TAG_LEN:
        raise ValueError("v2 ciphertext too short")

    wrapped_dek = raw[:wrapped_len]
    nonce       = raw[wrapped_len : wrapped_len + _NONCE_LEN]
    ct          = raw[wrapped_len + _NONCE_LEN :]

    dek = kek.unwrap(wrapped_dek)
    return AESGCM(dek).decrypt(nonce, ct, None).decode("utf-8")


def _decrypt_v1(encrypted: str, secret_key: str) -> str:
    """Legacy path: single-key AES-GCM. Kept so pre-v1.1.0 rows still read."""
    import hashlib
    raw   = base64.b64decode(encrypted.encode("utf-8"))
    if len(raw) < _NONCE_LEN + _TAG_LEN:
        raise ValueError("v1 ciphertext too short")
    nonce = raw[:_NONCE_LEN]
    ct    = raw[_NONCE_LEN:]
    key   = hashlib.pbkdf2_hmac(
        "sha256",
        secret_key.encode("utf-8"),
        b"wrapsec-proxy-enc-salt-v1",
        iterations=100_000,
        dklen=32,
    )
    return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")


def mask(plaintext: str) -> str:
    """
    Return a masked version of a secret for safe display.
    Shows first 4 and last 4 characters with ... in the middle.

    Examples:
        "sk-abcdefghijklmnop"  ->  "sk-a...mnop"
        "short"                ->  "****"
    """
    if len(plaintext) <= 8:
        return "****"
    return plaintext[:4] + "..." + plaintext[-4:]
