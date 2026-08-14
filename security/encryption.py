# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
AES-256-GCM envelope encryption for sensitive values stored in the database.

Every ciphertext carries its own random Data Encryption Key (DEK), wrapped by a
Key Encryption Key (KEK). The KEK is currently derived from SECRET_KEY (see
security.kek.DerivedSecretKEK); the abstraction lets a KMS/HSM or per-tenant KEK
arrive later without any call-site change.

Wire format (single, final -- D3):
    "<key_id>:" + base64(wrapped_dek || nonce || ciphertext || tag)

key_id is "primary" (the SECRET_KEY-derived KEK). decrypt() dispatches on key_id
and raises ValueError on an unknown id -- THAT is the seam: a future per-tenant or
KMS KEK registers a new key_id and decrypt() routes to it, with no re-encryption
campaign and no format flag day. There is deliberately no legacy v1/v2 decode
branch: this is a greenfield with no pre-existing ciphertexts, so a value that does
not carry a recognized key_id is treated as corrupt, not silently reinterpreted.
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

# The one key id emitted today. New key ids (per-tenant, KMS) are added here and
# routed in decrypt(); the wire format never changes.
_PRIMARY_KEY_ID = "primary"


def encrypt(plaintext: str, secret_key: str) -> str:
    """
    Envelope-encrypt a plaintext string. Returns "<key_id>:<base64 payload>" with
    key_id="primary". Safe to store in the database.
    """
    kek         = DerivedSecretKEK(secret_key)
    dek         = os.urandom(_DEK_LEN)
    wrapped_dek = kek.wrap(dek)

    nonce = os.urandom(_NONCE_LEN)
    ct    = AESGCM(dek).encrypt(nonce, plaintext.encode("utf-8"), None)

    payload = wrapped_dek + nonce + ct
    return _PRIMARY_KEY_ID + ":" + base64.b64encode(payload).decode("utf-8")


def decrypt(encrypted: str, secret_key: str) -> str:
    """
    Decrypt a value produced by encrypt(). Dispatches on the leading key_id.
    Raises ValueError on an unknown key_id, wrong key, tampered ciphertext, or
    malformed input -- callers rely on that single exception type.
    """
    key_id, sep, b64_payload = encrypted.partition(":")
    if not sep:
        raise ValueError("Decryption failed: value carries no key id.")
    if key_id != _PRIMARY_KEY_ID:
        raise ValueError(f"Decryption failed: unknown key id '{key_id}'.")
    try:
        return _decrypt_primary(b64_payload, secret_key)
    except (InvalidTag, ValueError, binascii.Error) as exc:
        raise ValueError(
            "Decryption failed: data may be corrupt or key may have changed."
        ) from exc


def _decrypt_primary(b64_payload: str, secret_key: str) -> str:
    raw = base64.b64decode(b64_payload.encode("utf-8"))
    kek = DerivedSecretKEK(secret_key)
    wrapped_len = kek.wrapped_length
    if len(raw) < wrapped_len + _NONCE_LEN + _TAG_LEN:
        raise ValueError("ciphertext too short")

    wrapped_dek = raw[:wrapped_len]
    nonce       = raw[wrapped_len : wrapped_len + _NONCE_LEN]
    ct          = raw[wrapped_len + _NONCE_LEN :]

    dek = kek.unwrap(wrapped_dek)
    return AESGCM(dek).decrypt(nonce, ct, None).decode("utf-8")


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
