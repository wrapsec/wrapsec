# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Key Encryption Key (KEK) abstraction for envelope encryption.

Purpose:
  Envelope encryption gives every stored secret its own random Data
  Encryption Key (DEK). The DEK is wrapped by a single Key Encryption
  Key (KEK) and stored alongside the ciphertext. Rotating the KEK
  re-wraps the DEKs rather than re-encrypting every secret from scratch.

Design:
  KeyEncryptionKey is an abstract interface with wrap()/unwrap() methods.
  DerivedSecretKEK is the v1.1.0 default: KEK bytes come from PBKDF2 of
  SECRET_KEY, matching the pre-B3 encryption scheme so existing installs
  keep working without a manual KEK provisioning step.

Roadmap:
  v1.5+ will add KmsKEK (AWS KMS), CloudKmsKEK (GCP), VaultKEK (HashiCorp
  Vault). Callers use security.encryption.encrypt/decrypt, which route to
  the active KEK - no proxy_settings, no policy_resolver, no router change.
"""

from __future__ import annotations

import hashlib
import os
from abc import ABC, abstractmethod
from functools import lru_cache

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KeyEncryptionKey(ABC):
    """
    Wraps and unwraps Data Encryption Keys.

    Implementations must be deterministic across processes -- given the
    same configuration, wrap() must produce output that any process using
    the same KEK config can unwrap. That constraint is what lets the API,
    the workers, and any operator tool share access to encrypted secrets.
    """

    @abstractmethod
    def wrap(self, dek: bytes) -> bytes:
        """Encrypt a 32-byte DEK, return the wrapped bytes (opaque length)."""

    @abstractmethod
    def unwrap(self, wrapped: bytes) -> bytes:
        """Decrypt a previously wrapped DEK back to 32 raw bytes."""

    @property
    @abstractmethod
    def wrapped_length(self) -> int:
        """
        Number of bytes wrap() always produces. Envelope decoders use this
        to slice the wrapped-DEK prefix out of a ciphertext blob without
        needing a separate length field.
        """


class DerivedSecretKEK(KeyEncryptionKey):
    """
    KEK bytes derived from SECRET_KEY via PBKDF2-HMAC-SHA256.

    Salt and iteration count are identical to the pre-B3 direct-encrypt
    scheme, so a DEK wrapped here can be unwrapped by any process that
    holds the same SECRET_KEY. AES-256-GCM wraps the DEK with a fresh
    12-byte nonce; total wrapped length is deterministic (see WRAPPED_LEN).

    Derivation is deliberately expensive: PBKDF2 with 100,000 iterations costs
    around 20ms, which is the point of a password-based KDF.

    That makes CONSTRUCTION the thing to avoid repeating, not the wrap/unwrap
    calls. Use `derived_kek_for()` below rather than constructing this directly
    on a request path: an instance per call pays the 20ms every time, and this
    key is derived on every policy resolution carrying provider credentials and
    on every webhook signature.
    """

    _PBKDF2_SALT       = b"wrapsec-proxy-enc-salt-v1"
    _PBKDF2_ITERATIONS = 100_000
    _KEY_LEN           = 32   # AES-256
    _NONCE_LEN         = 12   # GCM standard
    _TAG_LEN           = 16   # GCM tag
    _DEK_LEN           = 32   # AES-256 DEK

    # nonce(12) + ct(dek_len) + tag(16)
    WRAPPED_LEN = _NONCE_LEN + _DEK_LEN + _TAG_LEN

    def __init__(self, secret_key: str) -> None:
        raw_key = hashlib.pbkdf2_hmac(
            "sha256",
            secret_key.encode("utf-8"),
            self._PBKDF2_SALT,
            iterations = self._PBKDF2_ITERATIONS,
            dklen      = self._KEY_LEN,
        )
        self._aesgcm = AESGCM(raw_key)

    def wrap(self, dek: bytes) -> bytes:
        if len(dek) != self._DEK_LEN:
            raise ValueError(f"DEK must be exactly {self._DEK_LEN} bytes")
        nonce = os.urandom(self._NONCE_LEN)
        ct    = self._aesgcm.encrypt(nonce, dek, None)
        return nonce + ct

    def unwrap(self, wrapped: bytes) -> bytes:
        if len(wrapped) != self.WRAPPED_LEN:
            raise ValueError("wrapped DEK has unexpected length")
        nonce = wrapped[: self._NONCE_LEN]
        ct    = wrapped[self._NONCE_LEN:]
        try:
            return self._aesgcm.decrypt(nonce, ct, None)
        except InvalidTag as exc:
            raise ValueError("KEK unwrap failed") from exc

    @property
    def wrapped_length(self) -> int:
        return self.WRAPPED_LEN


@lru_cache(maxsize=8)
def derived_kek_for(secret_key: str) -> DerivedSecretKEK:
    """A KEK for this secret, derived once and reused.

    The derivation is ~20ms of PBKDF2 and depends on nothing but the secret, so
    repeating it per call buys nothing. It was being repeated on every encrypt
    and every decrypt -- which put it on the policy-resolution path, where a
    tenant with stored provider credentials paid it on every request.

    KEYED BY THE SECRET, which is what makes rotation correct without an
    invalidation hook: a changed secret is a different key and therefore a
    different entry, so nothing stale is ever returned. Bounded, so a deployment
    that rotates repeatedly cannot grow this without limit.

    The derived key lives in process memory beside the secret it came from,
    which the process already holds; caching adds no exposure that was not
    already present.
    """
    return DerivedSecretKEK(secret_key)
