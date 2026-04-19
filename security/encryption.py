"""
AES-256-GCM encryption for sensitive values stored in the database.
Used to encrypt provider API keys in proxy_provider_configs.

The encryption key is derived from settings.secret_key using PBKDF2.
The secret_key in .env must never change after provider keys are stored,
or all encrypted values will become unreadable.
"""

import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _derive_key(secret: str) -> bytes:
    """Derive a 32-byte AES-256 key from the application secret key."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        secret.encode(),
        b"wrapsec-proxy-enc-salt-v1",
        iterations=100_000,
        dklen=32,
    )


def encrypt(plaintext: str, secret_key: str) -> str:
    """
    Encrypt a plaintext string using AES-256-GCM.
    Returns a base64-encoded string: nonce (12 bytes) + ciphertext + GCM tag.
    Safe to store in the database.
    """
    key    = _derive_key(secret_key)
    nonce  = os.urandom(12)
    aesgcm = AESGCM(key)
    ct     = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("utf-8")


def decrypt(encrypted: str, secret_key: str) -> str:
    """
    Decrypt a value produced by encrypt().
    Raises ValueError if decryption fails (wrong key or tampered data).
    """
    try:
        raw    = base64.b64decode(encrypted.encode("utf-8"))
        nonce  = raw[:12]
        ct     = raw[12:]
        key    = _derive_key(secret_key)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ct, None).decode("utf-8")
    except Exception as exc:
        raise ValueError(
            "Decryption failed: data may be corrupt or key may have changed."
        ) from exc


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