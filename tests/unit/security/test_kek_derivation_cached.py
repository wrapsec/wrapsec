# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""The key-encryption key is derived once per secret, not once per call.

Derivation is PBKDF2 with 100,000 iterations -- about 20ms, deliberately. That
cost is correct for a password-based KDF and wrong to pay repeatedly: it depends
on nothing but the secret.

It was being paid on every encrypt and every decrypt, which put it on the
policy-resolution path. A tenant with stored provider credentials paid it on
every request, and webhook signing paid it per delivery.

These assert the NUMBER OF DERIVATIONS rather than elapsed time. A timing
assertion would measure the machine as much as the code and would fail on a
loaded runner; counting derivations states the property directly.
"""

from __future__ import annotations

import pytest

from security.encryption import decrypt, encrypt
from security.kek import DerivedSecretKEK, derived_kek_for

_SECRET   = "unit-test-secret-key-long-enough-padding"
_OTHER    = "a-completely-different-secret-key-padding"


@pytest.fixture(autouse=True)
def _clear_cache():
    derived_kek_for.cache_clear()
    yield
    derived_kek_for.cache_clear()


@pytest.fixture
def count_derivations(monkeypatch):
    """Count how many times PBKDF2 actually runs."""
    calls = {"n": 0}
    original = DerivedSecretKEK.__init__

    def _counting(self, secret_key):
        calls["n"] += 1
        original(self, secret_key)

    monkeypatch.setattr(DerivedSecretKEK, "__init__", _counting)
    return calls


def test_repeated_calls_derive_the_key_once(count_derivations):
    blob = encrypt("provider-api-key", _SECRET)
    for _ in range(20):
        decrypt(blob, _SECRET)
        encrypt("provider-api-key", _SECRET)

    assert count_derivations["n"] == 1, (
        f"the key was derived {count_derivations['n']} times for one secret; "
        "each derivation is ~20ms on a request path"
    )


def test_a_different_secret_derives_its_own_key(count_derivations):
    """Keyed by the secret, which is what makes rotation correct without an
    invalidation hook: a new secret is a new entry, so nothing stale is served."""
    encrypt("v", _SECRET)
    encrypt("v", _OTHER)

    assert count_derivations["n"] == 2


def test_a_rotated_secret_cannot_decrypt_the_old_ciphertext():
    """The property caching must not break. If the cache ever returned a stale
    key for a changed secret, this would start passing when it must not."""
    blob = encrypt("provider-api-key", _SECRET)

    with pytest.raises(ValueError):
        decrypt(blob, _OTHER)


def test_the_round_trip_is_unchanged():
    """The control: caching must not alter what encrypt/decrypt actually do."""
    for value in ("simple", "with spaces and 'quotes'", "unicode: café 🔑", ""):
        assert decrypt(encrypt(value, _SECRET), _SECRET) == value


def test_ciphertext_is_still_fresh_per_call():
    """A cached KEK must not lead to a cached DEK or a reused nonce -- two
    encryptions of the same value must differ."""
    first  = encrypt("same-value", _SECRET)
    second = encrypt("same-value", _SECRET)

    assert first != second, (
        "two encryptions produced identical ciphertext: the data key or nonce "
        "is being reused, which AES-GCM does not survive"
    )


def test_the_cache_is_bounded():
    """An unbounded cache keyed by a secret would grow with every rotation."""
    assert derived_kek_for.cache_info().maxsize is not None
