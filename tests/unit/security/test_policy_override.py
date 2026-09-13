# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""The generic policy_override guards.

A plaintext provider credential used to be storable through the generic
`policy_override` dict on department and application create/update: accepted by
an unconstrained schema, stored verbatim, returned unmasked by every read, and
merged into the effective policy by a resolver that only decrypts
`api_key_enc`.

The write guard refuses those. The read guard drops any that are already
stored, because a redaction that only runs when the writer remembered to
validate is not a redaction.

THE ALLOW-LIST IS THE FRAGILE PART. Refusing unknown keys is what stops the next
credential-shaped field repeating the defect, and it is also what breaks a
caller if the product writes a key the list omits. That happened: `default_model`
is written by the dedicated proxy endpoints and was missing, so GET-then-PUT of
an override the product itself produced was refused. The census test below
derives the expectation from those endpoints' write sites rather than from the
list, so the list cannot fall behind them again.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from security.policy_override import (
    _ALLOWED_SECTION_KEYS,
    ENCRYPTED_SECTIONS,
    PolicyOverrideError,
    mask_policy_override,
    reject_plaintext_credentials,
)

_ROOT      = Path(__file__).resolve().parents[3]
_ENDPOINTS = (
    _ROOT / "api/v1/endpoints/departments.py",
    _ROOT / "api/v1/endpoints/applications.py",
)

_SECRET = "unit-test-secret-key-padding-0123456789abc"
_PLAIN  = "sk-live-PLAINTEXT-0123456789"


# ---------------------------------------------------------------------------
# the write guard
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("section", ENCRYPTED_SECTIONS)
@pytest.mark.parametrize(
    "field", ["api_key", "API_KEY", "apikey", "token", "secret", "password",
              "access_token", "bearer_token"],
)
def test_a_credential_in_the_clear_is_refused(section, field):
    with pytest.raises(PolicyOverrideError, match="plaintext"):
        reject_plaintext_credentials({section: {"provider": "openai", field: _PLAIN}})


def test_the_rejection_does_not_repeat_the_secret():
    """The message reaches logs and error bodies; it must name the field, not
    the value."""
    with pytest.raises(PolicyOverrideError) as caught:
        reject_plaintext_credentials({"llm": {"api_key": _PLAIN}})
    assert _PLAIN not in str(caught.value)


@pytest.mark.parametrize("section", ENCRYPTED_SECTIONS)
def test_an_unknown_key_in_a_guarded_section_is_refused(section):
    with pytest.raises(PolicyOverrideError, match="unsupported key"):
        reject_plaintext_credentials({section: {"provider": "openai", "novel_field": "x"}})


def test_sections_outside_the_guarded_pair_are_not_constrained():
    """This guards credentials, not the whole policy. Constraining every section
    would make it a schema for policy, which it is not."""
    reject_plaintext_credentials({
        "detection":  {"rule_enabled": False, "anything": 1},
        "thresholds": {"block": 0.7},
    })


@pytest.mark.parametrize("value", [None, "not a dict", 42, []])
def test_a_non_dict_override_is_ignored_rather_than_raising(value):
    reject_plaintext_credentials(value)


# ---------------------------------------------------------------------------
# the allow-list must not fall behind what the product writes
# ---------------------------------------------------------------------------

def _keys_the_endpoints_write() -> set[str]:
    """Every `current["..."]` the dedicated override endpoints assign.

    Those endpoints build the llm / proxy_provider sections, so what they write
    is exactly what a caller can later read back and send again.
    """
    found: set[str] = set()
    for path in _ENDPOINTS:
        assert path.exists(), f"{path} moved; update this census"
        found |= set(re.findall(r'current\["([a-z_]+)"\]', path.read_text(encoding="utf-8")))
    assert found, "the census matched nothing; the write sites were rewritten"
    return found


def test_every_key_the_product_writes_is_accepted_back():
    """The regression this test exists for.

    `default_model` is written by the proxy override endpoints and was absent
    from the allow-list, so a caller that fetched an override and sent it back
    unchanged was refused for echoing the product's own output.
    """
    written = _keys_the_endpoints_write()
    missing = sorted(written - _ALLOWED_SECTION_KEYS)
    assert not missing, (
        f"{missing} are written into these sections by the dedicated override "
        f"endpoints but refused by the allow-list, so a GET-then-PUT round trip "
        f"of an override the product itself produced would be rejected"
    )


def test_a_full_product_written_section_round_trips():
    """The same thing end to end, on the shape those endpoints actually store."""
    stored = {"proxy_provider": {
        "provider": "openai", "default_model": "openai/gpt-4o",
        "base_url": "https://api.openai.com/v1", "timeout_seconds": 30,
    }}
    reject_plaintext_credentials(stored)          # must not raise

    rendered = mask_policy_override(stored, _SECRET)
    reject_plaintext_credentials(rendered)        # and what a read returns must go back


# ---------------------------------------------------------------------------
# the read guard
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("section", ENCRYPTED_SECTIONS)
def test_a_stored_plaintext_credential_is_dropped_not_masked(section):
    """Masking it would tell a reader the field is handled. It is not: it should
    never have been stored."""
    out = mask_policy_override({section: {"provider": "openai", "api_key": _PLAIN}}, _SECRET)

    assert _PLAIN not in str(out)
    assert "api_key" not in out[section]
    assert "api_key_masked" not in out[section], "a dropped value must not be reported as masked"


def test_an_encrypted_key_is_still_decrypted_and_masked():
    """The behaviour the previous per-endpoint copies had, preserved."""
    from security.encryption import encrypt

    enc = encrypt("sk-real-secret-value", _SECRET)
    out = mask_policy_override({"llm": {"provider": "openai", "api_key_enc": enc}}, _SECRET)

    assert "api_key_enc" not in out["llm"]
    assert out["llm"]["api_key_masked"]
    assert "sk-real-secret-value" not in str(out)


def test_an_undecryptable_value_is_not_rendered():
    out = mask_policy_override({"llm": {"api_key_enc": "not-decryptable"}}, _SECRET)
    assert out["llm"]["api_key_masked"] == "****"


def test_unguarded_sections_pass_through_untouched():
    payload = {"detection": {"rule_enabled": False}, "thresholds": {"block": 0.7}}
    assert mask_policy_override(payload, _SECRET) == payload


def test_the_original_override_is_not_mutated():
    """The stored object is still the subject of the audit record."""
    original = {"llm": {"provider": "openai", "api_key": _PLAIN}}
    mask_policy_override(original, _SECRET)
    assert original["llm"]["api_key"] == _PLAIN
