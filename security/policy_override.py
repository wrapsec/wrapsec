# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Credential handling for the generic `policy_override` dict.

Two write paths reach the same stored structure. The dedicated
`/policy/llm` and `/policy/proxy` endpoints take a SecretStr, encrypt it, and
store `api_key_enc`. The generic `policy_override` on department and
application create/update takes an unconstrained dict and stores it verbatim.

That second path never handled credentials. A caller could put a plaintext
`api_key` in the `llm` or `proxy_provider` section and it was stored in the
clear, returned unmasked by every read that renders the override, and merged
into the effective policy by the resolver -- which only ever decrypts
`api_key_enc`. Both halves of the documented invariant were broken: provider
keys encrypted at rest, and never returned in full.

SSRF validation already had this shape and was retrofitted onto the generic
path with a shared helper. This is the same retrofit for credentials, in one
place for the same reason: the mask was duplicated across the two endpoint
modules, which is how a single fix leaves half the surface unfixed.

TWO FUNCTIONS, BOTH NEEDED.

`reject_plaintext_credentials` guards the WRITE. It refuses rather than
encrypting silently: the generic path never documented a plaintext `api_key`,
so accepting one and transforming it would let a caller believe their key
round-trips as sent. Refusing is loud, and it matches what the dedicated
endpoints already require.

`mask_policy_override` guards the READ, and is not made redundant by the
write guard. It is the backstop for anything already stored, by an earlier
build or by a path added later, and a redaction that only runs when the writer
remembered to validate is not a redaction.
"""

from __future__ import annotations

from typing import Any

# The sections whose credentials are encrypted at rest. Kept here rather than
# duplicated per endpoint module, which is what allowed the two copies of the
# mask to drift out of step with what they were meant to protect.
ENCRYPTED_SECTIONS: tuple[str, ...] = ("llm", "proxy_provider")

# What a section is permitted to carry. Anything else is refused, so the next
# credential-shaped field does not repeat this defect by simply not being
# named here.
#
# THIS MUST COVER EVERY KEY THE PRODUCT ITSELF WRITES. The dedicated
# `/policy/llm` and `/policy/proxy` endpoints build these sections, and a key
# they write but this omits makes a GET-then-PUT round trip fail -- the caller
# is refused for sending back exactly what the product gave it. `default_model`
# was missed on the first pass and did that, so a test now derives this set from
# those endpoints' own write sites rather than trusting the list below.
#
# `api_key_enc` is the stored form the dedicated endpoints write;
# `api_key_masked` is what a read returns, and is accepted for the same
# round-trip reason.
_ALLOWED_SECTION_KEYS: frozenset[str] = frozenset({
    "provider", "model", "base_url", "default_model",
    "timeout", "timeout_seconds",
    "api_key_enc", "api_key_masked",
})

# Names that carry a secret in the clear. Refused outright.
_CREDENTIAL_KEYS: frozenset[str] = frozenset({
    "api_key", "apikey", "api_key_plain", "key", "secret", "token",
    "password", "access_token", "bearer_token",
})


class PolicyOverrideError(ValueError):
    """The override cannot be stored as written."""


def reject_plaintext_credentials(override: dict | None) -> None:
    """Refuse an override that carries a secret in the clear.

    Raises `PolicyOverrideError`, which callers convert to `ValidationError`
    and therefore serve as 400 INVALID_REQUEST -- the same status the URL
    validator's rejection already produces on these paths.

    Only the encrypted sections are inspected. The rest of the override is
    ordinary policy -- thresholds, feature flags -- and constraining it here
    would make this function a schema for the whole policy, which it is not.
    """
    if not isinstance(override, dict):
        return

    for name in ENCRYPTED_SECTIONS:
        section = override.get(name)
        if not isinstance(section, dict):
            continue

        offending = sorted(k for k in section if k.lower() in _CREDENTIAL_KEYS)
        if offending:
            raise PolicyOverrideError(
                f"policy_override.{name} carries {', '.join(offending)} in "
                f"plaintext. Provider credentials are encrypted at rest and are "
                f"not accepted here; set them through the dedicated policy "
                f"endpoint, which encrypts before storing."
            )

        unknown = sorted(k for k in section if k not in _ALLOWED_SECTION_KEYS)
        if unknown:
            raise PolicyOverrideError(
                f"policy_override.{name} has unsupported key(s): "
                f"{', '.join(unknown)}. Supported: "
                f"{', '.join(sorted(_ALLOWED_SECTION_KEYS))}."
            )


def mask_policy_override(override: dict | None, secret_key: str) -> dict | None:
    """The override as a read may return it.

    `api_key_enc` is decrypted and replaced with a masked form, which is what
    the previous per-endpoint copies did. Any plaintext credential is DROPPED
    rather than masked: a masked rendering of a value that should never have
    been stored would tell a reader the field is handled, and it is not.
    """
    if not override:
        return override

    from security.encryption import decrypt, mask

    result: dict[str, Any] = {}
    for key, value in override.items():
        if key not in ENCRYPTED_SECTIONS or not isinstance(value, dict):
            result[key] = value
            continue

        section = {k: v for k, v in value.items() if k.lower() not in _CREDENTIAL_KEYS}
        enc     = section.pop("api_key_enc", None)
        if enc:
            try:
                section["api_key_masked"] = mask(decrypt(enc, secret_key))
            except ValueError:
                # An undecryptable value still must not be rendered. Reporting
                # the failure as a masked field keeps the shape a reader
                # expects without disclosing the stored bytes.
                section["api_key_masked"] = "****"
        result[key] = section

    return result
