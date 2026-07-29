# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
HMAC-SHA256 signing for outbound webhook payloads.

Wire format follows the Svix "Standard Webhooks" scheme, which is also
what Stripe and most modern SaaS webhook providers use in 2026. Chosen
over GitHub's simpler `X-Hub-Signature-256: sha256=<hex>` because the
Svix format carries a timestamp that the receiver can verify to reject
replayed deliveries -- GitHub's header does not.

Headers emitted per delivery:

    webhook-id:        stable per-message identifier (UUID string)
    webhook-timestamp: unix seconds when the payload was signed
    webhook-signature: space-separated list "v1,<b64> v1,<b64> ..."

Signed string:

    {webhook-id}.{webhook-timestamp}.{body}

Signature: base64(HMAC-SHA256(secret, signed_string)), prefixed with
"v1," so a future algo change can add "v2," entries without breaking
existing verifiers.

Rotation. Multiple signatures may appear in the header, one per active
signing secret. The emitter signs with each currently-valid secret
(active + any old_secrets that have not yet expired) and joins them
with a single space. Receivers accept if ANY signature verifies. This
is Svix's ExpiringSigningKeys pattern -- during a rotation the emitter
briefly sends two signatures, giving the receiver a grace window to
update their verifier code.

Replay protection. `verify` rejects signatures whose timestamp is
older than `tolerance_seconds` (default 300s / 5 min, matching Svix
and Stripe). Even a captured valid signature stops working after the
tolerance window.

Distinct HMAC secret per feature per feedback_conflict_prevention.md:
webhook signing secrets MUST NOT be reused for the audit hash chain,
JWT signing, CSRF tokens, or inbound SDK request signing. Callers are
responsible for using the correct per-endpoint secret from
webhook_endpoints.secret_enc.

This module is a pure crypto primitive. It knows nothing about the
database, envelope encryption, HTTP, or WrapSec settings -- callers
decrypt the envelope-encrypted secret via security.encryption before
passing plaintext bytes here.

References:
- Svix Standard Webhooks: https://www.standardwebhooks.com/
- Stripe webhook signatures: https://docs.stripe.com/webhooks/signatures
"""

from __future__ import annotations

import base64
import hmac
import time
from hashlib import sha256
from typing import Sequence


# Signature scheme prefix. Bumping to v2 (e.g. HMAC-SHA512, EdDSA) would
# emit "v2,<sig>" alongside "v1,<sig>" during transition; verifiers accept
# any entry that matches with the appropriate algorithm.
SIGNATURE_VERSION = "v1"

# Replay window. Signatures whose webhook-timestamp is more than this many
# seconds off from `now` are rejected by `verify`. Matches Svix/Stripe.
DEFAULT_TIMESTAMP_TOLERANCE_S = 300


def sign(
    secret:    bytes,
    msg_id:    str,
    timestamp: int,
    body:      bytes,
) -> str:
    """
    Compute one signature entry (e.g. "v1,abc...=").

    The emitter typically calls this once per active secret and joins
    the results with " " to build the webhook-signature header value.
    """
    signed = f"{msg_id}.{timestamp}.".encode("utf-8") + body
    mac    = hmac.new(secret, signed, sha256).digest()
    return f"{SIGNATURE_VERSION},{base64.b64encode(mac).decode('ascii')}"


def build_headers(
    secrets:   Sequence[bytes],
    msg_id:    str,
    body:      bytes,
    timestamp: int | None = None,
) -> dict[str, str]:
    """
    Build the three webhook headers for a delivery.

    `secrets` is ordered [active, *old_unexpired]. All are signed with
    and joined into the webhook-signature header so a receiver still
    on an old secret keeps verifying during the rotation grace window.

    `timestamp` defaults to now() when omitted; tests pin it explicitly.
    """
    if not secrets:
        raise ValueError("at least one signing secret is required")

    ts        = int(time.time()) if timestamp is None else timestamp
    sig_parts = [sign(s, msg_id, ts, body) for s in secrets]

    return {
        "webhook-id":        msg_id,
        "webhook-timestamp": str(ts),
        "webhook-signature": " ".join(sig_parts),
    }


def verify(
    secrets:             Sequence[bytes],
    msg_id:              str,
    timestamp_header:    str,
    signature_header:    str,
    body:                bytes,
    tolerance_seconds:   int = DEFAULT_TIMESTAMP_TOLERANCE_S,
    now:                 int | None = None,
) -> bool:
    """
    Verify a received webhook.

    Returns True iff:
      - `timestamp_header` parses to an integer within `tolerance_seconds`
        of `now` (defaults to time.time()); AND
      - at least one "v1,<b64>" entry in `signature_header` matches the
        HMAC of any secret in `secrets`.

    All comparisons use hmac.compare_digest to defeat timing oracles.
    Malformed timestamp or signature header -> False (never raises).
    """
    if not secrets:
        return False

    try:
        ts_signed = int(timestamp_header)
    except (TypeError, ValueError):
        return False

    ts_now = int(time.time()) if now is None else now
    if abs(ts_now - ts_signed) > tolerance_seconds:
        return False

    # Compute the expected raw HMAC bytes for each secret once.
    signed        = f"{msg_id}.{ts_signed}.".encode("utf-8") + body
    expected_macs = [hmac.new(s, signed, sha256).digest() for s in secrets]

    for entry in signature_header.split(" "):
        entry = entry.strip()
        if not entry.startswith(f"{SIGNATURE_VERSION},"):
            continue
        try:
            got = base64.b64decode(entry.split(",", 1)[1], validate=True)
        except (ValueError, IndexError):
            continue
        for expected in expected_macs:
            if hmac.compare_digest(got, expected):
                return True

    return False
