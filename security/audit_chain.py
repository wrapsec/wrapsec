# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Tamper-evident hash chain for audit_logs.

Each row's record_hash covers a deterministic serialisation of the row's
content plus the previous row's record_hash:

    record_hash = SHA-256( canonical(row) || prev_hash )

Design points that match enterprise-tier tamper-evidence systems (AWS QLDB,
HashiCorp Vault, AWS CloudTrail, Sigstore Rekor):

  1. Per-tenant chain. Cross-tenant chaining would leak scan-volume metadata
     across boundaries and force every write to serialize against a global
     lock. Rows with no tenant_id are intentionally left unchained (both
     hash columns NULL) so unattributed system-level rows do not pollute a
     "null-tenant" chain that spans customers.

  2. Explicit CANONICAL_FIELDS list. Adding a new column to audit_logs does
     NOT silently change hash values -- the new column is invisible to the
     chain until it is added here consciously. This preserves verifiability
     of pre-column-add rows and forces the operator to think about hash
     compatibility on every schema change.

  3. Deterministic JSON. sort_keys, no whitespace, ensure_ascii; datetime
     serialised as UTC ISO 8601 with microseconds; UUID as canonical string;
     None preserved as JSON null. Booleans stay booleans (not 0/1). Floats
     are cast through repr()-safe round-trip via json.dumps default.

  4. Genesis row uses prev_hash = "" (empty string) in the hash input so the
     input to SHA-256 is always length canonical(row) + 64, EXCEPT for the
     genesis row where it is length canonical(row) + 0. Storing prev_hash
     as NULL on the genesis row is a display convention; the empty string
     is the hash input.

The hash itself is application-layer integrity: it detects tampering by
anyone with row-level UPDATE/DELETE access. Preventing that tampering is
a separate concern (the postgres trigger that lands two commits later).
Without the trigger, the chain is theatre.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from typing import Any

from services.time import ensure_utc


# Explicit sorted list. Every audit_logs column EXCEPT id (DB-assigned,
# not part of the content) and record_hash/prev_hash (the chain output
# itself). New columns must be added here explicitly -- do not derive from
# the ORM at import time or a model change will silently break the chain.
CANONICAL_FIELDS: tuple[str, ...] = (
    "app_id",
    "attribution_verified",
    "confidence",
    "confidence_band",
    "created_at",
    "decision",
    "dept_id",
    "detection_mode",
    "detection_scores",
    "execution_mode",
    "guardrail_scores",
    "input_hash",
    "input_length",
    "ip_address",
    "key_id",
    "latency_ms",
    "llm_invoked",
    "model_version",
    "policy_source",
    "primary_reason",
    "principal_type",
    "proxy_interaction_id",
    "risk_score",
    "run_id",
    "session_id",
    "severity",
    "source",
    "tenant_id",
    "threats",
    "trace_id",
    "turn_index",
    "user_agent",
    "user_id",
)


def _json_safe(value: Any) -> Any:
    """
    Convert values that json.dumps cannot serialise natively into stable,
    deterministic string forms. Anything else round-trips as-is.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        # Canonical aware-UTC ISO 8601 with microseconds. Timestamps are stored
        # as TIMESTAMPTZ; normalizing to UTC first keeps the hash input
        # deterministic regardless of the tzinfo attached to the value.
        return ensure_utc(value).isoformat(timespec="microseconds")
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, dict):
        # Recursively canonicalise nested dicts so scores etc. hash the same
        # regardless of insertion order.
        return {str(k): _json_safe(v) for k, v in sorted(value.items())}
    # Everything else (Decimal, bytes, custom objects) -- refuse rather than
    # silently accept a non-deterministic repr.
    raise TypeError(
        f"audit_chain: value of type {type(value).__name__} is not "
        f"canonicalisable; add explicit handling to _json_safe()."
    )


def canonical_row(data: dict[str, Any]) -> str:
    """
    Deterministic JSON serialisation of `data` restricted to CANONICAL_FIELDS.

    Missing fields default to None. Fields outside CANONICAL_FIELDS are
    ignored (see module docstring point 2).
    """
    normalized = {name: _json_safe(data.get(name)) for name in CANONICAL_FIELDS}
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def compute_record_hash(data: dict[str, Any], prev_hash: str | None) -> str:
    """
    SHA-256 over canonical(data) concatenated with prev_hash. Returns the
    64-char lowercase hex digest.

    prev_hash is treated as the empty string on the genesis row -- the
    stored prev_hash column is NULL on that row by convention, but the
    hash input MUST NOT change based on whether an SQL NULL was involved.
    """
    payload = canonical_row(data).encode("ascii") + (prev_hash or "").encode("ascii")
    return hashlib.sha256(payload).hexdigest()
