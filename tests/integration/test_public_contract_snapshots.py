# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Runtime response baseline for the PUBLIC API surface.

This is a MEASUREMENT harness, not an assertion of what the contract ought to be.
It records what each public route actually returns today, over real HTTP, so that
a later change to the response layer can be compared against observed behaviour
rather than against documentation. The published API currently declares no
response schema for any of these routes, so nothing else pins their shape.

What is captured, per route and per caller class:

  * HTTP status;
  * the JSON body, with field PRESENCE preserved -- an absent key and a null key
    are different observations here, because the response layer can silently turn
    the first into the second;
  * for the scan path, both a fresh response and the immediately following one,
    since the semantic cache serves a separately-built body.

NORMALIZATION. Only genuinely nondeterministic values are replaced, each with a
typed placeholder so a change of TYPE still shows up as a diff:

  * `trace_id`                  -> "<trace_id>"      (generated per request)
  * `*_at`, `timestamp`         -> "<timestamp>"     (wall clock)
  * `latency_ms`, `*_latency_*` -> "<float>"         (timing)
  * `id`, `key_id`, `*_id` UUID -> "<uuid>"          (row identity)
  * `key`/`api_key` secrets     -> "<secret>"        (never snapshotted in full)
  * `version`                   -> "<version>"       (release-dependent)

Nothing else is touched. A value that disappears, changes type, or gains a null
sibling is a real difference and must be investigated, not re-recorded.

Snapshots live in `snapshots/` next to this file. Regenerate deliberately:

    WRAPSEC_UPDATE_SNAPSHOTS=1 pytest tests/integration/test_public_contract_snapshots.py

Never regenerate to make a red test green without first explaining the diff.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path

import pytest

_SNAPSHOT_DIR = Path(__file__).parent / "snapshots"
_UPDATE       = os.environ.get("WRAPSEC_UPDATE_SNAPSHOTS") == "1"

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)

# Probe prompts carry a unique suffix so a run cannot be answered from another
# test's cache entry. That suffix must not itself look like PII: a raw
# `uuid4().hex` is a 32-character alphanumeric run, and about 5% of them match the
# IBAN_STRICT pattern, which turns the scan into a SANITIZE and changes the very
# body being recorded. Mapping the digits out keeps the value unique and
# unmistakable for an account number, with no change to detection.
_NO_DIGITS = str.maketrans("0123456789", "ghijklmnop")


def _unique() -> str:
    return uuid.uuid4().hex.translate(_NO_DIGITS)


def _normalize(value, key: str | None = None):
    """Replace nondeterministic values with typed placeholders. See module docstring."""
    if isinstance(value, dict):
        return {k: _normalize(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize(v, key) for v in value]

    if key is None or value is None:
        return value

    k = key.lower()
    if k == "trace_id" or k.endswith("_trace_id"):
        return "<trace_id>"
    if k in ("timestamp", "created_at", "updated_at", "last_seen", "expires_at",
             "last_used_at", "suspended_at", "last_login_at",
             "period_from", "period_to") or k.endswith("_at"):
        return "<timestamp>"
    if "latency" in k or k in ("duration_ms", "elapsed_ms"):
        return "<float>" if isinstance(value, (int, float)) else value
    if k in ("key", "api_key", "secret", "password_hash", "key_hash"):
        return "<secret>"
    if k == "version":
        return "<version>"
    if isinstance(value, str) and _UUID_RE.match(value):
        return "<uuid>"
    if k in ("id", "key_id", "run_id", "session_id") and isinstance(value, str):
        return "<id>"
    return value


def _shape(value):
    """Record the SHAPE of a data-dependent payload: keys and value types, not
    values.

    Used only for routes whose body reflects accumulated rows -- aggregate counts
    and audit collections -- where the value legitimately differs between runs
    while the CONTRACT does not. Types are retained, so an int that becomes a
    float, or a field that disappears, still shows up as a diff. Any route whose
    body is fully determined by its own request is snapshotted by value instead.
    """
    if isinstance(value, dict):
        return {k: _shape(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_shape(value[0])] if value else []
    if isinstance(value, bool):   return "<bool>"
    if isinstance(value, int):    return "<int>"
    if isinstance(value, float):  return "<float>"
    if isinstance(value, str):    return "<str>"
    if value is None:             return None
    return f"<{type(value).__name__}>"


def _keys(value):
    """Record only the top-level key set and each value's type.

    For bodies whose NESTED content is driven by mutable tenant configuration --
    which detection layers are enabled decides the keys inside
    `detection_scores`, and the settings families are themselves written by other
    tests -- the response contract is the top-level shape. Recording deeper makes
    the snapshot a record of whatever configuration happened to be in the database
    when it ran, which fails on test ordering rather than on a contract change.
    """
    if not isinstance(value, dict):
        return _shape(value)
    return {k: _shape(v) if not isinstance(v, (dict, list)) else f"<{type(v).__name__}>"
            for k, v in value.items()}


def _record(name: str, status: int, body, shape_only: bool = False,
            keys_only: bool = False) -> None:
    """Compare against the stored snapshot, or write it under the update flag."""
    _SNAPSHOT_DIR.mkdir(exist_ok=True)
    path = _SNAPSHOT_DIR / f"{name}.json"
    if keys_only:
        normalized, mode = _keys(body), "keys"
    elif shape_only:
        normalized, mode = _shape(body), "shape"
    else:
        normalized, mode = _normalize(body), "value"
    observed = {"status": status, "body": normalized, "mode": mode}

    if _UPDATE or not path.exists():
        path.write_text(json.dumps(observed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if not _UPDATE:
            pytest.skip(f"recorded new baseline snapshot: {path.name}")
        return

    expected = json.loads(path.read_text(encoding="utf-8"))
    assert observed == expected, (
        f"runtime response for {name} differs from the recorded baseline.\n"
        f"expected: {json.dumps(expected, indent=2, sort_keys=True)}\n"
        f"observed: {json.dumps(observed, indent=2, sort_keys=True)}\n"
        "This is a behavioural difference. Explain it before updating the snapshot."
    )


async def _snap(client, name: str, method: str, path: str, headers=None,
                json_body=None, shape_only: bool = False, keys_only: bool = False):
    r = await client.request(method, path, headers=headers or {}, json=json_body)
    try:
        body = r.json()
    except Exception:
        body = {"<non-json>": r.text[:200]}
    _record(name, r.status_code, body, shape_only=shape_only, keys_only=keys_only)
    return r


# ── unauthenticated / infrastructure routes ──────────────────────────────────

@pytest.mark.asyncio
async def test_snapshot_health_family(client):
    """/health, /health/live and /health/ready are the three probe routes on the
    public surface. /health/ready is the one that can answer 503, and it is also
    the one that returns a constructed JSONResponse."""
    await _snap(client, "health", "GET", "/health")
    await _snap(client, "health_live", "GET", "/health/live")
    await _snap(client, "health_ready", "GET", "/health/ready")


@pytest.mark.asyncio
async def test_snapshot_health_config_by_caller(client, scored_key_pair):
    """/health/config is caller-dependent: the privileged body carries threshold
    calibration the restricted one must not."""
    live, trial = scored_key_pair   # header dicts, not raw keys
    await _snap(client, "health_config_anonymous", "GET", "/health/config")
    await _snap(client, "health_config_live_key", "GET", "/health/config",
                headers=live, keys_only=True)
    await _snap(client, "health_config_trial_key", "GET", "/health/config",
                headers=trial, keys_only=True)


@pytest.mark.asyncio
async def test_snapshot_capabilities(client, scored_key_pair):
    live, _ = scored_key_pair       # header dicts, not raw keys
    await _snap(client, "capabilities", "GET", "/v1/capabilities",
                headers=live)


# ── the scan path, including the cache-served body ───────────────────────────

@pytest.mark.asyncio
async def test_snapshot_scan_fresh_and_repeat(client, scored_key_pair):
    """Two identical scans. The second may be served from the semantic cache,
    which builds its body on a different code path, so both are recorded.

    The prompt is unique per run so the first call cannot be answered from an
    entry left by another test.
    """
    live, _ = scored_key_pair       # header dicts, not raw keys
    prompt = f"snapshot baseline probe {_unique()}"

    await _snap(client, "scan_fresh_live_key", "POST", "/v1/ai/request",
                headers=live, json_body={"input": prompt})
    await _snap(client, "scan_repeat_live_key", "POST", "/v1/ai/request",
                headers=live, json_body={"input": prompt})


@pytest.mark.asyncio
async def test_snapshot_scan_caller_dependent_layer_scores(client, scored_key_pair):
    """The live key holds settings:read and sees assessment.layers[].score; the
    trial key is refused it by holds_permission's trial exclusion. Recorded as
    two snapshots so the PRESENCE difference is visible, not just the value."""
    live, trial = scored_key_pair   # header dicts, not raw keys
    prompt = f"layer score probe {_unique()}"

    await _snap(client, "scan_scores_live_key", "POST", "/v1/ai/request",
                headers=live, json_body={"input": prompt})
    await _snap(client, "scan_scores_trial_key", "POST", "/v1/ai/request",
                headers=trial, json_body={"input": f"{prompt} b"})


@pytest.mark.asyncio
async def test_snapshot_scan_batch(client, scored_key_pair):
    """Each item is an OBJECT carrying its own `input` and provenance -- a bare
    string is a 422. The first recording of this snapshot sent strings and so
    captured a validation error as the batch baseline, which measured the request
    schema rather than the batch response contract."""
    live, _ = scored_key_pair       # header dicts, not raw keys
    await _snap(client, "scan_batch_live_key", "POST", "/v1/ai/scan-batch",
                headers=live,
                json_body={"items": [{"input": f"batch probe {_unique()}"},
                                     {"input": "hello world"}]})


# ── audit read-back ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_snapshot_audit_reads(client, scored_key_pair):
    """Audit read-back is the second caller-dependent surface: detection_scores
    and guardrail_scores are emptied rather than omitted for restricted callers.
    Both callers are recorded so that difference is captured as observed."""
    live, trial = scored_key_pair   # header dicts, not raw keys
    await _snap(client, "audit_logs_live_key", "GET", "/v1/audit/logs?limit=1",
                headers=live, shape_only=True)
    await _snap(client, "audit_stats_live_key", "GET", "/v1/audit/stats",
                headers=live, shape_only=True)
    await _snap(client, "audit_logs_trial_key", "GET", "/v1/audit/logs?limit=1",
                headers=trial, shape_only=True)


@pytest.mark.asyncio
async def test_snapshot_scan_then_read_back(client, scored_key_pair):
    """GET /v1/ai/requests/{trace_id} against a trace this test just produced,
    so the read-back body is captured with real content rather than a 404."""
    live, _ = scored_key_pair       # header dicts, not raw keys
    scan = await client.post("/v1/ai/request", headers=live,
                             json={"input": f"read back probe {_unique()}"})
    assert scan.status_code == 200, scan.text
    trace_id = scan.json()["trace_id"]

    await _snap(client, "ai_request_read_back", "GET", f"/v1/ai/requests/{trace_id}",
                headers=live, keys_only=True)


# ── proxy interaction read-back and settings ─────────────────────────────────

@pytest.mark.asyncio
async def test_snapshot_proxy_interactions_list(client, scored_key_pair):
    """Empty-collection shape matters: it is what an integrator sees first."""
    live, _ = scored_key_pair       # header dicts, not raw keys
    await _snap(client, "proxy_interactions_list", "GET", "/v1/proxy/interactions?limit=1",
                headers=live)


@pytest.mark.asyncio
async def test_snapshot_settings_reads(client, scored_key_pair):
    """The four settings families the SDKs call, read with a key that holds
    settings:read."""
    live, _ = scored_key_pair       # header dicts, not raw keys
    for name, path in (
        ("settings_thresholds", "/v1/settings/thresholds"),
        ("settings_layers",     "/v1/settings/layers"),
        ("settings_llm",        "/v1/settings/llm"),
        ("settings_rate_limit", "/v1/settings/rate_limit"),
        ("settings_proxy",      "/v1/settings/proxy"),
    ):
        await _snap(client, name, "GET", path, headers=live, keys_only=True)


@pytest.mark.asyncio
async def test_snapshot_keys_list(client, scored_key_pair):
    live, _ = scored_key_pair       # header dicts, not raw keys
    await _snap(client, "keys_list", "GET", "/v1/keys", headers=live)


# ── documented error envelopes ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_snapshot_error_envelopes(client, scored_key_pair):
    """Both public error families, recorded as they are actually emitted: the
    catalog envelope on a WrapSec route and the OpenAI-compatible envelope on the
    OpenAI-compatible route."""
    live, _ = scored_key_pair       # header dicts, not raw keys
    await _snap(client, "error_unauthorized", "GET", "/v1/settings/thresholds")
    await _snap(client, "error_not_found", "GET", "/v1/ai/requests/req_" + "0" * 32,
                headers=live)
    await _snap(client, "error_openai_bad_model", "POST", "/v1/chat/completions",
                headers=live,
                json_body={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]})
