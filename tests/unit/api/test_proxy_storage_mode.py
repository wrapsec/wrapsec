# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Regression tests for DATA_STORAGE_MODE enforcement in the proxy log path.

Invariant: _log_interaction() must honor get_settings().data_storage_mode:
  - full   -> store input_raw / output_raw as captured
  - masked -> null out raw fields; keep sanitized
  - none   -> null out both raw and sanitized

Before v1.0.1 this setting was a no-op and every proxy call persisted raw
input/output. See pentest_round3 C2.
"""

from unittest.mock import AsyncMock, MagicMock, patch

from api.v1.endpoints.proxy import _log_interaction


def _make_db_capture():
    captured = {}
    db = MagicMock()
    db.add    = MagicMock(side_effect=lambda obj: captured.setdefault("added", []).append(obj))
    db.flush  = AsyncMock()
    db.commit = AsyncMock()
    db.execute = AsyncMock()
    return db, captured


async def _run_log(mode: str):
    db, captured = _make_db_capture()

    with patch("api.v1.endpoints.proxy.get_settings") as mock_settings, \
         patch("api.v1.endpoints.proxy.AuditRepository") as mock_audit:
        mock_settings.return_value.data_storage_mode = mode
        mock_audit.return_value.create = AsyncMock()

        await _log_interaction(
            db                = db,
            trace_id          = "trace-test",
            key_id            = "key-123",
            user_id           = "user-123",
            input_raw         = "hello secret password",
            input_sanitized   = "hello secret <REDACTED>",
            input_decision    = "ALLOW",
            input_reason      = "NO_THREAT_DETECTED",
            input_confidence  = 0.9,
            input_threats     = [],
            input_attack_type = None,
            provider          = "openai",
            model             = "gpt-4o",
            provider_latency  = 100,
            execution_status  = "SUCCESS",
            output_raw        = "here is the raw output",
            output_sanitized  = "here is the <REDACTED>",
            output_decision   = "ALLOW",
            output_reason     = "NO_THREAT_DETECTED",
            output_confidence = 0.9,
            output_threats    = [],
            total_latency_ms  = 150,
            input_length      = 20,
        )

    interactions = [o for o in captured.get("added", []) if hasattr(o, "input_raw")]
    assert len(interactions) == 1, f"expected one ProxyInteractionModel, got {captured}"
    return interactions[0]


async def test_full_mode_stores_raw_and_sanitized():
    obj = await _run_log("full")
    assert obj.input_raw       == "hello secret password"
    assert obj.input_sanitized == "hello secret <REDACTED>"
    assert obj.output_raw      == "here is the raw output"
    assert obj.output_sanitized == "here is the <REDACTED>"


async def test_masked_mode_nulls_raw_keeps_sanitized():
    obj = await _run_log("masked")
    assert obj.input_raw       is None
    assert obj.input_sanitized == "hello secret <REDACTED>"
    assert obj.output_raw      is None
    assert obj.output_sanitized == "here is the <REDACTED>"


async def test_none_mode_nulls_both_raw_and_sanitized():
    obj = await _run_log("none")
    assert obj.input_raw       is None
    assert obj.input_sanitized is None
    assert obj.output_raw      is None
    assert obj.output_sanitized is None


async def test_default_falls_back_to_masked_when_missing():
    """If somehow the setting is empty, fail safe by treating as masked."""
    obj = await _run_log("")
    assert obj.input_raw  is None
    assert obj.output_raw is None
    assert obj.input_sanitized  == "hello secret <REDACTED>"
    assert obj.output_sanitized == "here is the <REDACTED>"


async def test_unknown_mode_fails_closed_to_masked():
    """B5: an unrecognized mode must fail CLOSED (mask) -- never store raw
    prompt/response. Only an explicit 'full' opts into plaintext retention."""
    obj = await _run_log("gibberish")
    assert obj.input_raw        is None
    assert obj.output_raw       is None
    assert obj.input_sanitized  == "hello secret <REDACTED>"
    assert obj.output_sanitized == "here is the <REDACTED>"
