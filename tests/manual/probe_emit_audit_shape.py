# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Live end-to-end probe: emit_from_audit projects the audit dict onto a
Redis Streams payload with the expected shape.

Not part of the unit suite. Run in-container after copying:

    docker exec -w /app wrapsec_api python tests/manual/probe_emit_audit_shape.py
"""

from __future__ import annotations

import asyncio
import json
from uuid import UUID, uuid4

from cache.redis_client import get_redis
from cache.webhook_queue import STREAM_MAIN
from db.session import AsyncSessionFactory
from services.webhooks.emitter import EVENT_BLOCKED, emit_from_audit


TENANT_ID = UUID("42a083bf-5cad-4b65-84d1-b81def88c9f3")
ENDPOINT_ID = UUID("11111111-1111-1111-1111-111111111111")


async def main() -> None:
    redis = get_redis()
    await redis.delete(STREAM_MAIN)

    audit_data = {
        "trace_id":         f"probe-{uuid4().hex[:8]}",
        "tenant_id":        TENANT_ID,
        "decision":         "BLOCK",
        "risk_score":       0.95,
        "primary_reason":   "RULE_DETECTOR",
        "confidence":       0.9,
        "confidence_band":  "HIGH",
        "threats":          ["prompt_injection"],
        "input_hash":       "sha256:probe",
        "detection_mode":   "fast",
        "execution_mode":   "scan_only",
        "latency_ms":       12.5,
        "source":           "api",
        "user_id":          "probe-user",
        "severity":         "CRITICAL",
        # Internal columns that must be excluded from the payload body.
        "record_hash":      "chain-hash",
        "prev_hash":        "chain-hash-prev",
    }

    async with AsyncSessionFactory() as db:
        n = await emit_from_audit(db=db, redis=redis, audit_data=audit_data)

    print(f"enqueued={n}")
    assert n == 1, f"expected 1 endpoint enqueued, got {n}"

    entries = await redis.xrange(STREAM_MAIN, count=1)
    assert entries, "no entries on stream"
    stream_id, fields = entries[0]
    raw = fields[b"p"] if b"p" in fields else fields["p"]
    payload = json.loads(raw)

    print("stream_id =", stream_id)
    print("payload   =", json.dumps(payload, indent=2, default=str))

    assert payload["event_type"] == EVENT_BLOCKED
    assert payload["tenant_id"] == str(TENANT_ID)
    assert payload["endpoint_id"] == str(ENDPOINT_ID)
    assert payload["attempt_number"] == 1

    body = payload["body"]
    assert "timestamp" in body
    assert body["decision"] == "BLOCK"
    assert body["risk_score"] == 0.95
    assert body["severity"] == "CRITICAL"
    assert body["confidence_band"] == "HIGH"
    assert body["threats"] == ["prompt_injection"]
    assert body["input_hash"] == "sha256:probe"
    assert "record_hash" not in body, "internal hash-chain column leaked"
    assert "prev_hash"   not in body, "internal hash-chain column leaked"

    print("OK: audit-shape probe passed")


if __name__ == "__main__":
    asyncio.run(main())
