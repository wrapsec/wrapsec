# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Resolution of a request-level trace id to the first row of that request.

A proxy request writes one audit row per scanned message, keyed
`{request_trace}-{message_index}`, because the trace column is unique. The
caller only ever holds the request-level id, so GET /v1/ai/requests/{trace_id}
resolves through `AuditRepository.first_derived_trace_id`.

The suffix is a POSITION, and positions pass 9. Ordering the ids as text puts
`-10` and `-11` ahead of `-2`, so "first" silently becomes "some other message".

Two dataset shapes cannot detect that, and both pass whichever ordering is in
effect:

  * indices that stop at 9 -- text order and numeric order agree throughout;
  * any dataset CONTAINING index 0 -- "-0" is the smallest string as well as the
    smallest number, so it wins under either rule.

The discriminating cases below therefore carry a multi-digit index AND no index
0, which makes the two orderings disagree on the answer. The second trap is not
hypothetical: the first draft of this file included index 0 and passed against a
deliberately reintroduced lexicographic sort.

The index is the message's position in the FULL messages array, so it is not
bounded by the scan-all cap: a conversation of twelve messages reaches index 11
even when only ten are scanned.
"""

import hashlib
import uuid

import pytest

from db.repositories.audit import AuditRepository
from services.time import utc_now


async def _seed_key(test_db):
    """Seed a hash-matching non-admin key so the request carries real dept scope."""
    from db.models import APIKeyModel, DepartmentModel, TenantModel

    tid, did = uuid.uuid4(), uuid.uuid4()
    raw = "wsk_live_" + uuid.uuid4().hex

    test_db.add(TenantModel(id=tid, slug=f"t-{tid.hex[:8]}", name="T"))
    await test_db.commit()
    test_db.add(DepartmentModel(id=did, tenant_id=tid, slug=f"d-{did.hex[:6]}",
                                name="Eng", is_active=True))
    await test_db.commit()
    test_db.add(APIKeyModel(
        id=uuid.uuid4(), key_id="key_" + uuid.uuid4().hex[:8],
        tenant_id=tid, dept_id=did, app_id=None, name="k",
        key_hash=hashlib.sha256(raw.encode()).hexdigest(),
        key_type="live", is_admin=False, revoked=False,
    ))
    await test_db.commit()
    return raw, tid, did


def _audit_row(*, trace_id, tenant_id=None, dept_id=None):
    from db.models import AuditLogModel
    return AuditLogModel(
        id=uuid.uuid4(), trace_id=trace_id, decision="ALLOW", risk_score=0.1, threats=[],
        input_hash="h", detection_mode="standard", execution_mode="proxy",
        llm_invoked=False, latency_ms=10.0, source="api", input_source="user_prompt",
        tenant_id=str(tenant_id) if tenant_id else None,
        dept_id=str(dept_id) if dept_id else None,
        created_at=utc_now(),
    )


async def _seed_message_rows(test_db, base, indices, tenant_id=None, dept_id=None):
    """One audit row per scanned message, inserted out of numeric order so a
    result cannot come from insertion order by accident."""
    for index in indices:
        test_db.add(_audit_row(
            trace_id  = f"{base}-{index}",
            tenant_id = tenant_id,
            dept_id   = dept_id,
        ))
    await test_db.commit()


# ── repository ordering ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_first_derived_id_is_the_lowest_index_not_the_lowest_string(test_db):
    base = "req_" + uuid.uuid4().hex
    # Insertion order scrambled, 10 and 11 present, and index 0 deliberately
    # ABSENT: "-0" sorts first under either rule, so a dataset containing it
    # cannot distinguish them. Here the text order yields "-10" and the numeric
    # order yields "-2", so only one of the two can pass.
    await _seed_message_rows(test_db, base, [11, 3, 10, 2, 7, 5])

    first = await AuditRepository(test_db).first_derived_trace_id(base)

    assert first == f"{base}-2"


@pytest.mark.asyncio
async def test_single_digit_only_dataset_would_pass_either_way(test_db):
    """Kept as an explicit record of why the multi-digit cases above exist: with
    indices 0-9 the text order and the numeric order agree, so this assertion
    holds both before and after the fix and proves nothing on its own."""
    base = "req_" + uuid.uuid4().hex
    await _seed_message_rows(test_db, base, [4, 1, 9, 2])

    first = await AuditRepository(test_db).first_derived_trace_id(base)

    assert first == f"{base}-1"


@pytest.mark.asyncio
async def test_first_derived_id_handles_a_two_digit_minimum(test_db):
    """The lowest index need not be 0: with 10, 11 and 12 the answer is 10, which
    text ordering also happens to get right -- included so the numeric path is
    exercised where no single-digit row exists to mask it."""
    base = "req_" + uuid.uuid4().hex
    await _seed_message_rows(test_db, base, [12, 10, 11])

    first = await AuditRepository(test_db).first_derived_trace_id(base)

    assert first == f"{base}-10"


@pytest.mark.asyncio
async def test_non_numeric_suffix_does_not_break_the_lookup(test_db):
    """A suffix that is not a position must not crash the resolve or win the
    ordering; real positions still come first."""
    base = "req_" + uuid.uuid4().hex
    await _seed_message_rows(test_db, base, [10, 2])
    test_db.add(_audit_row(trace_id=f"{base}-retry"))
    await test_db.commit()

    first = await AuditRepository(test_db).first_derived_trace_id(base)

    assert first == f"{base}-2"


@pytest.mark.asyncio
async def test_only_a_non_numeric_suffix_still_resolves(test_db):
    base = "req_" + uuid.uuid4().hex
    test_db.add(_audit_row(trace_id=f"{base}-retry"))
    await test_db.commit()

    assert await AuditRepository(test_db).first_derived_trace_id(base) == f"{base}-retry"


@pytest.mark.asyncio
async def test_no_rows_resolves_to_none(test_db):
    base = "req_" + uuid.uuid4().hex
    assert await AuditRepository(test_db).first_derived_trace_id(base) is None


@pytest.mark.asyncio
async def test_tenant_filter_still_applies_to_the_numeric_ordering(test_db):
    """The tenant predicate must bound the candidate set BEFORE the position is
    chosen: another tenant's lower-indexed row must not become this tenant's
    answer."""
    base  = "req_" + uuid.uuid4().hex
    mine  = uuid.uuid4()
    other = uuid.uuid4()

    from db.models import TenantModel
    test_db.add(TenantModel(id=mine,  slug=f"t-{mine.hex[:8]}",  name="Mine"))
    test_db.add(TenantModel(id=other, slug=f"t-{other.hex[:8]}", name="Other"))
    await test_db.commit()

    await _seed_message_rows(test_db, base, [0, 1], tenant_id=other)
    await _seed_message_rows(test_db, base, [4, 12], tenant_id=mine)

    first = await AuditRepository(test_db).first_derived_trace_id(base, str(mine))

    assert first == f"{base}-4"


# ── the endpoint that consumers actually call ────────────────────────────────

@pytest.mark.asyncio
async def test_get_request_returns_the_first_message_row_past_index_nine(client, test_db):
    """The claim that matters: a caller holding only the request-level id gets
    the first message of that request back, whatever the message count."""
    raw, tid, did = await _seed_key(test_db)
    base = "req_" + uuid.uuid4().hex
    # No index 0, for the reason given on the repository case above: with one
    # present both orderings agree and the test proves nothing.
    await _seed_message_rows(
        test_db, base, [11, 10, 3, 8, 2], tenant_id=tid, dept_id=did,
    )

    r = await client.get(f"/v1/ai/requests/{base}", headers={"x-api-key": raw})

    assert r.status_code == 200
    assert r.json()["trace_id"] == f"{base}-2"


@pytest.mark.asyncio
async def test_get_request_scoping_is_unchanged_by_the_numeric_ordering(client, test_db):
    """Resolving the id must not become a way to read another tenant's row: the
    rows here belong to a foreign tenant, so the lookup must 404 rather than
    return the numerically-first one."""
    raw, _tid, _did = await _seed_key(test_db)
    base  = "req_" + uuid.uuid4().hex
    other = uuid.uuid4()

    from db.models import TenantModel
    test_db.add(TenantModel(id=other, slug=f"t-{other.hex[:8]}", name="Other"))
    await test_db.commit()
    await _seed_message_rows(test_db, base, [0, 10], tenant_id=other)

    r = await client.get(f"/v1/ai/requests/{base}", headers={"x-api-key": raw})

    assert r.status_code == 404
