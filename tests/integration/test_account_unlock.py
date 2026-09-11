# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""A locked account must be recoverable by an authorized operator.

The lockout closes a loop with no exit. `is_locked` is checked BEFORE
credentials are verified, so a locked account refuses the CORRECT password; the
lock is re-set on every further failure at or above the threshold; and the only
code that cleared it ran after a successful login, which the first check makes
unreachable. One wrong password per window therefore holds an account shut for
as long as the attacker cares to, and recovery meant editing the store by hand.

The lockout itself is unchanged -- the sliding counter and the extension on
further failures ARE the brute-force protection. What is added is a way back.

`test_an_attacker_can_hold_an_account_locked_indefinitely` documents the
attack rather than asserting it is impossible, because it IS possible and is
supposed to be: that is the control working. It exists so the unlock tests below
are read as a recovery path and not as a hole.
"""

from __future__ import annotations

import pytest

from services.auth.lockout import is_locked, record_failure, unlock
from services.auth.password import normalize_email

_UNLOCK = "/v1/admin/users/{}/unlock"


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def _lock_out(email: str) -> None:
    """Drive the real lockout to its locked state."""
    from config.settings import get_settings

    for _ in range(get_settings().auth_max_failed_attempts):
        await record_failure(email)
    assert await is_locked(email), "the account did not lock; the test proves nothing"


@pytest.mark.asyncio
async def test_an_attacker_can_hold_an_account_locked_indefinitely(auth_setup):
    """The behaviour that makes recovery necessary, stated as a fact.

    Each failure at or above the threshold re-sets the lock's expiry, so the
    window never elapses while an attacker keeps submitting. This is the
    brute-force control doing its job -- it is only a problem because nothing
    could clear it.
    """
    email = normalize_email(auth_setup["viewer_user"].email)
    await _lock_out(email)

    from services.auth.lockout import get_lockout_remaining

    first = await get_lockout_remaining(email)
    await record_failure(email)          # one more attempt, as an attacker would
    extended = await get_lockout_remaining(email)

    assert await is_locked(email)
    assert extended >= first - 1, (
        "the lockout did not extend on a further failure, so the brute-force "
        "control has been weakened"
    )


@pytest.mark.asyncio
async def test_an_admin_can_unlock_an_account_in_their_tenant(client, auth_setup):
    email = normalize_email(auth_setup["viewer_user"].email)
    await _lock_out(email)

    resp = await client.post(
        _UNLOCK.format(auth_setup["viewer_user"].id),
        headers=_bearer(auth_setup["admin_token"]),
    )

    assert resp.status_code == 200, resp.text
    assert resp.json()["was_locked"] is True
    assert not await is_locked(email), "the account is still locked after an unlock"


@pytest.mark.asyncio
async def test_the_unlock_clears_the_failure_counter_too(client, auth_setup):
    """Clearing the lock while leaving the counter at the threshold would
    re-lock the account on the very next failure, which reads as the unlock not
    having worked."""
    from config.settings import get_settings

    email = normalize_email(auth_setup["viewer_user"].email)
    await _lock_out(email)

    await client.post(
        _UNLOCK.format(auth_setup["viewer_user"].id),
        headers=_bearer(auth_setup["admin_token"]),
    )

    count, now_locked = await record_failure(email)

    assert count == 1, f"the counter survived the unlock (restarted at {count})"
    assert now_locked is False or get_settings().auth_max_failed_attempts == 1


@pytest.mark.asyncio
async def test_a_non_admin_cannot_unlock(client, auth_setup):
    email = normalize_email(auth_setup["viewer_user"].email)
    await _lock_out(email)

    for role in ("dev_token", "viewer_token"):
        resp = await client.post(
            _UNLOCK.format(auth_setup["viewer_user"].id),
            headers=_bearer(auth_setup[role]),
        )
        assert resp.status_code == 403, f"{role} unlocked an account: {resp.status_code}"

    assert await is_locked(email), "a refused request still cleared the lockout"


@pytest.mark.asyncio
async def test_an_admin_cannot_unlock_a_user_outside_their_tenant(client, auth_setup, two_tenant_setup):
    """Authority stops at the tenant boundary, and the refusal must not reveal
    whether the user id exists elsewhere -- so it is the same 404 as an unknown
    id."""
    other_user_id = two_tenant_setup["B"]["admin_user"].id

    resp = await client.post(
        _UNLOCK.format(other_user_id), headers=_bearer(auth_setup["admin_token"]),
    )

    assert resp.status_code == 404, (
        f"an admin reached into another tenant: {resp.status_code}"
    )


@pytest.mark.asyncio
async def test_unlocking_an_account_that_was_not_locked_is_reported_honestly(client, auth_setup):
    """The authority was still exercised, so it is still audited; the response
    says which happened rather than implying a lock existed."""
    resp = await client.post(
        _UNLOCK.format(auth_setup["viewer_user"].id),
        headers=_bearer(auth_setup["admin_token"]),
    )

    assert resp.status_code == 200
    assert resp.json()["was_locked"] is False


@pytest.mark.asyncio
async def test_the_unlock_is_audited(client, auth_setup, test_db):
    from sqlalchemy import select

    from db.models import AdminEventModel

    email = normalize_email(auth_setup["viewer_user"].email)
    await _lock_out(email)
    await client.post(
        _UNLOCK.format(auth_setup["viewer_user"].id),
        headers=_bearer(auth_setup["admin_token"]),
    )

    action = await test_db.scalar(
        select(AdminEventModel.action).where(
            AdminEventModel.target_user_id == auth_setup["viewer_user"].id,
            AdminEventModel.action == "account_unlocked",
        )
    )
    assert action == "account_unlocked", (
        "clearing a lockout restores the ability to authenticate and was not "
        "recorded"
    )


@pytest.mark.asyncio
async def test_a_legitimate_user_recovers_when_the_window_elapses(auth_setup):
    """Recovery without an operator still works: the lock carries a TTL, and
    nothing here made it permanent."""
    email = normalize_email(auth_setup["admin_user"].email)
    await _lock_out(email)

    from cache import keyspace
    from cache.redis_client import get_redis

    ttl = await get_redis().ttl(keyspace.auth_locked(email))
    assert ttl > 0, "the lockout has no expiry, so it never elapses on its own"

    await unlock(email)   # stand in for the elapsed window
    assert not await is_locked(email)
