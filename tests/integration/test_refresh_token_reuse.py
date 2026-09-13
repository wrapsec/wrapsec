# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Replaying a rotated refresh token must end every session for that user.

Rotation alone does not survive theft. When a refresh token is stolen, both the
thief and the legitimate client hold the same token; whoever presents it second
gets a 401 while the winner keeps a live session. The loser sees one failed
refresh, re-authenticates, and carries on -- beside the winner. Nothing
distinguishes that from a flaky network, so a stolen session survives
indefinitely and silently.

The signal that something is wrong is the replay itself: a token that was
issued, rotated away, and presented again. Acting on it revokes the family, which
forces both parties back to authentication -- something the legitimate user can
complete and the thief cannot.

Revoking more than strictly necessary is the intent, not a side effect. The
alternative is leaving a live session in unknown hands.
"""

from __future__ import annotations

import pytest

_LOGIN   = "/v1/auth/login"
_REFRESH = "/v1/auth/refresh"


# The refresh token is an httpOnly COOKIE at both ends -- it is never in a
# response body and the refresh endpoint reads `request.cookies`, not JSON. A
# test that posted it as a body field would be refused for a missing cookie and
# would prove nothing about replay.


async def _login(client, email: str, password: str = "TestPass1!") -> str:
    resp = await client.post(_LOGIN, json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    token = resp.cookies.get("refresh_token")
    assert token, f"login set no refresh cookie: {dict(resp.cookies)}"
    return token


async def _refresh(client, token: str):
    """Present a specific token, rather than whatever the client jar holds.

    The jar is overwritten by every rotation, so replaying an ANCESTOR means
    sending it explicitly.
    """
    return await client.post(_REFRESH, cookies={"refresh_token": token})


@pytest.mark.asyncio
async def test_a_rotated_token_replayed_is_refused(client, auth_setup):
    """The precondition: rotation works and the old token dies."""
    original = await _login(client, auth_setup["admin_user"].email)

    rotated = await _refresh(client, original)
    assert rotated.status_code == 200, rotated.text

    replay = await _refresh(client, original)
    assert replay.status_code == 401


@pytest.mark.asyncio
async def test_a_replay_also_kills_the_token_that_replaced_it(client, auth_setup):
    """The actual fix. Before it, the descendant kept working -- so a thief who
    lost the race kept the live session and the victim never learned of it."""
    original = await _login(client, auth_setup["admin_user"].email)

    rotated = await _refresh(client, original)
    assert rotated.status_code == 200
    descendant = rotated.cookies.get("refresh_token")
    assert descendant and descendant != original, "rotation did not issue a new token"

    # the thief replays the token they captured
    await _refresh(client, original)

    # the session that replaced it must no longer refresh
    after = await _refresh(client, descendant)
    assert after.status_code == 401, (
        "the descendant token still works after its ancestor was replayed: a "
        "stolen session survives the detection"
    )


@pytest.mark.asyncio
async def test_the_legitimate_user_can_still_authenticate_afterwards(client, auth_setup):
    """Revoking the family must not lock the account out -- the recovery is
    exactly the thing the thief cannot do."""
    original = await _login(client, auth_setup["admin_user"].email)
    await _refresh(client, original)
    await _refresh(client, original)   # replay

    again = await client.post(
        _LOGIN, json={"email": auth_setup["admin_user"].email, "password": "TestPass1!"},
    )
    assert again.status_code == 200, (
        "the user cannot log in again after a replay revoked their sessions"
    )


@pytest.mark.asyncio
async def test_an_unknown_token_is_not_treated_as_a_replay(client, auth_setup, test_db):
    """A garbage token has no family to revoke. Treating it as a replay would
    let anyone end a session by guessing, which is a denial of service wearing
    the fix as a disguise."""
    from sqlalchemy import func, select

    from db.models import RefreshTokenModel

    live = await _login(client, auth_setup["admin_user"].email)

    resp = await _refresh(client, "not-a-real-token")
    assert resp.status_code == 401

    still_active = await test_db.scalar(
        select(func.count()).select_from(RefreshTokenModel)
        .where(RefreshTokenModel.revoked_at.is_(None))
    )
    assert still_active >= 1, "an unknown token revoked real sessions"

    ok = await _refresh(client, live)
    assert ok.status_code == 200, "a live session was ended by an unrelated bad token"


@pytest.mark.asyncio
async def test_the_replay_is_recorded_as_its_own_reason(client, auth_setup, test_db):
    """A replay and an ordinary bad token must be distinguishable in the event
    stream: one means a token escaped its owner and every session was revoked.

    This also pins that the reason is a KNOWN enum member -- the writer coerces
    it through the enum and its handler swallows the failure, so an unlisted
    reason produces a log line and no audit row at all.
    """
    from sqlalchemy import select

    from db.models import AuthEventModel

    original = await _login(client, auth_setup["admin_user"].email)
    await _refresh(client, original)
    await _refresh(client, original)   # replay

    reason = await test_db.scalar(
        select(AuthEventModel.failure_reason).where(
            AuthEventModel.failure_reason == "token_reuse_detected"
        )
    )
    assert reason == "token_reuse_detected", (
        "the replay was not recorded; either it was not detected, or the "
        "failure reason is not a member of the enum the writer coerces through"
    )


@pytest.mark.asyncio
async def test_a_replay_also_ends_access_tokens_already_issued(client, auth_setup):
    """Revoking refresh tokens alone stops renewal and nothing else.

    An access token minted moments before the replay would otherwise stay valid
    for the rest of its lifetime, so whoever won the race keeps a working
    credential against every authenticated endpoint until it expires. A replay
    is a compromise signal; the answer to it must not leave a usable credential
    behind.

    The access token is taken from the login that also issued the refresh token,
    so it is exactly the credential a thief would be holding.
    """
    email = auth_setup["viewer_user"].email

    login = await client.post(_LOGIN, json={"email": email, "password": "TestPass1!"})
    assert login.status_code == 200, login.text
    original = login.cookies.get("refresh_token")
    access   = login.json()["access_token"]
    headers  = {"Authorization": f"Bearer {access}"}

    # The access token works before anything goes wrong -- otherwise the
    # assertion below would pass for the wrong reason.
    before = await client.get("/v1/auth/me", headers=headers)
    assert before.status_code == 200, (
        f"the access token was already unusable, so this test proves nothing: {before.text}"
    )

    rotated = await _refresh(client, original)
    assert rotated.status_code == 200, rotated.text

    replay = await _refresh(client, original)
    assert replay.status_code == 401

    after = await client.get("/v1/auth/me", headers=headers)
    assert after.status_code == 401, (
        "an access token issued before the replay is still accepted; revoking "
        "refresh tokens stopped renewal but left a live credential in whichever "
        "hands won the race"
    )
