# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Configuration written by one test must not be visible to the next.

Settings are the one kind of state a test writes through the API that another
test then reads as though an operator had configured it. A test asserting a
default -- "nothing is stored, so the value comes from the environment" -- passes
in isolation and fails after any earlier test stored one.

That was a real failure, not a hypothetical: running `test_api_settings.py` twice
against the same database produced

    assert r.json()["source"] == "environment"
    AssertionError: assert 'database' == 'environment'

in three tests, because `tenant_settings` was not in the per-test TRUNCATE.
`make test-integration` never showed it -- it builds a fresh container per run --
so it surfaced only when a container was reused, which made it look like
flakiness instead of missing cleanup.

The tests below are ORDER-DEPENDENT BY DESIGN, in file order: the first writes a
setting, the second asserts the default is back. That is the whole point. Do not
reorder them, mark them independent, or "fix" the second by seeding what it
needs -- the second test's job is to prove it inherited nothing.
"""

import pytest

_STORED_LIMITS = {"max_departments": 7, "max_applications": 11}


@pytest.mark.asyncio
async def test_a_stored_setting_is_reported_as_coming_from_the_database(
    client, admin_jwt_headers, test_db,
):
    """Writes configuration, and confirms the API reports it as stored.

    This is the polluting half. It also proves the write actually landed -- if it
    silently failed, the next test would pass for the wrong reason and this file
    would guard nothing.
    """
    # Written with the ADMIN JWT: the write is role-gated, and the admin API key
    # carries no tenant under TESTING, so it cannot store per-tenant settings.
    put = await client.put(
        "/v1/settings/admin_limits", json=_STORED_LIMITS, headers=admin_jwt_headers,
    )
    assert put.status_code == 200, put.text

    got = await client.get("/v1/settings/admin_limits", headers=admin_jwt_headers)
    assert got.status_code == 200
    assert got.json()["source"] == "database", (
        "the write did not take effect, so the isolation test below would pass "
        "trivially"
    )


@pytest.mark.asyncio
async def test_the_next_test_sees_the_environment_default_again(
    client, admin_headers, test_db,
):
    """The invariant. Runs immediately after a test that stored a value, and must
    still see the environment default."""
    got = await client.get("/v1/settings/admin_limits", headers=admin_headers)

    assert got.status_code == 200
    assert got.json()["source"] == "environment", (
        "configuration written by the previous test survived into this one. "
        "The per-test TRUNCATE in conftest.py must clear the configuration "
        "tables, not only the high-churn ones."
    )


@pytest.mark.asyncio
async def test_the_configuration_tables_start_empty(test_db):
    """Directly, at the table level, so the guarantee does not depend on one
    endpoint's notion of `source`. Named tables rather than a query over the
    fixture's own list: this must fail if a table is dropped from that list."""
    from sqlalchemy import text

    for table in ("tenant_settings", "platform_settings", "proxy_provider_configs"):
        count = (await test_db.execute(text(f"SELECT count(*) FROM {table}"))).scalar_one()
        assert count == 0, (
            f"{table} carried {count} row(s) into this test; it is not being "
            "cleared between tests"
        )


@pytest.mark.asyncio
async def test_seed_identity_is_deliberately_preserved(test_db):
    """The other half of the contract, so a later change does not "improve"
    cleanup by truncating everything: the seeded tenant must survive, because the
    tier's own admin credentials resolve against it."""
    from sqlalchemy import text

    tenants = (await test_db.execute(text("SELECT count(*) FROM tenants"))).scalar_one()
    assert tenants > 0, (
        "the seeded default tenant was truncated; identity tables are seeded once "
        "per session and the auth fixtures depend on them"
    )
