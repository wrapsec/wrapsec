# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
The migration chain, run on PostgreSQL.

`test_migrations.py` runs the chain on SQLite. That establishes table parity and
idempotence, but every PostgreSQL-only construct in the chain is skipped there,
by the migrations themselves: 0004 returns early unless the dialect is
postgresql, 0006's JSON-to-JSONB conversion has no SQLite meaning, 0010's
timestamptz swap is skipped where the type does not exist, and
`ck_api_keys_non_admin_tenant` carries a `_create_rule` that omits it on any
dialect but PostgreSQL. Those are precisely the parts that can only break in
production.

The integration tier's own schema is built with `Base.metadata.create_all`, not
Alembic, so it does not cover the chain either: it proves the MODELS work on
PostgreSQL, never that the migrations produce that schema.

Each test here therefore creates its own throwaway database on the PostgreSQL
server the tier is already using, runs `alembic upgrade head` into it, asserts
against the real schema, and drops it. Nothing touches the shared test database,
and no second test framework or container is introduced.

Alembic's env.py drives an async engine through `asyncio.run`, which cannot be
called inside a running loop, so every `command.*` call goes through a worker
thread.
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import JSON, DateTime, inspect, make_url, text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from db.models import Base

_REPO_ROOT     = Path(__file__).resolve().parents[2]
_MIGRATIONS    = _REPO_ROOT / "db" / "migrations"


def _alembic_config(url: str) -> Config:
    cfg = Config(str(_REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_MIGRATIONS))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def _head_revision() -> str:
    return ScriptDirectory.from_config(_alembic_config("postgresql+asyncpg:///")).get_current_head()


async def _upgrade(url: str, revision: str = "head") -> None:
    await asyncio.to_thread(command.upgrade, _alembic_config(url), revision)


async def _downgrade(url: str, revision: str) -> None:
    await asyncio.to_thread(command.downgrade, _alembic_config(url), revision)


@pytest_asyncio.fixture
async def migration_db(pg_url):
    """A brand-new, empty database on the same server, dropped afterwards.

    A fresh database is what makes this a migration test rather than a schema
    test: the chain has to build everything from nothing, exactly as it does on a
    real deployment.
    """
    base   = make_url(pg_url)
    dbname = "wrapsec_mig_" + uuid.uuid4().hex[:12]
    # render_as_string(hide_password=False): str(URL) masks the password as
    # "***", which reaches the driver verbatim and fails authentication.
    admin  = base.set(database="postgres").render_as_string(hide_password=False)
    target = base.set(database=dbname).render_as_string(hide_password=False)

    engine = create_async_engine(admin, isolation_level="AUTOCOMMIT", poolclass=NullPool)
    async with engine.connect() as conn:
        await conn.execute(text(f'CREATE DATABASE "{dbname}"'))
    await engine.dispose()

    try:
        yield target
    finally:
        engine = create_async_engine(admin, isolation_level="AUTOCOMMIT", poolclass=NullPool)
        async with engine.connect() as conn:
            # Any lingering session would block the drop and leave the database
            # behind for the next run to trip over.
            await conn.execute(text(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = :name AND pid <> pg_backend_pid()"
            ), {"name": dbname})
            await conn.execute(text(f'DROP DATABASE IF EXISTS "{dbname}"'))
        await engine.dispose()


async def _fetch(url: str, sql: str, **params):
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            return (await conn.execute(text(sql), params or None)).fetchall()
    finally:
        await engine.dispose()


# ── the chain itself ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_chain_reaches_head_and_creates_every_model_table(migration_db):
    await _upgrade(migration_db)

    stamped = await _fetch(migration_db, "SELECT version_num FROM alembic_version")
    assert [r[0] for r in stamped] == [_head_revision()]

    engine = create_async_engine(migration_db, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            tables = set(await conn.run_sync(lambda c: inspect(c).get_table_names()))
    finally:
        await engine.dispose()

    missing = set(Base.metadata.tables) - tables
    assert not missing, f"migration chain missing tables on PostgreSQL: {sorted(missing)}"


@pytest.mark.asyncio
async def test_chain_is_idempotent_on_postgres(migration_db):
    """Re-running the chain is the in-place upgrade path; on PostgreSQL it also
    re-executes the trigger and conversion migrations, which SQLite skips."""
    await _upgrade(migration_db)
    await _upgrade(migration_db)

    stamped = await _fetch(migration_db, "SELECT version_num FROM alembic_version")
    assert [r[0] for r in stamped] == [_head_revision()]


@pytest.mark.asyncio
async def test_head_revision_downgrades_and_reapplies(migration_db):
    head = _head_revision()
    await _upgrade(migration_db)

    await _downgrade(migration_db, "-1")
    stepped_back = await _fetch(migration_db, "SELECT version_num FROM alembic_version")
    assert [r[0] for r in stepped_back] != [head]

    await _upgrade(migration_db)
    assert [r[0] for r in await _fetch(migration_db, "SELECT version_num FROM alembic_version")] == [head]


# ── the PostgreSQL-only constructs ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_audit_immutability_trigger_is_installed_by_the_chain(migration_db):
    """0004 is a no-op on SQLite, so nothing has ever proven the chain installs
    this. The tamper-evidence claim rests on it."""
    await _upgrade(migration_db)

    triggers = await _fetch(
        migration_db,
        "SELECT tgname FROM pg_trigger WHERE tgname = 'audit_logs_no_update_on_chained'",
    )
    assert [r[0] for r in triggers] == ["audit_logs_no_update_on_chained"]


@pytest.mark.asyncio
async def test_a_chained_audit_row_cannot_be_updated(migration_db):
    """The behaviour, not just the catalog entry: a row carrying a record_hash is
    immutable, and one without a hash is still writable."""
    from sqlalchemy.exc import DBAPIError

    await _upgrade(migration_db)

    insert = """
        INSERT INTO audit_logs (
            id, trace_id, decision, risk_score, threats, input_hash,
            detection_mode, execution_mode, llm_invoked, latency_ms,
            attribution_verified, created_at, record_hash
        ) VALUES (
            :id, :trace_id, 'ALLOW', 0.1, '[]'::jsonb, 'h',
            'fast', 'scan_only', false, 1.0, false, now(), :record_hash
        )
    """
    chained, unchained = uuid.uuid4(), uuid.uuid4()

    engine = create_async_engine(migration_db, poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.execute(text(insert), {
                "id": chained, "trace_id": "req_chained", "record_hash": "abc123",
            })
            await conn.execute(text(insert), {
                "id": unchained, "trace_id": "req_unchained", "record_hash": None,
            })

        with pytest.raises(DBAPIError) as caught:
            async with engine.begin() as conn:
                await conn.execute(
                    text("UPDATE audit_logs SET decision = 'BLOCK' WHERE id = :id"),
                    {"id": chained},
                )
        assert "chain-locked" in str(caught.value)

        # The trigger is scoped to chained rows; it must not freeze the table.
        async with engine.begin() as conn:
            await conn.execute(
                text("UPDATE audit_logs SET decision = 'BLOCK' WHERE id = :id"),
                {"id": unchained},
            )
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_every_json_column_lands_as_jsonb(migration_db):
    """0006 exists because the code queries these columns with jsonb operators,
    which fail against `json`. The expected set is derived from the models, so a
    new JSON column is covered without editing this test."""
    await _upgrade(migration_db)

    expected = {
        (table.name, column.name)
        for table in Base.metadata.tables.values()
        for column in table.columns
        if isinstance(column.type, JSON)
    }
    assert expected, "no JSON columns found in the models; the assertion below would be vacuous"

    rows = await _fetch(
        migration_db,
        "SELECT table_name, column_name, data_type FROM information_schema.columns "
        "WHERE table_schema = 'public' AND data_type IN ('json', 'jsonb')",
    )
    actual = {(t, c): d for t, c, d in rows}

    not_jsonb = {key: actual.get(key) for key in expected if actual.get(key) != "jsonb"}
    assert not not_jsonb, f"columns not at jsonb after the chain: {not_jsonb}"


@pytest.mark.asyncio
async def test_a_jsonb_operator_works_on_the_migrated_schema(migration_db):
    """The failure 0006 was written for was a runtime one:
    `jsonb_array_elements_text(json) does not exist`. Run the operator."""
    await _upgrade(migration_db)

    engine = create_async_engine(migration_db, poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.execute(text("""
                INSERT INTO audit_logs (
                    id, trace_id, decision, risk_score, threats, input_hash,
                    detection_mode, execution_mode, llm_invoked, latency_ms,
                    attribution_verified, created_at
                ) VALUES (
                    :id, :trace_id, 'BLOCK', 0.9, '["prompt_injection"]'::jsonb, 'h',
                    'fast', 'scan_only', false, 1.0, false, now()
                )
            """), {"id": uuid.uuid4(), "trace_id": "req_" + uuid.uuid4().hex})

        async with engine.connect() as conn:
            found = (await conn.execute(text(
                "SELECT count(*) FROM audit_logs, "
                "jsonb_array_elements_text(threats) AS threat "
                "WHERE threat = 'prompt_injection'"
            ))).scalar_one()
    finally:
        await engine.dispose()

    assert found == 1


@pytest.mark.asyncio
async def test_every_timestamp_column_lands_as_timestamptz(migration_db):
    """0010 rebuilds these columns; a naive one anywhere reintroduces the bug the
    aware-UTC conversion closed."""
    await _upgrade(migration_db)

    expected = {
        (table.name, column.name)
        for table in Base.metadata.tables.values()
        for column in table.columns
        if isinstance(column.type, DateTime)
    }
    assert expected, "no DateTime columns found in the models"

    rows = await _fetch(
        migration_db,
        "SELECT table_name, column_name, data_type FROM information_schema.columns "
        "WHERE table_schema = 'public' AND data_type LIKE 'timestamp%'",
    )
    actual = {(t, c): d for t, c, d in rows}

    naive = {
        key: actual.get(key)
        for key in expected
        if actual.get(key) != "timestamp with time zone"
    }
    assert not naive, f"columns not timestamptz after the chain: {naive}"


@pytest.mark.asyncio
async def test_non_admin_key_check_constraint_is_enforced(migration_db):
    """`ck_api_keys_non_admin_tenant` is omitted on SQLite by its own
    `_create_rule`, so the model comment's warning -- that invalid key rows are
    not caught until the production schema is exercised -- has been literally
    true of the whole suite. Exercise it."""
    from sqlalchemy.exc import IntegrityError

    await _upgrade(migration_db)

    tenant_id = uuid.uuid4()
    engine = create_async_engine(migration_db, poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.execute(text(
                "INSERT INTO tenants (id, slug, name, status, created_at) "
                "VALUES (:id, :slug, 'T', 'active', now())"
            ), {"id": tenant_id, "slug": "t-" + tenant_id.hex[:8]})

        key_insert = """
            INSERT INTO api_keys (
                id, key_id, tenant_id, dept_id, name, key_hash,
                key_type, is_admin, revoked, created_at
            ) VALUES (
                :id, :key_id, :tenant_id, :dept_id, 'k', :key_hash,
                'live', :is_admin, false, now()
            )
        """

        # A non-admin key with no department violates the constraint.
        with pytest.raises(IntegrityError) as caught:
            async with engine.begin() as conn:
                await conn.execute(text(key_insert), {
                    "id": uuid.uuid4(), "key_id": "key_bad", "tenant_id": tenant_id,
                    "dept_id": None, "key_hash": "h_bad", "is_admin": False,
                })
        assert "ck_api_keys_non_admin_tenant" in str(caught.value)

        # An admin key legitimately carries no department.
        async with engine.begin() as conn:
            await conn.execute(text(key_insert), {
                "id": uuid.uuid4(), "key_id": "key_admin", "tenant_id": tenant_id,
                "dept_id": None, "key_hash": "h_admin", "is_admin": True,
            })
    finally:
        await engine.dispose()


# ── the conversions, actually converting ─────────────────────────────────────
#
# On a fresh database 0001's create_all already produces jsonb and timestamptz
# columns, so 0006 and 0010 find nothing to do and the two end-state assertions
# above pass without either migration converting anything. The conversions only
# matter for a database that predates them, so the pre-migration state is staged
# here by downgrading the chain to the revision just before each one -- using the
# migrations' own downgrades, rather than hand-written DDL that could stage a
# state the chain never actually produces.

# No column may remain `json` after the chain. This was previously pinned to
# {("api_keys", "ip_allowlist")}: 0022 adds that column as `sa.JSON()` rather than
# the JSONVariant the model declares, and it postdates 0006's target list, so a
# database that reached head by UPGRADING had `json` where a fresh install had
# `jsonb`. 0024 closes it. The set stays here, empty, so a future column adding
# the same divergence fails this assertion rather than being absorbed silently.
_KNOWN_JSON_NOT_JSONB: set[tuple[str, str]] = set()


async def _column_types(url: str, where: str) -> dict[tuple[str, str], str]:
    rows = await _fetch(
        url,
        "SELECT table_name, column_name, data_type FROM information_schema.columns "
        f"WHERE table_schema = 'public' AND {where}",
    )
    return {(t, c): d for t, c, d in rows}


@pytest.mark.asyncio
async def test_json_columns_are_converted_when_the_chain_finds_them_as_json(migration_db):
    await _upgrade(migration_db)
    await _downgrade(migration_db, "0005_add_auditor_role")

    staged = await _column_types(migration_db, "data_type IN ('json', 'jsonb')")
    assert "json" in staged.values(), (
        "staging produced no json columns, so this test would pass without 0006 "
        "converting anything"
    )

    await _upgrade(migration_db)

    converted = await _column_types(migration_db, "data_type IN ('json', 'jsonb')")
    still_json = {k for k, v in converted.items() if v != "jsonb"}
    assert still_json == _KNOWN_JSON_NOT_JSONB, (
        f"json/jsonb divergence changed: {sorted(still_json)}"
    )


@pytest.mark.asyncio
async def test_timestamps_are_converted_when_the_chain_finds_them_naive(migration_db):
    await _upgrade(migration_db)
    await _downgrade(migration_db, "0009_webhook_connector_type")

    staged = await _column_types(migration_db, "data_type LIKE 'timestamp%'")
    assert "timestamp without time zone" in staged.values(), (
        "staging produced no naive timestamp columns, so this test would pass "
        "without 0010 converting anything"
    )

    await _upgrade(migration_db)

    converted = await _column_types(migration_db, "data_type LIKE 'timestamp%'")
    naive = {k: v for k, v in converted.items() if v != "timestamp with time zone"}
    assert not naive, f"columns left naive after the chain re-ran: {naive}"


# ── api_keys.ip_allowlist: json on the upgrade path, jsonb everywhere now ─────
#
# The column's type used to depend on how a database reached head -- `jsonb` from
# the baseline's create_all on a fresh install, `json` from 0022's `sa.JSON()` on
# an upgrade -- so two deployments at the same revision had different schemas.
# 0024 converts it. These cases prove the conversion on the path that actually
# produced the divergence, and that no allowlist changes value in either
# direction.

_IP_ALLOWLIST_COL = ("api_keys", "ip_allowlist")

# NULL (control off), empty list (also off), and a populated list, because the
# absent and empty cases are the ones a cast is most likely to mangle.
_ALLOWLISTS = {
    "key_null":  None,
    "key_empty": [],
    "key_full":  ["10.0.0.0/8", "192.168.1.1/32", "2001:db8::/32"],
}


async def _ip_allowlist_type(url: str) -> str | None:
    types = await _column_types(url, "data_type IN ('json', 'jsonb')")
    return types.get(_IP_ALLOWLIST_COL)


async def _seed_keys_with_allowlists(url: str) -> None:
    """Insert one key per allowlist shape while the column is still `json`.

    The cast is written as `json` because that is the column's type at the point
    this is called; casting to the target type would beg the question the test is
    asking.
    """
    tenant_id = uuid.uuid4()
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.execute(text(
                "INSERT INTO tenants (id, slug, name, status, created_at) "
                "VALUES (:id, :slug, 'T', 'active', now())"
            ), {"id": tenant_id, "slug": "t-" + tenant_id.hex[:8]})

            for key_id, allowlist in _ALLOWLISTS.items():
                await conn.execute(text("""
                    INSERT INTO api_keys (
                        id, key_id, tenant_id, dept_id, name, key_hash,
                        key_type, is_admin, revoked, ip_allowlist, created_at
                    ) VALUES (
                        :id, :key_id, :tenant_id, NULL, 'k', :key_hash,
                        'live', true, false, CAST(:allowlist AS json), now()
                    )
                """), {
                    "id":        uuid.uuid4(),
                    "key_id":    key_id,
                    "tenant_id": tenant_id,
                    "key_hash":  "h_" + key_id,
                    # NULL stays NULL rather than becoming the JSON literal null.
                    "allowlist": None if allowlist is None else json.dumps(allowlist),
                })
    finally:
        await engine.dispose()


async def _stored_allowlists(url: str) -> dict[str, object]:
    """Read the allowlists back as Python values.

    Cast to text and parse, rather than comparing raw column output: jsonb
    normalises whitespace and key order, so a textual comparison would report a
    difference that is not one.
    """
    rows = await _fetch(
        url,
        "SELECT key_id, ip_allowlist::text FROM api_keys "
        "WHERE key_id IN ('key_null', 'key_empty', 'key_full')",
    )
    return {key_id: (json.loads(value) if value is not None else None) for key_id, value in rows}


async def _stage_upgrade_path(url: str) -> None:
    """Reach 0023 the way a pre-0022 deployment does.

    Downgrading below 0022 drops the column; upgrading back to 0023 makes 0022
    re-add it, which is the step that produces `json`. Stopping at 0023 leaves the
    database in the exact state 0024 was written for.
    """
    await _upgrade(url)
    await _downgrade(url, "0021_proxy_scan_latency")
    await _upgrade(url, "0023_auth_event_key_id")


@pytest.mark.asyncio
async def test_ip_allowlist_is_jsonb_on_a_fresh_install(migration_db):
    await _upgrade(migration_db)

    assert await _ip_allowlist_type(migration_db) == "jsonb"


@pytest.mark.asyncio
async def test_ip_allowlist_is_json_before_the_conversion(migration_db):
    """The staging itself, asserted: without this the conversion case below could
    pass while testing nothing."""
    await _stage_upgrade_path(migration_db)

    assert await _ip_allowlist_type(migration_db) == "json"


@pytest.mark.asyncio
async def test_ip_allowlist_converts_to_jsonb_on_the_upgrade_path(migration_db):
    await _stage_upgrade_path(migration_db)
    assert await _ip_allowlist_type(migration_db) == "json"

    await _upgrade(migration_db)

    assert await _ip_allowlist_type(migration_db) == "jsonb"


@pytest.mark.asyncio
async def test_existing_allowlists_survive_the_conversion(migration_db):
    """Rows written before the conversion must read back identically after it --
    NULL still NULL, empty still empty, entries in order."""
    await _stage_upgrade_path(migration_db)
    await _seed_keys_with_allowlists(migration_db)
    assert await _stored_allowlists(migration_db) == _ALLOWLISTS

    await _upgrade(migration_db)

    assert await _ip_allowlist_type(migration_db) == "jsonb"
    assert await _stored_allowlists(migration_db) == _ALLOWLISTS


@pytest.mark.asyncio
async def test_the_conversion_round_trips_with_its_data(migration_db):
    """Down to json, back up to jsonb, with the rows unchanged throughout. A
    downgrade that loses an allowlist would silently widen every key it touched
    from a restricted set of networks to unrestricted."""
    await _stage_upgrade_path(migration_db)
    await _seed_keys_with_allowlists(migration_db)
    await _upgrade(migration_db)
    assert await _ip_allowlist_type(migration_db) == "jsonb"

    await _downgrade(migration_db, "0023_auth_event_key_id")

    assert await _ip_allowlist_type(migration_db) == "json"
    assert await _stored_allowlists(migration_db) == _ALLOWLISTS

    await _upgrade(migration_db)

    assert await _ip_allowlist_type(migration_db) == "jsonb"
    assert await _stored_allowlists(migration_db) == _ALLOWLISTS


@pytest.mark.asyncio
async def test_the_conversion_is_idempotent_in_both_directions(migration_db):
    """Both directions are guarded by the column's current type, so re-running
    either must be a no-op rather than an error."""
    await _upgrade(migration_db)
    await _upgrade(migration_db)
    assert await _ip_allowlist_type(migration_db) == "jsonb"

    await _downgrade(migration_db, "0023_auth_event_key_id")
    await _downgrade(migration_db, "0023_auth_event_key_id")
    assert await _ip_allowlist_type(migration_db) == "json"


# ── 0025: a data migration, tested with data present ─────────────────────────
#
# Every test above upgrades into an EMPTY database, which is the one condition
# under which a backfill does nothing. 0025 shipped broken for exactly that
# reason: its backfill writes chain_seq to every chained row, 0004 installed a
# trigger that refuses any update to a chained row, and with no rows present the
# two never met. On a real deployment the migration aborted and the API
# crash-looped on startup.
#
# So these stop one revision short, put rows in, and then migrate.

_PRE   = "0024_ip_allowlist_jsonb"
_UNDER = "0025_audit_chain_sequence"

_AUDIT_INSERT = """
    INSERT INTO audit_logs (
        id, tenant_id, trace_id, decision, risk_score, threats, input_hash,
        detection_mode, execution_mode, llm_invoked, latency_ms,
        attribution_verified, created_at, record_hash
    ) VALUES (
        :id, :tenant_id, :trace_id, 'ALLOW', 0.1, '[]'::jsonb, 'h',
        'fast', 'scan_only', false, 1.0, false, :created_at, :record_hash
    )
"""

def _at(second: int) -> datetime:
    """An aware UTC instant. asyncpg binds timestamptz from a datetime, never a
    string, and the column is timestamptz end to end."""
    return datetime(2026, 1, 1, 10, 0, second, tzinfo=timezone.utc)


# Two tenants so the per-tenant partitioning is actually exercised, rows out of
# insertion order by timestamp so the ordering is not accidentally satisfied,
# and one unchained row, which must be left alone.
_ROWS = [
    # (tenant, trace, created_at, record_hash, expected chain_seq)
    ("tenant-a", "req_a2",   _at(2), "hash-a2", 2),
    ("tenant-a", "req_a1",   _at(1), "hash-a1", 1),
    ("tenant-a", "req_a3",   _at(3), "hash-a3", 3),
    ("tenant-b", "req_b2",   _at(2), "hash-b2", 2),
    ("tenant-b", "req_b1",   _at(1), "hash-b1", 1),
    ("tenant-a", "req_none", _at(4), None,      None),
]


async def _seed_audit_rows(url: str) -> dict[str, uuid.UUID]:
    """Write the rows at 0024, before chain_seq exists."""
    ids: dict[str, uuid.UUID] = {}
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            for tenant, trace, created, record_hash, _ in _ROWS:
                ids[trace] = uuid.uuid4()
                await conn.execute(text(_AUDIT_INSERT), {
                    "id": ids[trace], "tenant_id": tenant, "trace_id": trace,
                    "created_at": created, "record_hash": record_hash,
                })
    finally:
        await engine.dispose()
    return ids


@pytest.mark.asyncio
async def test_the_chain_seq_backfill_runs_on_a_populated_audit_table(migration_db):
    """The regression. Before the fix this raised and the chain never advanced.

    The failure was not subtle -- the migration aborted outright -- but it was
    invisible, because nothing ever ran it against a row it had to touch.
    """
    await _upgrade(migration_db, _PRE)
    await _seed_audit_rows(migration_db)

    await _upgrade(migration_db, _UNDER)          # must not raise

    rows = await _fetch(migration_db, """
        SELECT tenant_id, trace_id, chain_seq
          FROM audit_logs
         ORDER BY tenant_id, chain_seq NULLS LAST
    """)
    got = {r.trace_id: r.chain_seq for r in rows}

    for _tenant, trace, _created, _hash, expected in _ROWS:
        assert got[trace] == expected, (
            f"{trace} was numbered {got[trace]}, expected {expected}"
        )


@pytest.mark.asyncio
async def test_the_backfill_numbers_each_tenant_densely_from_one(migration_db):
    """Per tenant, in created_at order, with no gaps.

    A gap would be indistinguishable from a row removed by retention, and the
    verifier reads this sequence to decide whether a chain is intact.
    """
    await _upgrade(migration_db, _PRE)
    await _seed_audit_rows(migration_db)
    await _upgrade(migration_db, _UNDER)

    for tenant, expected_count in (("tenant-a", 3), ("tenant-b", 2)):
        rows = await _fetch(migration_db, """
            SELECT chain_seq FROM audit_logs
             WHERE tenant_id = :t AND record_hash IS NOT NULL
             ORDER BY chain_seq
        """, t=tenant)
        assert [r.chain_seq for r in rows] == list(range(1, expected_count + 1)), (
            f"{tenant} is not numbered 1..{expected_count} without gaps"
        )


@pytest.mark.asyncio
async def test_the_backfill_leaves_every_stored_hash_byte_for_byte(migration_db):
    """The whole table is tamper-evidence; a backfill that rewrote a hash would
    destroy the only evidence those rows carry.

    Safe because chain_seq is not hashed under format 1 -- only
    CANONICAL_FIELDS_V2 includes it -- and this asserts that rather than assuming
    it.
    """
    await _upgrade(migration_db, _PRE)
    await _seed_audit_rows(migration_db)

    before = {
        r.trace_id: r.record_hash
        for r in await _fetch(migration_db, "SELECT trace_id, record_hash FROM audit_logs")
    }

    await _upgrade(migration_db, _UNDER)

    after = {
        r.trace_id: (r.record_hash, r.chain_format)
        for r in await _fetch(
            migration_db, "SELECT trace_id, record_hash, chain_format FROM audit_logs")
    }

    for trace, stored in before.items():
        assert after[trace][0] == stored, f"{trace} had its record_hash rewritten"
        assert after[trace][1] == 1, (
            f"{trace} was moved to format {after[trace][1]}; rows hashed without "
            f"chain_seq must stay verifiable under the field set they were "
            f"hashed with"
        )


@pytest.mark.asyncio
async def test_an_unchained_row_is_not_given_a_position(migration_db):
    """A row written before the chain existed belongs to no chain, and numbering
    it would say otherwise."""
    await _upgrade(migration_db, _PRE)
    await _seed_audit_rows(migration_db)
    await _upgrade(migration_db, _UNDER)

    rows = await _fetch(migration_db, """
        SELECT chain_seq FROM audit_logs WHERE record_hash IS NULL
    """)
    assert [r.chain_seq for r in rows] == [None]


@pytest.mark.asyncio
async def test_the_immutability_trigger_is_re_armed_after_the_backfill(migration_db):
    """The migration suspends the trigger to do its work. If it ever failed to
    put it back, the audit table would be silently writable from then on and the
    next thing to notice would be a trail nobody could trust."""
    from sqlalchemy.exc import DBAPIError

    await _upgrade(migration_db, _PRE)
    ids = await _seed_audit_rows(migration_db)
    await _upgrade(migration_db, _UNDER)

    # Cast in SQL: pg_trigger.tgenabled is the "char" type, which asyncpg hands
    # back as bytes (b"O"), so comparing it to a str silently never matches.
    enabled = await _fetch(migration_db, """
        SELECT tgenabled::text AS enabled FROM pg_trigger
         WHERE tgrelid = 'audit_logs'::regclass
           AND tgname  = 'audit_logs_no_update_on_chained'
    """)
    assert [r.enabled for r in enabled] == ["O"], "the trigger was left disabled"

    engine = create_async_engine(migration_db, poolclass=NullPool)
    try:
        with pytest.raises(DBAPIError) as caught:
            async with engine.begin() as conn:
                await conn.execute(
                    text("UPDATE audit_logs SET decision = 'BLOCK' WHERE id = :id"),
                    {"id": ids["req_a1"]},
                )
        assert "chain-locked" in str(caught.value)
    finally:
        await engine.dispose()
