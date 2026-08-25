# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Baseline migration smoke tests.

These verify that:
  1. `alembic upgrade head` runs cleanly against a fresh database and
     produces the same set of tables that `Base.metadata.create_all()` does.
  2. Running it a second time is a no-op (idempotent -- required for the
     v1.0.11 -> v1.1.0 in-place upgrade path).
"""
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from db.models import Base

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _alembic_config(sqlite_url: str) -> Config:
    cfg = Config(str(_REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_REPO_ROOT / "db" / "migrations"))
    cfg.set_main_option("sqlalchemy.url", sqlite_url)
    return cfg


def _tables(url: str) -> set[str]:
    engine = create_engine(url)
    try:
        return {t for t in inspect(engine).get_table_names() if t != "alembic_version"}
    finally:
        engine.dispose()


def test_baseline_migration_creates_all_model_tables(tmp_path):
    db_file   = tmp_path / "migrated.db"
    async_url = f"sqlite+aiosqlite:///{db_file}"
    sync_url  = f"sqlite:///{db_file}"

    # env.py builds an async engine from sqlalchemy.url, so we pass the
    # aiosqlite driver here. Inspection later uses the sync driver on the
    # same file.
    cfg = _alembic_config(async_url)
    command.upgrade(cfg, "head")

    created  = _tables(sync_url)
    expected = set(Base.metadata.tables.keys())
    missing  = expected - created
    assert not missing, f"baseline migration missing tables: {sorted(missing)}"


def test_baseline_migration_is_idempotent(tmp_path):
    db_file   = tmp_path / "migrated.db"
    async_url = f"sqlite+aiosqlite:///{db_file}"
    sync_url  = f"sqlite:///{db_file}"

    cfg = _alembic_config(async_url)
    command.upgrade(cfg, "head")
    command.upgrade(cfg, "head")  # must be a no-op

    created = _tables(sync_url)
    assert "tenants" in created


def test_head_revision_advances_to_json_to_jsonb(tmp_path):
    """
    After `alembic upgrade head`, alembic_version must point at the newest
    migration. Locks in that new revisions are actually being picked up (a
    common failure mode is dropping the file into the wrong directory and
    silently landing on 0001). The expected head is read from the migration
    scripts so this never goes stale as new revisions land.
    """
    db_file   = tmp_path / "migrated.db"
    async_url = f"sqlite+aiosqlite:///{db_file}"
    sync_url  = f"sqlite:///{db_file}"

    cfg = _alembic_config(async_url)
    command.upgrade(cfg, "head")

    from alembic.script import ScriptDirectory
    expected_head = ScriptDirectory.from_config(cfg).get_current_head()

    engine = create_engine(sync_url)
    try:
        with engine.connect() as conn:
            from sqlalchemy import text
            row = conn.execute(text("SELECT version_num FROM alembic_version")).fetchone()
    finally:
        engine.dispose()

    assert row is not None
    assert row[0] == expected_head
    # A concrete lower bound so a broken ScriptDirectory can't make this vacuous.
    assert row[0] != "0001_baseline"


def test_audit_logs_has_v1_2_session_and_hash_columns(tmp_path):
    """
    v1.2.0 adds session_id/turn_index/run_id (caller-supplied tracking)
    plus record_hash/prev_hash (tamper-evident chain) to audit_logs.
    All five must be present and nullable after upgrade -- the hash writer
    and the UPDATE-blocking trigger land in later commits, so existing
    rows must be free to stay NULL.
    """
    db_file   = tmp_path / "migrated.db"
    async_url = f"sqlite+aiosqlite:///{db_file}"
    sync_url  = f"sqlite:///{db_file}"

    cfg = _alembic_config(async_url)
    command.upgrade(cfg, "head")

    engine = create_engine(sync_url)
    try:
        cols = {c["name"]: c for c in inspect(engine).get_columns("audit_logs")}
    finally:
        engine.dispose()

    for name in ("session_id", "turn_index", "run_id", "record_hash", "prev_hash"):
        assert name in cols, f"audit_logs missing v1.2.0 column: {name}"
        assert cols[name]["nullable"] is True, f"audit_logs.{name} must be nullable"


# ---------------------------------------------------------------------------
# Reversibility
# ---------------------------------------------------------------------------

def _columns(url: str, table: str) -> set[str]:
    engine = create_engine(url)
    try:
        inspector = inspect(engine)
        if table not in inspector.get_table_names():
            return set()
        return {c["name"] for c in inspector.get_columns(table)}
    finally:
        engine.dispose()


def test_recent_migrations_reverse_and_reapply(tmp_path):
    """
    A downgrade path that is never exercised is a downgrade path that does not
    work. Nothing here called downgrade before, so each of these was only ever
    verified by hand, which is not a thing CI can repeat.

    Steps down through the migrations that added columns, checks each column is
    gone, then steps back up and checks it returns. Re-applying matters as much
    as reversing: an operator who rolls back to investigate has to be able to
    roll forward again.
    """
    db_file   = tmp_path / "reversible.db"
    async_url = f"sqlite+aiosqlite:///{db_file}"
    sync_url  = f"sqlite:///{db_file}"
    cfg       = _alembic_config(async_url)

    command.upgrade(cfg, "head")

    # (revision that adds them, table, columns it adds)
    steps = [
        ("0023_auth_event_key_id",   "auth_events",        {"key_id"}),
        ("0022_api_key_ip_allowlist", "api_keys",          {"ip_allowlist"}),
        ("0021_proxy_scan_latency",  "proxy_interactions", {"input_scan_ms", "output_scan_ms"}),
    ]

    # Land on the newest revision this test walks before stepping down. The walk
    # below moves by "-1" and asserts on the column the revision it just left
    # behind had added, so it only lines up when the starting point is steps[0].
    # Anchoring here keeps that true as revisions are added on top: without it
    # every new head offsets the walk by one, and the first assertion fails
    # against a column that is still applied.
    command.downgrade(cfg, steps[0][0])

    for revision, table, added in steps:
        assert added <= _columns(sync_url, table), (
            f"{revision} did not leave {added} on {table}"
        )

    # walk back down through all three
    for revision, table, added in steps:
        command.downgrade(cfg, "-1")
        assert not (added & _columns(sync_url, table)), (
            f"{revision} downgrade left {added & _columns(sync_url, table)} behind"
        )

    # and forward again
    command.upgrade(cfg, "head")
    for revision, table, added in steps:
        assert added <= _columns(sync_url, table), (
            f"{revision} did not restore {added} on re-upgrade"
        )
