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

import pytest
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


def test_head_revision_advances_to_add_auditor_role(tmp_path):
    """
    After `alembic upgrade head`, alembic_version must point at the newest
    v1.2.0 migration. Locks in that new revisions are actually being picked
    up (a common failure mode is dropping the file into the wrong directory
    and silently landing on 0001). Bump this assertion in lock-step with the
    latest revision file.
    """
    db_file   = tmp_path / "migrated.db"
    async_url = f"sqlite+aiosqlite:///{db_file}"
    sync_url  = f"sqlite:///{db_file}"

    cfg = _alembic_config(async_url)
    command.upgrade(cfg, "head")

    engine = create_engine(sync_url)
    try:
        with engine.connect() as conn:
            from sqlalchemy import text
            row = conn.execute(text("SELECT version_num FROM alembic_version")).fetchone()
    finally:
        engine.dispose()

    assert row is not None
    assert row[0] == "0005_add_auditor_role"


def test_users_check_constraint_admits_auditor(tmp_path):
    """
    Migration 0005 rewrites ck_users_role and ck_users_dept_required_v2 so
    a row with role='AUDITOR' and either NULL or set dept_id is accepted.
    An INSERT that would violate the old constraint but satisfy the new
    one proves the migration ran on the SQLite path (batch_alter_table).
    """
    import uuid
    from datetime import datetime
    from sqlalchemy import text

    db_file   = tmp_path / "migrated.db"
    async_url = f"sqlite+aiosqlite:///{db_file}"
    sync_url  = f"sqlite:///{db_file}"

    cfg = _alembic_config(async_url)
    command.upgrade(cfg, "head")

    tenant_id = str(uuid.uuid4())
    user_id   = str(uuid.uuid4())

    engine = create_engine(sync_url)
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO tenants "
                    "(id, name, slug, global_policy, created_at, is_active) "
                    "VALUES (:id, :name, :slug, :policy, :ts, :active)"
                ),
                {
                    "id":     tenant_id,
                    "name":   "auditor-test-tenant",
                    "slug":   "auditor-test",
                    "policy": "{}",
                    "ts":     datetime(2026, 7, 28, 12, 0, 0),
                    "active": True,
                },
            )
            conn.execute(
                text(
                    "INSERT INTO users "
                    "(id, tenant_id, dept_id, email, password_hash, role, "
                    " is_active, force_password_change, token_version, created_at) "
                    "VALUES (:id, :tenant, NULL, :email, :pw, 'AUDITOR', "
                    " 1, 0, 1, :ts)"
                ),
                {
                    "id":     user_id,
                    "tenant": tenant_id,
                    "email":  "auditor@example.com",
                    "pw":     "hash-placeholder",
                    "ts":     datetime(2026, 7, 28, 12, 0, 0),
                },
            )
    finally:
        engine.dispose()


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
