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
