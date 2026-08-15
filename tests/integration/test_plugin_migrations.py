# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Plugin migration helper (Phase 2, 2.10) -- proof by construction. Runs the
reference plugin's own Alembic chain via db.plugin_migrations.run_plugin_
migrations and verifies it (1) created its table, (2) recorded history in the
ISOLATED alembic_version_refplugin table, and (3) left the core alembic_version
untouched. The plugin and core chains share a database but never a version table.
"""
import asyncio
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from config.settings import get_settings
from db.plugin_migrations import plugin_version_table, run_plugin_migrations

_MIGRATIONS = (
    Path(__file__).resolve().parents[2]
    / "plugins" / "refplugin" / "wrapsec_refplugin" / "migrations"
)


@pytest.mark.asyncio
async def test_run_plugin_migrations_uses_isolated_version_table():
    url    = get_settings().database_url
    vt     = plugin_version_table("refplugin")     # alembic_version_refplugin
    engine = create_async_engine(url, poolclass=NullPool)
    sf     = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async def _drop():
        async with sf() as db:
            await db.execute(text("DROP TABLE IF EXISTS ref_plugin_widget"))
            await db.execute(text(f"DROP TABLE IF EXISTS {vt}"))  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text -- vt is a controlled constant (alembic_version_refplugin), not user input
            await db.commit()

    await _drop()   # clean any artifact left by an aborted run on a reused container
    try:
        # command.upgrade is sync and the plugin env.py calls asyncio.run, so run
        # it in a worker thread (no running loop there).
        await asyncio.to_thread(run_plugin_migrations, "refplugin", str(_MIGRATIONS), url)

        async with sf() as db:
            # (1) the plugin table exists, tenant_id NOT NULL (I8).
            assert (await db.execute(
                text("SELECT to_regclass('public.ref_plugin_widget')")
            )).scalar() is not None
            assert (await db.execute(text(
                "SELECT is_nullable FROM information_schema.columns "
                "WHERE table_name='ref_plugin_widget' AND column_name='tenant_id'"
            ))).scalar() == "NO"

            # (2) history lives in the plugin's OWN version table.
            assert (await db.execute(
                # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text -- vt is a controlled constant (alembic_version_refplugin), not user input
                text(f"SELECT version_num FROM {vt}")
            )).scalar() == "0001_ref_widget"

            # (3) the core version table (if present) never records the plugin rev.
            if (await db.execute(
                text("SELECT to_regclass('public.alembic_version')")
            )).scalar() is not None:
                core_revs = [
                    r[0] for r in (await db.execute(
                        text("SELECT version_num FROM alembic_version")
                    )).all()
                ]
                assert "0001_ref_widget" not in core_revs
    finally:
        await _drop()
        await engine.dispose()
