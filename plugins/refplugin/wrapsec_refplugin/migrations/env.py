# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Reference plugin Alembic env (2.10 proof). Mirrors the core env.py, with the one
difference every plugin makes: the version table is read from
config.attributes["version_table"] (set by db.plugin_migrations.run_plugin_
migrations) so this chain records its history in alembic_version_refplugin and
never collides with the core alembic_version table. A real plugin would set
target_metadata to its own Base.metadata for autogenerate; this reference chain
is hand-written, so None is fine.
"""

import asyncio

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from config.settings import get_settings

config = context.config

# The isolated version table -- the crux of plugin migration ownership. Falls
# back to the conventional name when run outside the helper.
_VERSION_TABLE = config.attributes.get("version_table", "alembic_version_refplugin")

target_metadata = None


def _get_url() -> str:
    return get_settings().database_url


def _do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection      = connection,
        target_metadata = target_metadata,
        version_table   = _VERSION_TABLE,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section) or {}
    if not configuration.get("sqlalchemy.url"):
        configuration["sqlalchemy.url"] = _get_url()

    connectable = async_engine_from_config(
        configuration,
        prefix    = "sqlalchemy.",
        poolclass = pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(_do_run_migrations)
    await connectable.dispose()


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url") or _get_url()
    context.configure(
        url           = url,
        literal_binds = True,
        dialect_opts  = {"paramstyle": "named"},
        version_table = _VERSION_TABLE,
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
