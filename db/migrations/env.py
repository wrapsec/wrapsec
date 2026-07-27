# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Alembic env: async engine, URL from settings, metadata from ORM Base."""

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from config.settings import get_settings
from db.models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _get_url() -> str:
    return get_settings().database_url


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url") or _get_url()
    context.configure(
        url                 = url,
        target_metadata     = target_metadata,
        literal_binds       = True,
        dialect_opts        = {"paramstyle": "named"},
        compare_type        = True,
        compare_server_default = True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection             = connection,
        target_metadata        = target_metadata,
        compare_type           = True,
        compare_server_default = True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section) or {}
    # Respect an explicit sqlalchemy.url when set by the caller (tests use
    # this to point at an ephemeral sqlite file); otherwise resolve from
    # application settings so `alembic upgrade head` works out of the box.
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


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
