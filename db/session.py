# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from pathlib import Path

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from config.settings import get_settings

_settings = get_settings()

_REPO_ROOT   = Path(__file__).resolve().parent.parent
_ALEMBIC_INI = _REPO_ROOT / "alembic.ini"

engine = create_async_engine(
    _settings.database_url,
    pool_size     = _settings.db_pool_size,
    max_overflow  = _settings.db_max_overflow,
    pool_pre_ping = True,
    echo          = _settings.debug,
)

AsyncSessionFactory = async_sessionmaker(
    bind        = engine,
    class_      = AsyncSession,
    expire_on_commit = False,
)


async def get_session() -> AsyncSession:
    async with AsyncSessionFactory() as session:
        yield session


async def create_tables() -> None:
    """
    Legacy schema bootstrap kept for test suites that build a throwaway
    database per test. Production and dev startup goes through
    run_migrations() so the alembic_version table stays authoritative.
    """
    from db.models import Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def run_migrations() -> None:
    """
    Runs Alembic upgrade head against the configured database. Safe on both
    fresh databases (baseline migration creates every table) and existing
    v1.0.11 databases (baseline uses checkfirst=True so existing tables are
    skipped; the alembic_version table is created on first run).
    """
    from alembic import command
    from alembic.config import Config

    def _upgrade() -> None:
        cfg = Config(str(_ALEMBIC_INI))
        cfg.set_main_option("script_location", str(_REPO_ROOT / "db" / "migrations"))
        command.upgrade(cfg, "head")

    import asyncio
    await asyncio.to_thread(_upgrade)


async def dispose_engine() -> None:
    """Dispose the connection pool on application shutdown to release all connections."""
    await engine.dispose()


async def drop_tables() -> None:
    if _settings.environment == "production":
        raise RuntimeError("drop_tables() must never be called in production.")
    from db.models import Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)