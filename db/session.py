# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from config.settings import get_settings

_settings = get_settings()

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
    from db.models import Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def dispose_engine() -> None:
    """Dispose the connection pool on application shutdown to release all connections."""
    await engine.dispose()


async def drop_tables() -> None:
    if _settings.environment == "production":
        raise RuntimeError("drop_tables() must never be called in production.")
    from db.models import Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)