from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from config.settings import get_settings

settings = get_settings()

engine = create_async_engine(
    settings.database_url,
    pool_size     = settings.db_pool_size,
    max_overflow  = settings.db_max_overflow,
    pool_pre_ping = True,
    echo          = settings.debug,
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


async def drop_tables() -> None:
    from db.models import Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)