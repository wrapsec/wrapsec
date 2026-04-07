import logging
from redis.asyncio import Redis, ConnectionPool
from config.settings import get_settings

logger   = logging.getLogger("wrapsec.cache")
settings = get_settings()

_pool: ConnectionPool | None = None
_client: Redis | None = None


def get_redis_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        _pool = ConnectionPool.from_url(
            settings.redis_url,
            max_connections = 20,
            decode_responses = True,
        )
    return _pool


def get_redis() -> Redis:
    global _client
    if _client is None:
        _client = Redis(connection_pool=get_redis_pool())
    return _client


async def ping() -> bool:
    try:
        client = get_redis()
        return await client.ping()
    except Exception as e:
        logger.error(f"Redis ping failed: {e}")
        return False


async def close() -> None:
    global _client, _pool
    if _client:
        await _client.aclose()
        _client = None
    if _pool:
        await _pool.aclose()
        _pool = None