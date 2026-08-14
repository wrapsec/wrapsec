# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Integration test fixtures.
Uses session-scoped event loop.
Flushes rate_limit and auth lockout Redis keys before each auth test
to prevent cross-test accumulation.
"""
import os

os.environ["TESTING"] = "true"

import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from api.main import app
from api.v1.dependencies.db import get_db
from config.settings import get_settings
from db.models import Base, TenantModel

settings = get_settings()


# ── Disposable-Postgres gate for the integration tier (Option B) ──────────────
# The integration tier runs against a DISPOSABLE Postgres, never SQLite, so
# tests exercise real jsonb/asyncpg/trigger behavior. The throwaway DB is
# provisioned BEFORE pytest by `make test-integration` (or CI), which points
# BOTH DATABASE_URL (the app binds this at import) and WRAPSEC_TEST_PG_URL (this
# file's opt-in, which also authorizes per-test TRUNCATE) at the same database.
# When it is absent the tier skips gracefully -- it never touches the dev DB.
_TEST_PG_URL = os.environ.get("WRAPSEC_TEST_PG_URL")


def _integration_skip_reason() -> str | None:
    if not _TEST_PG_URL:
        return (
            "no disposable Postgres configured. Run `make test-integration`, or "
            "set WRAPSEC_TEST_PG_URL and DATABASE_URL to the same throwaway "
            "database."
        )
    if settings.database_url != _TEST_PG_URL:
        return (
            "WRAPSEC_TEST_PG_URL and DATABASE_URL differ; point both at the same "
            "disposable database (make test-integration does this) so the app and "
            "tests share one DB."
        )
    return None


@pytest.fixture(autouse=True)
def _require_disposable_pg():
    """Skip every integration test unless a disposable Postgres is configured.
    Keeps the tier real-PG-only without ever running against SQLite or the dev
    database."""
    reason = _integration_skip_reason()
    if reason:
        pytest.skip(reason)


# ── PostgreSQL URL resolver for the pg_client fixture ─────────────────────────
# Resolution order (first that works wins):
#   1. WRAPSEC_TEST_PG_URL env var - explicit operator override.
#   2. settings.database_url - the same DB used by the app and by the existing
#      _postgres_db_setup autouse fixture. If `make up-dev` is running this is
#      what gets used. Zero container overhead in that path.
#   3. testcontainers PostgreSQL - spins up postgres:16-alpine (same image as
#      docker-compose.yml so it's already cached) for the session. Falls back
#      to skipping pg-marked tests if the testcontainers package or Docker is
#      unavailable, matching the pattern Airflow and dbt use.
#
# Only the NEW pg_client fixture consumes this. The pre-existing PG-backed
# fixtures (admin_jwt_headers, auth_setup, two_tenant_setup) continue to use
# db.session.AsyncSessionFactory, which is bound at import time from
# settings.database_url. Moving those fixtures to the resolver would require
# reloading db.session mid-session and is out of scope for v1.2.3.

_pg_container      = None  # module-level so we can stop it in a finalizer
_pg_url_cache: str | None = None


async def _resolve_pg_url() -> str | None:
    global _pg_container, _pg_url_cache
    if _pg_url_cache is not None:
        return _pg_url_cache

    env_url = os.environ.get("WRAPSEC_TEST_PG_URL")
    if env_url:
        _pg_url_cache = env_url
        return env_url

    # Try the app's configured DB. If it's reachable, use it.
    try:
        probe = create_async_engine(settings.database_url, poolclass=NullPool)
        async with probe.connect() as conn:
            await conn.execute(text("SELECT 1"))
        await probe.dispose()
        _pg_url_cache = settings.database_url
        return settings.database_url
    except Exception:
        pass  # Best-effort test cleanup; ignore teardown errors.

    # Fall through to testcontainers.
    try:
        from testcontainers.postgres import PostgresContainer
    except ImportError:
        return None

    try:
        # Match the docker-compose.yml image so we do not pull a second copy.
        _pg_container = PostgresContainer("postgres:16-alpine")
        _pg_container.start()
    except Exception:
        # Docker not running, socket unreachable, image pull failed, etc.
        _pg_container = None
        return None

    sync_url = _pg_container.get_connection_url()  # postgresql+psycopg2://...
    async_url = sync_url.replace("postgresql+psycopg2://", "postgresql+asyncpg://")
    _pg_url_cache = async_url
    return async_url


@pytest_asyncio.fixture(scope="session")
async def pg_url():
    url = await _resolve_pg_url()
    if url is None:
        pytest.skip(
            "PostgreSQL not available: set WRAPSEC_TEST_PG_URL, run "
            "`make up-dev`, or install testcontainers + start Docker."
        )
    yield url

    # Session teardown: stop the container if we spawned one.
    global _pg_container
    if _pg_container is not None:
        try:
            _pg_container.stop()
        finally:
            _pg_container = None


@pytest_asyncio.fixture(scope="session")
async def _pg_engine(pg_url):
    """
    Session-scoped engine against the resolved PG. Schema is created once with
    Base.metadata.create_all (checkfirst=True, so it is a no-op if the DB is
    already migrated). No drop_all at the end - the container is torn down
    with the process, and shared PGs (up-dev / WRAPSEC_TEST_PG_URL) are the
    operator's responsibility.
    """
    engine = create_async_engine(pg_url, poolclass=NullPool)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def pg_db(_pg_engine):
    """
    Function-scoped session against the resolved PG.

    Isolation model:

      * When the resolver spun up our own testcontainer (`_pg_container is
        not None`), the DB is a private sandbox -- TRUNCATE the tables the
        pg_client tests write to so state does not carry between tests.

      * When the resolver is pointing at a *shared* PG
        (WRAPSEC_TEST_PG_URL or settings.database_url from `make up-dev`),
        NEVER truncate. That destroys the operator's live dev data. Tests
        instead scope themselves by random tenant_id and rely on filtering.

    v1.2.3: The unconditional TRUNCATE previously here wiped a shared dev
    database in real use. Guard added so a shared PG is always append-only
    for pg_client tests.
    """
    sf = async_sessionmaker(bind=_pg_engine, class_=AsyncSession, expire_on_commit=False)
    async with sf() as session:
        if _pg_container is not None or _TEST_PG_URL:
            # Safe to TRUNCATE: the DB is disposable (we spawned it, or the
            # operator declared it via WRAPSEC_TEST_PG_URL). CASCADE is required
            # because audit_logs is referenced by the hash chain trigger's
            # constraint chain in v1.2.0+.
            await session.execute(text(
                "TRUNCATE TABLE audit_logs, proxy_interactions "
                "RESTART IDENTITY CASCADE"
            ))
            await session.commit()
        yield session


@pytest_asyncio.fixture(scope="function")
async def pg_client(pg_db):
    """
    HTTP client whose get_db override yields the pg_db PostgreSQL session.
    Use this instead of the SQLite-backed `client` fixture for anything that
    exercises PG-only code paths: jsonb queries, percentile_cont, hash-chain
    trigger, asyncpg tz-aware bind rejection.
    """
    app.dependency_overrides.clear()

    async def override_get_db():
        yield pg_db

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(
        transport = ASGITransport(app=app),
        base_url  = "http://test",
    ) as c:
        yield c

    app.dependency_overrides.clear()


# ── PostgreSQL bootstrap - runs once per integration session ─────────────────
# H10: this fixture used to live in tests/conftest.py where autouse+session
# scope forced every unit test to require a live Postgres instance. Scoped
# down to tests/integration/ so the unit tier stays hermetic.

@pytest_asyncio.fixture(scope="session", autouse=True)
async def _postgres_db_setup():
    """
    Creates all tables in PostgreSQL and seeds the default tenant.
    Required for admin_jwt_headers and auth_setup fixtures which call
    TenantRepository.get_default() and assert a slug='default' tenant exists.
    Runs once before any integration test in the session.

    Fail-graceful: if settings.database_url is unreachable, prints a warning
    and yields anyway. This is what unblocks the pg_client fixture's
    testcontainers fallback -- previously an unreachable app DB would
    session-error every integration test, including SQLite-only ones that
    do not touch this fixture. Tests that actually depend on the app's PG
    (auth_setup, admin_jwt_headers, two_tenant_setup) still fail on their
    own connection attempt, which is the correct signal.
    """
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    sf     = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        async with sf() as db:
            result = await db.execute(
                select(TenantModel).where(TenantModel.slug == "default")
            )
            if result.scalar_one_or_none() is None:
                db.add(TenantModel(
                    id            = uuid.uuid4(),
                    slug          = "default",
                    name          = "Default",
                    global_policy = {},
                    is_active     = True,
                ))
                await db.commit()
    except Exception as exc:
        # Do not use logging here -- pytest captures it and hides the warning
        # from operators who need to see it during collection.
        print(
            f"\n[integration/conftest] settings.database_url unreachable: "
            f"{type(exc).__name__}. Tests that depend on the app's PG will "
            f"fail; pg_client tests can still run via testcontainers."
        )

    yield

    await engine.dispose()


# ── Integration test session: disposable Postgres, per-test truncation ────────
# test_db (and the `client` fixture that wraps it) now runs on the disposable
# Postgres, not SQLite -- it shares the session-scoped _pg_engine (schema built
# once via create_all) and clears the high-churn tables between tests. Seed and
# config tables (tenants, users, departments, applications, settings) are
# preserved so the session-seeded default tenant and the admin_jwt fixtures stay
# valid; the _require_disposable_pg gate skips the whole tier when no throwaway
# DB is configured, so this never runs against SQLite or the dev database.

@pytest_asyncio.fixture(scope="function")
async def test_db(_pg_engine):
    sf = async_sessionmaker(bind=_pg_engine, class_=AsyncSession, expire_on_commit=False)
    async with sf() as session:
        await session.execute(text(
            "TRUNCATE TABLE api_keys, webhook_delivery_attempts, "
            "webhook_endpoints, audit_logs, proxy_interactions "
            "RESTART IDENTITY CASCADE"
        ))
        await session.commit()
        yield session


@pytest_asyncio.fixture(scope="function")
async def client(test_db):
    # Clear any leftover overrides from previous test
    app.dependency_overrides.clear()

    async def override_get_db():
        yield test_db

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(
        transport = ASGITransport(app=app),
        base_url  = "http://test",
    ) as c:
        yield c

    app.dependency_overrides.clear()


@pytest.fixture
def admin_headers():
    return {"x-api-key": settings.admin_api_key}


@pytest_asyncio.fixture(scope="function")
async def admin_key_scope(test_db, admin_jwt_headers):
    """
    Creates a Department row in the SQLite test_db whose tenant_id matches the
    admin_jwt token's tenant_id. Returns the dept_id (str) for tests that POST
    /v1/keys - required after H4 (endpoints reject non-admin keys without a dept).
    """
    from db.models import DepartmentModel
    from services.auth.token import decode_access_token

    token     = admin_jwt_headers["Authorization"].split()[1]
    payload   = decode_access_token(token)
    tenant_id = uuid.UUID(payload["tenant_id"])

    dept_id = uuid.uuid4()
    test_db.add(DepartmentModel(
        id        = dept_id,
        tenant_id = tenant_id,
        slug      = f"testdept-{dept_id.hex[:6]}",
        name      = "Test Dept",
        is_active = True,
    ))
    await test_db.commit()
    return str(dept_id)


@pytest.fixture
def standard_headers():
    return {"x-api-key": "wsk_live_test_standard_key"}


# ── Redis helpers ─────────────────────────────────────────────────────────────

async def _flush_test_redis_keys():
    """
    Flushes rate limit and auth lockout Redis keys before auth tests.
    Rate limit key: rate_limit:{ip} - accumulates across tests from 127.0.0.1
    Lockout keys: auth:failed:{email}, auth:locked:{email}

    Uses KEYS - O(N) blocking command. Acceptable for test cleanup on a local
    Redis instance with a small keyspace. Never use KEYS in production code.
    """
    try:
        from cache.redis_client import get_redis
        redis = get_redis()
        patterns = [
            "rate_limit:*",      # rate_limit_store.py pattern
            "auth:failed:*",     # lockout.py pattern
            "auth:locked:*",     # lockout.py pattern
        ]
        keys = []
        for pattern in patterns:
            found = await redis.keys(pattern)
            keys.extend(found)
        if keys:
            await redis.delete(*keys)
    except Exception:
        pass  # Redis unavailable - silently skip


# ── Auth fixtures ──────────────────────────────────────────────────────────────

@pytest_asyncio.fixture(scope="function")
async def auth_client():
    """HTTP client against real app - no DB override."""
    app.dependency_overrides.clear()
    # Flush rate limit keys before each auth test
    await _flush_test_redis_keys()
    async with AsyncClient(
        transport = ASGITransport(app=app),
        base_url  = "http://test",
    ) as c:
        yield c
    app.dependency_overrides.clear()
    await _flush_test_redis_keys()


@pytest_asyncio.fixture(scope="function")
async def auth_setup():
    """
    Creates tenant + dept + users in PostgreSQL using NullPool.
    JWT middleware also uses NullPool in test mode (auth.py _get_db_session).
    Cleans up all DB rows after each test.
    """
    from unittest.mock import MagicMock

    from sqlalchemy import delete as sa_delete

    from db.models import DepartmentModel, RefreshTokenModel, TenantModel, UserModel
    from db.repositories.user import UserRepository
    from services.auth.password import hash_password, normalize_email
    from services.auth.token import create_access_token

    tenant_id     = uuid.uuid4()
    dept_id       = uuid.uuid4()
    slug          = f"test-{uuid.uuid4().hex[:8]}"
    admin_email   = normalize_email(f"admin-{uuid.uuid4().hex[:6]}@test.com")
    dev_email     = normalize_email(f"dev-{uuid.uuid4().hex[:6]}@test.com")
    viewer_email  = normalize_email(f"viewer-{uuid.uuid4().hex[:6]}@test.com")
    password_hash = hash_password("TestPass1!")

    admin_db_id = dev_db_id = viewer_db_id = None

    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    sf = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    try:
        async with sf() as db:
            db.add(TenantModel(id=tenant_id, slug=slug, name="Test Tenant",
                               global_policy={}, is_active=True))
            await db.commit()

            db.add(DepartmentModel(id=dept_id, tenant_id=tenant_id,
                                   slug="engineering", name="Engineering",
                                   is_active=True))
            await db.commit()

            repo = UserRepository(db)
            from db.repositories.membership import MembershipRepository
            mem_repo = MembershipRepository(db)

            u = await repo.create({
                "tenant_id": tenant_id, "dept_id": None,
                "email": admin_email, "password_hash": password_hash,
                "role": "ADMIN", "force_password_change": False,
            })
            await db.flush()
            await mem_repo.upsert_for_user(u.id, tenant_id, "ADMIN", None)
            await db.commit()
            admin_db_id = u.id

            u = await repo.create({
                "tenant_id": tenant_id, "dept_id": dept_id,
                "email": dev_email, "password_hash": password_hash,
                "role": "DEVELOPER", "force_password_change": False,
            })
            await db.flush()
            await mem_repo.upsert_for_user(u.id, tenant_id, "DEVELOPER", dept_id)
            await db.commit()
            dev_db_id = u.id

            u = await repo.create({
                "tenant_id": tenant_id, "dept_id": dept_id,
                "email": viewer_email, "password_hash": password_hash,
                "role": "VIEWER", "force_password_change": False,
            })
            await db.flush()
            await mem_repo.upsert_for_user(u.id, tenant_id, "VIEWER", dept_id)
            await db.commit()
            viewer_db_id = u.id

    finally:
        await engine.dispose()

    def _mock(uid, tid, did, role):
        m = MagicMock()
        m.id = uid; m.tenant_id = tid; m.dept_id = did
        m.role = role; m.token_version = 1
        return m

    class _Obj:
        def __init__(self, **kw): self.__dict__.update(kw)

    yield {
        "tenant":       _Obj(id=tenant_id),
        "dept":         _Obj(id=dept_id),
        "admin_user":   _Obj(id=admin_db_id,  email=admin_email,  role="ADMIN"),
        "admin_token":  create_access_token(_mock(admin_db_id,  tenant_id, None,    "ADMIN")),
        "dev_user":     _Obj(id=dev_db_id,    email=dev_email,    role="DEVELOPER"),
        "dev_token":    create_access_token(_mock(dev_db_id,    tenant_id, dept_id, "DEVELOPER")),
        "viewer_user":  _Obj(id=viewer_db_id, email=viewer_email, role="VIEWER"),
        "viewer_token": create_access_token(_mock(viewer_db_id, tenant_id, dept_id, "VIEWER")),
    }

    # ── Cleanup ────────────────────────────────────────────────────────────────
    engine2 = create_async_engine(settings.database_url, poolclass=NullPool)
    sf2 = async_sessionmaker(bind=engine2, class_=AsyncSession, expire_on_commit=False)
    try:
        async with sf2() as db:
            ids = [i for i in [admin_db_id, dev_db_id, viewer_db_id] if i]
            if ids:
                from sqlalchemy import delete as sa_delete
                await db.execute(sa_delete(RefreshTokenModel).where(
                    RefreshTokenModel.user_id.in_(ids)))
                await db.execute(sa_delete(UserModel).where(
                    UserModel.tenant_id == tenant_id))
            await db.execute(sa_delete(DepartmentModel).where(
                DepartmentModel.id == dept_id))
            await db.execute(sa_delete(TenantModel).where(
                TenantModel.id == tenant_id))
            await db.commit()
    except Exception:
        pass  # Best-effort test cleanup; ignore teardown errors.
    finally:
        await engine2.dispose()


# ── Two-tenant fixture for cross-tenant isolation tests (Issue 162) ───────────

@pytest_asyncio.fixture(scope="function")
async def two_tenant_setup():
    """
    Seeds two independent tenants (A and B) in PostgreSQL, each with:
    admin user, dept, application, API key, and audit log row.

    HTTP-boundary cross-tenant tests use this to prove that tenant A's admin
    JWT cannot access tenant B's resources via any endpoint. Cleans up all
    seeded rows after each test.
    """
    from unittest.mock import MagicMock

    from sqlalchemy import delete as sa_delete

    from db.models import (
        AdminEventModel,
        APIKeyModel,
        ApplicationModel,
        AuditLogModel,
        DepartmentModel,
        ProxyInteractionModel,
        ProxyProviderConfigModel,
        RefreshTokenModel,
        TenantModel,
        UserModel,
    )
    from db.repositories.user import UserRepository
    from services.auth.password import hash_password, normalize_email
    from services.auth.token import create_access_token

    def _mock(uid, tid, did, role):
        m = MagicMock()
        m.id = uid; m.tenant_id = tid; m.dept_id = did
        m.role = role; m.token_version = 1
        return m

    class _Obj:
        def __init__(self, **kw): self.__dict__.update(kw)

    fixtures = {}
    tenant_ids = []
    user_ids = []
    api_key_ids = []

    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    sf = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    try:
        async with sf() as db:
            for letter in ("A", "B"):
                tid   = uuid.uuid4()
                did   = uuid.uuid4()
                aid   = uuid.uuid4()
                uuid.uuid4()
                keyid = f"wsk_live_{letter.lower()}_" + uuid.uuid4().hex[:12]
                trace = f"trace-{letter.lower()}-" + uuid.uuid4().hex[:8]
                email = normalize_email(
                    f"admin-{letter.lower()}-{uuid.uuid4().hex[:6]}@t.com"
                )

                db.add(TenantModel(
                    id=tid,
                    slug=f"tenant-{letter.lower()}-{uuid.uuid4().hex[:6]}",
                    name=f"Tenant {letter}",
                    global_policy={},
                    is_active=True,
                ))
                await db.commit()

                db.add(DepartmentModel(
                    id=did, tenant_id=tid,
                    slug=f"dept-{letter.lower()}",
                    name=f"Dept {letter}",
                    is_active=True,
                ))
                await db.commit()

                db.add(ApplicationModel(
                    id=aid, tenant_id=tid, dept_id=did,
                    slug=f"app-{letter.lower()}",
                    name=f"App {letter}",
                    is_active=True,
                ))
                await db.commit()

                db.add(APIKeyModel(
                    id=uuid.uuid4(), key_id=keyid,
                    tenant_id=tid, dept_id=did, app_id=aid,
                    name=f"key-{letter.lower()}",
                    key_hash=f"hash-{letter.lower()}-" + uuid.uuid4().hex,
                    key_type="live", is_admin=False, revoked=False,
                ))
                await db.commit()

                repo = UserRepository(db)
                u = await repo.create({
                    "tenant_id": tid, "dept_id": None,
                    "email": email, "password_hash": hash_password("TestPass1!"),
                    "role": "ADMIN", "force_password_change": False,
                })
                await db.flush()
                from db.repositories.membership import MembershipRepository
                await MembershipRepository(db).upsert_for_user(u.id, tid, "ADMIN", None)
                await db.commit()

                db.add(AuditLogModel(
                    id=uuid.uuid4(), trace_id=trace,
                    decision="ALLOW", risk_score=0.1, threats=[],
                    input_hash="hash-" + uuid.uuid4().hex,
                    detection_mode="standard", execution_mode="scan",
                    llm_invoked=False, latency_ms=12.5,
                    tenant_id=str(tid), dept_id=str(did), app_id=str(aid),
                    key_id=keyid, user_id=str(u.id), source="api",
                ))
                proxy_trace = f"px-{letter.lower()}-" + uuid.uuid4().hex[:8]
                db.add(ProxyInteractionModel(
                    id=uuid.uuid4(),
                    trace_id=proxy_trace,
                    key_id=keyid,
                    input_decision="ALLOW",
                    input_primary_reason="clean",
                    input_confidence=0.05,
                    execution_status="COMPLETED",
                    total_latency_ms=42,
                ))
                await db.commit()

                fixtures[letter] = {
                    "tenant":       _Obj(id=tid),
                    "dept":         _Obj(id=did),
                    "app":          _Obj(id=aid),
                    "admin_user":   _Obj(id=u.id, email=email, role="ADMIN"),
                    "admin_token":  create_access_token(
                        _mock(u.id, tid, None, "ADMIN")
                    ),
                    "api_key_id":   keyid,
                    "audit_trace":  trace,
                    "proxy_trace":  proxy_trace,
                }
                tenant_ids.append(tid)
                user_ids.append(u.id)
                api_key_ids.append(keyid)
    finally:
        await engine.dispose()

    yield fixtures

    # ── Cleanup ────────────────────────────────────────────────────────────────
    engine2 = create_async_engine(settings.database_url, poolclass=NullPool)
    sf2 = async_sessionmaker(bind=engine2, class_=AsyncSession, expire_on_commit=False)
    try:
        async with sf2() as db:
            if user_ids:
                await db.execute(sa_delete(RefreshTokenModel).where(
                    RefreshTokenModel.user_id.in_(user_ids)))
                await db.execute(sa_delete(AdminEventModel).where(
                    AdminEventModel.target_user_id.in_(user_ids)))
            if api_key_ids:
                await db.execute(sa_delete(ProxyInteractionModel).where(
                    ProxyInteractionModel.key_id.in_(api_key_ids)))
            for tid in tenant_ids:
                await db.execute(sa_delete(AuditLogModel).where(
                    AuditLogModel.tenant_id == str(tid)))
                await db.execute(sa_delete(APIKeyModel).where(
                    APIKeyModel.tenant_id == tid))
                await db.execute(sa_delete(UserModel).where(
                    UserModel.tenant_id == tid))
                await db.execute(sa_delete(ApplicationModel).where(
                    ApplicationModel.tenant_id == tid))
                await db.execute(sa_delete(DepartmentModel).where(
                    DepartmentModel.tenant_id == tid))
                await db.execute(sa_delete(ProxyProviderConfigModel).where(
                    ProxyProviderConfigModel.tenant_id == str(tid)))
                await db.execute(sa_delete(TenantModel).where(
                    TenantModel.id == tid))
            await db.commit()
    except Exception:
        pass  # Best-effort test cleanup; ignore teardown errors.
    finally:
        await engine2.dispose()
