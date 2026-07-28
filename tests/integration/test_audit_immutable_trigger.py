# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Integration tests for migration 0004's UPDATE-blocking trigger.

The trigger only exists in Postgres (SQLite has no equivalent RAISE
construct); these tests skip cleanly on the SQLite tier. The trigger
DDL is loaded straight from the migration module and applied inline so
the test verifies THE ACTUAL SQL that will run against production --
duplicating the string in the test file would let the two drift.

The three cases mirror the trigger's contract:

  * chained row (record_hash NOT NULL) -- UPDATE must raise
  * legacy row  (record_hash IS  NULL) -- UPDATE must succeed
  * chained row DELETE must succeed (retention worker prerequisite)
"""
from __future__ import annotations

import importlib.util
import uuid
from datetime import datetime
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy import delete as sa_delete, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import (
    AsyncSession, async_sessionmaker, create_async_engine,
)
from sqlalchemy.pool import NullPool

from config.settings import get_settings
from db.models import AuditLogModel


_settings = get_settings()

_IS_POSTGRES = _settings.database_url.startswith(
    ("postgresql://", "postgresql+")
)

pytestmark = pytest.mark.skipif(
    not _IS_POSTGRES,
    reason="audit_logs UPDATE trigger is Postgres-only (see migration 0004)",
)


def _load_migration_sql() -> tuple[str, str, str]:
    """
    importlib is required because Alembic revision filenames begin with a
    digit, which is not a valid Python identifier. Loading the migration
    module by path lets us reference the SAME SQL constants that ship in
    production; anything else risks the test and the migration drifting
    apart silently.
    """
    migration_path = (
        Path(__file__).resolve().parents[2]
        / "db" / "migrations" / "versions" / "0004_audit_immutable_trigger.py"
    )
    spec = importlib.util.spec_from_file_location(
        "wrapsec_migration_0004", migration_path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return (
        module._TRIGGER_FUNCTION_SQL,
        module._DROP_TRIGGER_SQL,
        module._CREATE_TRIGGER_SQL,
    )


@pytest_asyncio.fixture
async def pg_session_with_trigger():
    """
    Yields a NullPool-backed AsyncSession against the live Postgres and
    ensures the trigger is installed for the duration of the test. The
    trigger is left in place on teardown -- the migration is idempotent
    (DROP + CREATE), production installs it once, and the alternative
    (drop after every test) would race any other integration test that
    happens to write audit_logs rows in the same session.
    """
    fn_sql, drop_sql, create_sql = _load_migration_sql()

    engine = create_async_engine(_settings.database_url, poolclass=NullPool)
    sf = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.execute(text(fn_sql))
        await conn.execute(text(drop_sql))
        await conn.execute(text(create_sql))

    async with sf() as session:
        yield session

    await engine.dispose()


def _base_row(tenant_id: str, trace_id: str) -> dict:
    return {
        "id":             uuid.uuid4(),
        "trace_id":       trace_id,
        "decision":       "ALLOW",
        "risk_score":     0.1,
        "threats":        [],
        "input_hash":     "sha256:trigger_test",
        "detection_mode": "fast",
        "execution_mode": "scan_only",
        "llm_invoked":    False,
        "latency_ms":     1.0,
        "tenant_id":      tenant_id,
        "created_at":     datetime(2026, 7, 28, 12, 0, 0),
    }


async def _cleanup(session: AsyncSession, tenant_id: str) -> None:
    # Trigger blocks UPDATE on chained rows but leaves DELETE unrestricted,
    # so cleanup works for both chained and legacy rows.
    await session.execute(
        sa_delete(AuditLogModel).where(AuditLogModel.tenant_id == tenant_id)
    )
    await session.commit()


class TestChainedRowIsImmutable:

    @pytest.mark.asyncio
    async def test_update_on_chained_row_raises_check_violation(
        self, pg_session_with_trigger
    ):
        session   = pg_session_with_trigger
        tenant_id = f"trigger-test-{uuid.uuid4().hex[:8]}"
        try:
            row_data = _base_row(tenant_id, trace_id=f"chained-{uuid.uuid4().hex[:8]}")
            row_data["record_hash"] = "a" * 64
            row_data["prev_hash"]   = None
            session.add(AuditLogModel(**row_data))
            await session.commit()

            with pytest.raises(DBAPIError) as excinfo:
                await session.execute(
                    update(AuditLogModel)
                    .where(AuditLogModel.trace_id == row_data["trace_id"])
                    .values(decision="BLOCK")
                )
                await session.commit()
            # Trigger message is asserted on rather than the generic wrapper
            # class -- a future SQLAlchemy that stops wrapping DBAPIError as
            # IntegrityError should not silently pass this test.
            assert "chain-locked" in str(excinfo.value).lower()
            # In-tx failures leave the session in a poisoned state; the
            # rollback is what lets _cleanup() run.
            await session.rollback()
        finally:
            await _cleanup(session, tenant_id)

    @pytest.mark.asyncio
    async def test_delete_on_chained_row_still_works(self, pg_session_with_trigger):
        # The 02:00 UTC retention worker depends on DELETE staying open.
        # If a future edit tightens the trigger to also cover DELETE, this
        # test breaks loudly instead of the worker silently dying at 02:00.
        session   = pg_session_with_trigger
        tenant_id = f"trigger-test-{uuid.uuid4().hex[:8]}"
        try:
            row_data = _base_row(tenant_id, trace_id=f"chained-{uuid.uuid4().hex[:8]}")
            row_data["record_hash"] = "b" * 64
            session.add(AuditLogModel(**row_data))
            await session.commit()

            await session.execute(
                sa_delete(AuditLogModel)
                .where(AuditLogModel.trace_id == row_data["trace_id"])
            )
            await session.commit()

            still_there = await session.scalar(
                select(AuditLogModel)
                .where(AuditLogModel.trace_id == row_data["trace_id"])
            )
            assert still_there is None
        finally:
            await _cleanup(session, tenant_id)


class TestLegacyRowIsMutable:

    @pytest.mark.asyncio
    async def test_update_on_pre_v1_2_row_is_allowed(self, pg_session_with_trigger):
        # Pre-v1.2 rows have record_hash IS NULL and predate the chain.
        # Retroactive immutability would break any operational fix-up of
        # historical rows and is deliberately out of scope for the trigger
        # (see migration 0004 docstring).
        session   = pg_session_with_trigger
        tenant_id = f"trigger-test-{uuid.uuid4().hex[:8]}"
        try:
            row_data = _base_row(tenant_id, trace_id=f"legacy-{uuid.uuid4().hex[:8]}")
            # record_hash omitted on purpose -- this is the legacy shape.
            session.add(AuditLogModel(**row_data))
            await session.commit()

            await session.execute(
                update(AuditLogModel)
                .where(AuditLogModel.trace_id == row_data["trace_id"])
                .values(decision="BLOCK")
            )
            await session.commit()

            updated = await session.scalar(
                select(AuditLogModel)
                .where(AuditLogModel.trace_id == row_data["trace_id"])
            )
            assert updated is not None
            assert updated.decision == "BLOCK"
        finally:
            await _cleanup(session, tenant_id)
