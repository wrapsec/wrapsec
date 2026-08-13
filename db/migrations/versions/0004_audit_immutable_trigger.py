# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""block UPDATE on chained audit_logs rows

Revision ID: 0004_audit_immutable_trigger
Revises: 0003_audit_session_hash
Create Date: 2026-07-27

Second half of the v1.2.0 tamper-evidence work. `0003` added
record_hash/prev_hash and the previous commit wired the application-layer
writer that populates them. Without this DB-level guard the chain only
DETECTS tampering after the fact -- anyone with UPDATE privilege on
audit_logs (including a WrapSec service bug or an insider with DB
credentials) could rewrite chained rows and recompute the chain in the
same transaction, leaving no evidence.

The trigger rejects any UPDATE on a row where record_hash IS NOT NULL.
Pre-v1.2 rows (record_hash NULL) remain updateable -- retroactive
tamper-evidence is not something a schema change can grant. DELETE stays
unrestricted so the retention worker's 02:00 UTC audit cleanup keeps
working; block-and-forever storage is not the intent.

Postgres only. SQLite (test fixture DBs, dev sandboxes) has no
equivalent trigger construct with RAISE support, and the SQLite path
is deliberately single-writer so the concurrency motivation does not
apply. The migration is a no-op there.
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0004_audit_immutable_trigger"
down_revision: str | None = "0003_audit_session_hash"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_TRIGGER_FUNCTION_SQL = """
CREATE OR REPLACE FUNCTION audit_logs_prevent_chained_update()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.record_hash IS NOT NULL THEN
        RAISE EXCEPTION
            'audit_logs row is chain-locked and immutable (id=%, trace_id=%)',
            OLD.id, OLD.trace_id
        USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
""".strip()

# BEFORE UPDATE so the RAISE aborts the write before any storage is touched.
# DROP + CREATE for idempotence against baseline drift; unlike columns,
# triggers do not benefit from create_all() so this is only "belt and
# braces", but the pattern matches 0003 and keeps re-runs safe.
#
# Kept as two separate statements (not one multi-statement string) because
# the asyncpg driver rejects "cannot insert multiple commands into a
# prepared statement" -- Alembic hands each op.execute() to the driver
# individually via a prepared statement path.
_DROP_TRIGGER_SQL = (
    "DROP TRIGGER IF EXISTS audit_logs_no_update_on_chained ON audit_logs;"
)
_CREATE_TRIGGER_SQL = """
CREATE TRIGGER audit_logs_no_update_on_chained
    BEFORE UPDATE ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION audit_logs_prevent_chained_update();
""".strip()

_DROP_FUNCTION_SQL = (
    "DROP FUNCTION IF EXISTS audit_logs_prevent_chained_update();"
)


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    op.execute(_TRIGGER_FUNCTION_SQL)
    op.execute(_DROP_TRIGGER_SQL)
    op.execute(_CREATE_TRIGGER_SQL)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    op.execute(_DROP_TRIGGER_SQL)
    op.execute(_DROP_FUNCTION_SQL)
