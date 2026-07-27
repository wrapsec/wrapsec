# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""add session tracking and hash chain columns to audit_logs

Revision ID: 0003_audit_session_hash
Revises: 0002_envelope_reencrypt
Create Date: 2026-07-27

v1.2.0 groundwork. Adds five nullable columns to `audit_logs`:

  session_id    caller-supplied conversation identifier grouping related scans
  turn_index    zero-based turn index within session_id
  run_id        caller-supplied identifier for one agent execution
  record_hash   SHA-256 hex of this row's canonical serialisation (populated
                by the hash-chained audit writer in the following commit)
  prev_hash     record_hash of the immediately preceding row in this tenant's
                chain, or NULL for the genesis row

Field naming matches enterprise convention: AWS QLDB (hash, previousBlockHash),
HashiCorp Vault (hash), Ethereum (hash, parentHash). `record_hash`/`prev_hash`
are unambiguous vs the existing `input_hash` column which is a scan-input
deduplication marker, not part of the tamper-evidence chain.

Existing rows keep NULL in all five columns; the writer that populates
record_hash/prev_hash lands next. The postgres trigger that blocks UPDATEs
on populated rows lands two commits after that -- without the trigger,
the hash chain is theatre.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0003_audit_session_hash"
down_revision: Union[str, None] = "0002_envelope_reencrypt"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_NEW_COLUMNS = (
    ("session_id",  sa.String(200)),
    ("turn_index",  sa.Integer()),
    ("run_id",      sa.String(200)),
    ("record_hash", sa.String(64)),
    ("prev_hash",   sa.String(64)),
)

# Composite indexes match the existing (tenant_id, created_at) /
# (dept_id, created_at) pattern -- the queries that will fetch these
# rows always order by created_at within a session or run.
_NEW_INDEXES = (
    ("ix_audit_session_created", ["session_id", "created_at"]),
    ("ix_audit_run_created",     ["run_id",     "created_at"]),
)


def upgrade() -> None:
    # Idempotent against baseline drift. `0001_baseline` runs
    # `Base.metadata.create_all(checkfirst=True)` off the CURRENT model, so a
    # fresh DB going through `alembic upgrade head` will already have these
    # columns/indexes by the time we get here. Existing v1.0.11 upgraders
    # only have the pre-v1.2.0 shape, so we still need the ADD path.
    bind             = op.get_bind()
    inspector        = sa.inspect(bind)
    existing_cols    = {c["name"]  for c  in inspector.get_columns("audit_logs")}
    existing_indexes = {ix["name"] for ix in inspector.get_indexes("audit_logs")}

    for name, coltype in _NEW_COLUMNS:
        if name not in existing_cols:
            op.add_column("audit_logs", sa.Column(name, coltype, nullable=True))

    for name, cols in _NEW_INDEXES:
        if name not in existing_indexes:
            op.create_index(name, "audit_logs", cols)


def downgrade() -> None:
    bind             = op.get_bind()
    inspector        = sa.inspect(bind)
    existing_cols    = {c["name"]  for c  in inspector.get_columns("audit_logs")}
    existing_indexes = {ix["name"] for ix in inspector.get_indexes("audit_logs")}

    for name, _cols in _NEW_INDEXES:
        if name in existing_indexes:
            op.drop_index(name, table_name="audit_logs")

    for name, _coltype in reversed(_NEW_COLUMNS):
        if name in existing_cols:
            op.drop_column("audit_logs", name)
