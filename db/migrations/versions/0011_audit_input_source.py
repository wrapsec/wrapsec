# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""add input_source column to audit_logs

Revision ID: 0011_audit_input_source
Revises: 0010_timestamptz
Create Date: 2026-08-04

v1.7.0 input provenance (trust boundary). Adds a NOT NULL `input_source` column
to audit_logs recording where the scanned text came from (user_prompt by
default; tool_output / retrieved_document / external_content mark agent-pulled
content -- the indirect prompt-injection surface).

NOT NULL with a server default of 'user_prompt' so the ADD is safe on a live
table: existing rows backfill to 'user_prompt' and every future row carries an
explicit source (the engine and audit never see NULL).

Hash-chain note: 0011 also adds input_source to security/audit_chain.py
CANONICAL_FIELDS, so rows written from this release forward hash over it. Rows
written BEFORE this release hashed without it and will not re-verify once the
column is populated -- acceptable here only because the pre-v1.7 audit_logs is
demo/sample data with no real adopters and is truncated + reseeded as part of
this change. A production deployment with a live chain would instead need a
per-row hash-schema epoch; that is out of scope until there is real data.

Idempotent: guarded by a column-existence check so a re-run (or a fresh install
whose model-driven baseline already has the column) is a no-op.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0011_audit_input_source"
down_revision: Union[str, None] = "0010_timestamptz"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TABLE = "audit_logs"
_COLUMN = "input_source"


def upgrade() -> None:
    bind      = op.get_bind()
    inspector = sa.inspect(bind)

    if _TABLE not in inspector.get_table_names():
        return

    existing = {col["name"] for col in inspector.get_columns(_TABLE)}
    if _COLUMN not in existing:
        op.add_column(
            _TABLE,
            sa.Column(
                _COLUMN,
                sa.String(32),
                nullable=False,
                server_default="user_prompt",
            ),
        )


def downgrade() -> None:
    bind      = op.get_bind()
    inspector = sa.inspect(bind)

    if _TABLE not in inspector.get_table_names():
        return

    existing = {col["name"] for col in inspector.get_columns(_TABLE)}
    if _COLUMN in existing:
        op.drop_column(_TABLE, _COLUMN)
