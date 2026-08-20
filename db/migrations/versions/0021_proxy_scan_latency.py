# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""proxy interactions: record how long security scanning took

Revision ID: 0021_proxy_scan_latency
Revises: 0020_tenant_lifecycle
Create Date: 2026-08-20

Total and provider latency were already recorded, so the security overhead a
deployment pays could only be inferred by subtraction, which silently attributes
queueing and serialisation to scanning. Record the input and output scan times
directly instead, so the cost of the guardrails is measurable on its own and a
latency regression is visible before a caller reports it.

Both columns are nullable: rows written before this migration have no scan
timings, and a request that never reached the output guard has no output timing.

Guarded/idempotent. On a fresh model-driven baseline the columns already exist
and each step is a no-op.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0021_proxy_scan_latency"
down_revision: str | None = "0020_tenant_lifecycle"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE   = "proxy_interactions"
_COLUMNS = ("input_scan_ms", "output_scan_ms")


def _existing_columns() -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if _TABLE not in inspector.get_table_names():
        return set()
    return {column["name"] for column in inspector.get_columns(_TABLE)}


def upgrade() -> None:
    present = _existing_columns()
    if not present:
        return  # table absent on a throwaway database; nothing to alter
    for column in _COLUMNS:
        if column not in present:
            op.add_column(_TABLE, sa.Column(column, sa.Integer(), nullable=True))


def downgrade() -> None:
    present = _existing_columns()
    for column in _COLUMNS:
        if column in present:
            op.drop_column(_TABLE, column)
