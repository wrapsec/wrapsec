# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""api keys: restrict a credential to named source networks

Revision ID: 0022_api_key_ip_allowlist
Revises: 0021_proxy_scan_latency
Create Date: 2026-08-20

A leaked key is usable from anywhere until its owner can revoke it. Recording
the networks a credential is valid from narrows that window to the places its
owner actually operates.

The column is nullable and the control is off when it is null or empty, so every
existing credential keeps working unchanged after this runs. Reading an absent
list as "deny everything" would turn the upgrade into an outage.

Guarded/idempotent. On a fresh model-driven baseline the column already exists
and the step is a no-op.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0022_api_key_ip_allowlist"
down_revision: str | None = "0021_proxy_scan_latency"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE  = "api_keys"
_COLUMN = "ip_allowlist"


def _existing_columns() -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if _TABLE not in inspector.get_table_names():
        return set()
    return {column["name"] for column in inspector.get_columns(_TABLE)}


def upgrade() -> None:
    present = _existing_columns()
    if not present or _COLUMN in present:
        return
    op.add_column(
        _TABLE,
        sa.Column(_COLUMN, sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    if _COLUMN in _existing_columns():
        op.drop_column(_TABLE, _COLUMN)
