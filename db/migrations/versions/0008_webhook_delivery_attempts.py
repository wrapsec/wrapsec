# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""add webhook_delivery_attempts partitioned table

Revision ID: 0008_webhook_delivery_attempts
Revises: 0007_webhook_endpoints
Create Date: 2026-07-29

v1.3.0 groundwork. Append-only log of every webhook delivery attempt
(first send plus every retry). Sized for the highest-volume table in
the outbound webhook system: 100k tenants x 100 events/day x ~2 retry
avg = ~7B rows/year at the top end. That volume is why the postgres
path is RANGE partitioned on `created_at` from day one -- retrofitting
partitioning on an unpartitioned billion-row table is painful and
rewriting is worse.

Partitioning shape:

  * Monthly RANGE partitions on created_at.
  * No default partition. A missing partition is a loud INSERT error,
    not a silent accumulation into a partition that can never later be
    detached to give the range back to a proper monthly one.
  * Initial migration creates the current month and the next two months
    so we have ~60 days runway before a maintenance job must run.
  * Later v1.3.0 commit adds a scheduled job that creates the next
    upcoming month N days ahead of its start and drops partitions
    older than the retention window.

Composite PK (id, created_at) is a postgres partitioning requirement:
the PK must include every partitioning column. SQLAlchemy's ORM sees
this as a two-column PK; UUID collision on id alone is already
astronomically unlikely so the created_at addition is purely a DDL
constraint, not an application invariant.

SQLite fallback (for unit tests): flat unpartitioned table, same
columns and PK, no partition DDL. Integration tests hit real postgres
via testcontainers and exercise the partitioned path.

Idempotent against baseline drift. 0001_baseline runs
create_all(checkfirst=True) off the CURRENT model. On SQLite that
returns a flat table already; on fresh postgres it does NOT return a
partitioned parent (SQLAlchemy has no PARTITION BY support), so a
fresh install will hit this migration and get the partitioned shape.
Existing v1.2.x upgraders take the same ADD path.
"""
from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import UUID

revision: str = "0008_webhook_delivery_attempts"
down_revision: str | None = "0007_webhook_endpoints"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_TABLE           = "webhook_delivery_attempts"
_MONTHS_INITIAL  = 3   # current month + 2 ahead


def _month_bounds(year: int, month: int) -> tuple[str, str]:
    """Return (inclusive-start, exclusive-end) ISO dates for a month."""
    start = f"{year:04d}-{month:02d}-01"
    if month == 12:
        end = f"{year + 1:04d}-01-01"
    else:
        end = f"{year:04d}-{month + 1:02d}-01"
    return start, end


def _create_month_partition(bind, parent: str, year: int, month: int) -> None:
    start, end = _month_bounds(year, month)
    partition  = f"{parent}_{year:04d}_{month:02d}"
    bind.execute(text(
        f"CREATE TABLE IF NOT EXISTS {partition} "
        f"PARTITION OF {parent} "
        f"FOR VALUES FROM ('{start}') TO ('{end}')"
    ))


def _upgrade_postgres(bind) -> None:
    bind.execute(text(f"""
        CREATE TABLE {_TABLE} (
            id                      UUID          NOT NULL,
            created_at              TIMESTAMP     NOT NULL,
            endpoint_id             UUID          NOT NULL REFERENCES webhook_endpoints(id),
            tenant_id               UUID          NOT NULL REFERENCES tenants(id),
            msg_id                  VARCHAR(64)   NOT NULL,
            url                     TEXT          NOT NULL,
            event_type              VARCHAR(100)  NOT NULL,
            attempt_number          INTEGER       NOT NULL,
            status                  VARCHAR(20)   NOT NULL,
            http_status_code        INTEGER,
            response_body_truncated TEXT,
            response_duration_ms    INTEGER,
            error_message           TEXT,
            next_attempt_at         TIMESTAMP,
            ended_at                TIMESTAMP,
            PRIMARY KEY (id, created_at)
        ) PARTITION BY RANGE (created_at)
    """))

    # Indexes on partitioned parent -- inherited by every partition, present
    # and future. Btree on next_attempt_at supports the retry scheduler's
    # range scan; NULL entries (terminal or in-flight) fall to the end.
    bind.execute(text(
        f"CREATE INDEX ix_webhook_delivery_attempts_msg_id ON {_TABLE} (msg_id)"
    ))
    bind.execute(text(
        f"CREATE INDEX ix_webhook_delivery_attempts_endpoint_status "
        f"ON {_TABLE} (endpoint_id, status)"
    ))
    bind.execute(text(
        f"CREATE INDEX ix_webhook_delivery_attempts_next_attempt "
        f"ON {_TABLE} (next_attempt_at)"
    ))

    # Initial partitions: current + 2 months forward. Any INSERT before the
    # first covered month will fail loudly by design; there is no default
    # partition to swallow it.
    now = datetime.now(timezone.utc)
    y, m = now.year, now.month
    for _ in range(_MONTHS_INITIAL):
        _create_month_partition(bind, _TABLE, y, m)
        m += 1
        if m > 12:
            m  = 1
            y += 1


def _upgrade_generic() -> None:
    # SQLite / other backends without native partitioning. Flat table,
    # identical columns and indexes, sufficient for unit tests.
    op.create_table(
        _TABLE,
        sa.Column("id",                      UUID(as_uuid=True), nullable=False),
        sa.Column("created_at",              sa.DateTime(),      nullable=False),
        sa.Column("endpoint_id",             UUID(as_uuid=True),
                                             sa.ForeignKey("webhook_endpoints.id"), nullable=False),
        sa.Column("tenant_id",               UUID(as_uuid=True),
                                             sa.ForeignKey("tenants.id"),           nullable=False),
        sa.Column("msg_id",                  sa.String(64),  nullable=False),
        sa.Column("url",                     sa.Text(),      nullable=False),
        sa.Column("event_type",              sa.String(100), nullable=False),
        sa.Column("attempt_number",          sa.Integer(),   nullable=False),
        sa.Column("status",                  sa.String(20),  nullable=False),
        sa.Column("http_status_code",        sa.Integer(),   nullable=True),
        sa.Column("response_body_truncated", sa.Text(),      nullable=True),
        sa.Column("response_duration_ms",    sa.Integer(),   nullable=True),
        sa.Column("error_message",           sa.Text(),      nullable=True),
        sa.Column("next_attempt_at",         sa.DateTime(),  nullable=True),
        sa.Column("ended_at",                sa.DateTime(),  nullable=True),
        sa.PrimaryKeyConstraint("id", "created_at"),
    )
    op.create_index("ix_webhook_delivery_attempts_msg_id",          _TABLE, ["msg_id"])
    op.create_index("ix_webhook_delivery_attempts_endpoint_status", _TABLE, ["endpoint_id", "status"])
    op.create_index("ix_webhook_delivery_attempts_next_attempt",    _TABLE, ["next_attempt_at"])


def upgrade() -> None:
    bind      = op.get_bind()
    inspector = sa.inspect(bind)

    if _TABLE in inspector.get_table_names():
        return

    if bind.dialect.name == "postgresql":
        _upgrade_postgres(bind)
    else:
        _upgrade_generic()


def downgrade() -> None:
    bind      = op.get_bind()
    inspector = sa.inspect(bind)

    if _TABLE not in inspector.get_table_names():
        return

    # DROP TABLE on the partitioned parent cascades to all partitions;
    # SQLite path just drops the flat table. Same statement works for
    # both backends.
    op.execute(f"DROP TABLE {_TABLE} CASCADE" if bind.dialect.name == "postgresql"
               else f"DROP TABLE {_TABLE}")
