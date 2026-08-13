# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""migrate all event timestamps to timestamptz (aware UTC)

Revision ID: 0010_timestamptz
Revises: 0009_webhook_connector_type
Create Date: 2026-08-02

Timestamp architecture decision (Path A): WrapSec stores every event timestamp
as TIMESTAMPTZ and works in aware UTC end to end. This migration converts the
existing schema from TIMESTAMP WITHOUT TIME ZONE to TIMESTAMPTZ.

Two shapes:

  * Flat tables -- a plain
        ALTER COLUMN col TYPE timestamptz USING col AT TIME ZONE 'UTC'
    for each timestamp column. The stored values were naive UTC, so
    interpreting them AT TIME ZONE 'UTC' preserves the instant exactly.

  * webhook_delivery_attempts -- RANGE partitioned on created_at (the
    partition key, also part of the composite PK). Postgres forbids
    ALTER COLUMN TYPE on a partition-key column, so this table is migrated
    with a DATA-PRESERVING SWAP: build a new timestamptz partitioned table,
    copy every row (converting naive -> aware UTC), drop the old table, then
    rename the new table and its partitions into place. No rows are lost and
    the operation is correct for any install, not just a pre-launch one.

Idempotent: every conversion is guarded on the column's current data_type, so
a re-run (or a fresh install whose baseline already created timestamptz columns
off the current model) is a no-op. PostgreSQL only; the SQLite test fallback
has no timestamptz type and is skipped.

Only tables present in the current ORM model are converted. Orphan tables left
over from older schemas (account_lockouts, llm_detector_configs) are not in the
model, are never created on fresh installs, and are intentionally left alone.
"""
from __future__ import annotations

import datetime as _dt
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text

revision: str = "0010_timestamptz"
down_revision: str | None = "0009_webhook_connector_type"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# Flat (non-partitioned) tables and their timestamp columns.
_FLAT_COLUMNS: dict[str, list[str]] = {
    "tenants":                ["created_at"],
    "departments":            ["created_at"],
    "applications":           ["created_at"],
    "audit_logs":             ["created_at"],
    "api_keys":               ["expires_at", "last_used_at", "created_at"],
    "settings":               ["updated_at"],
    "proxy_provider_configs": ["created_at", "updated_at"],
    "proxy_interactions":     ["created_at"],
    "users":                  ["created_at", "last_login_at"],
    "refresh_tokens":         ["expires_at", "revoked_at", "created_at"],
    "admin_events":           ["created_at"],
    "auth_events":            ["created_at"],
    "webhook_endpoints":      ["first_failure_at", "created_at", "updated_at"],
}

_PART_TABLE   = "webhook_delivery_attempts"
_PART_COLUMNS = ["created_at", "next_attempt_at", "ended_at"]

_NAIVE = "timestamp without time zone"
_AWARE = "timestamp with time zone"

_PART_INDEXES = [
    ("ix_webhook_delivery_attempts_msg_id",          "(msg_id)"),
    ("ix_webhook_delivery_attempts_endpoint_status", "(endpoint_id, status)"),
    ("ix_webhook_delivery_attempts_next_attempt",    "(next_attempt_at)"),
]


# ---------------------------------------------------------------------------
# helpers

def _data_type(bind, table: str, col: str) -> str | None:
    return bind.execute(
        text(
            "SELECT data_type FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name = :t AND column_name = :c"
        ),
        {"t": table, "c": col},
    ).scalar()


def _is_partitioned(bind, table: str) -> bool:
    return bool(
        bind.execute(
            text("SELECT relkind = 'p' FROM pg_class WHERE relname = :t"),
            {"t": table},
        ).scalar()
    )


def _alter_column_type(bind, table: str, col: str, ts_type: str) -> None:
    bind.execute(
        text(
            f'ALTER TABLE {table} ALTER COLUMN {col} TYPE {ts_type} '
            f"USING {col} AT TIME ZONE 'UTC'"
        )
    )


def _months_needed(bind, table: str) -> list[tuple[int, int]]:
    """Months to create partitions for: every month present in existing data
    plus the current month and the next two (mirroring 0008's runway)."""
    rows = bind.execute(
        text(f"SELECT DISTINCT date_trunc('month', created_at) AS m FROM {table}")
    ).fetchall()
    months = {(r[0].year, r[0].month) for r in rows if r[0] is not None}

    now = _dt.datetime.now(_dt.timezone.utc)
    y, m = now.year, now.month
    for _ in range(3):
        months.add((y, m))
        m += 1
        if m > 12:
            m = 1
            y += 1
    return sorted(months)


def _month_bounds_utc(year: int, month: int) -> tuple[str, str]:
    start = f"{year:04d}-{month:02d}-01 00:00:00+00"
    if month == 12:
        end = f"{year + 1:04d}-01-01 00:00:00+00"
    else:
        end = f"{year:04d}-{month + 1:02d}-01 00:00:00+00"
    return start, end


def _swap_partitioned(bind, ts_type: str) -> None:
    """Rebuild the partitioned webhook_delivery_attempts with `ts_type` for its
    timestamp columns, preserving every row. Used for both the upgrade
    (-> timestamptz) and the downgrade (-> timestamp). The copy expression
    `col AT TIME ZONE 'UTC'` is correct in both directions: on a naive value it
    yields timestamptz, on an aware value it yields naive UTC -- matching the
    target column type either way."""
    new     = f"{_PART_TABLE}__new"
    months  = _months_needed(bind, _PART_TABLE)

    bind.execute(text(
        f"""
        CREATE TABLE {new} (
            id                      UUID          NOT NULL,
            created_at              {ts_type}     NOT NULL,
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
            next_attempt_at         {ts_type},
            ended_at                {ts_type},
            PRIMARY KEY (id, created_at)
        ) PARTITION BY RANGE (created_at)
        """
    ))

    for y, m in months:
        start, end = _month_bounds_utc(y, m)
        bind.execute(text(
            f"CREATE TABLE {new}_{y:04d}_{m:02d} PARTITION OF {new} "
            f"FOR VALUES FROM ('{start}') TO ('{end}')"
        ))

    bind.execute(text(
        f"""
        INSERT INTO {new} (
            id, created_at, endpoint_id, tenant_id, msg_id, url, event_type,
            attempt_number, status, http_status_code, response_body_truncated,
            response_duration_ms, error_message, next_attempt_at, ended_at
        )
        SELECT
            id, created_at AT TIME ZONE 'UTC', endpoint_id, tenant_id, msg_id,
            url, event_type, attempt_number, status, http_status_code,
            response_body_truncated, response_duration_ms, error_message,
            next_attempt_at AT TIME ZONE 'UTC', ended_at AT TIME ZONE 'UTC'
        FROM {_PART_TABLE}
        """
    ))

    # Drop the old parent (cascades to its partitions) and move the new one and
    # its partitions into the canonical names so the naming convention that the
    # partition-maintenance job relies on ({parent}_{yyyy}_{mm}) is preserved.
    bind.execute(text(f"DROP TABLE {_PART_TABLE} CASCADE"))
    bind.execute(text(f"ALTER TABLE {new} RENAME TO {_PART_TABLE}"))
    for y, m in months:
        bind.execute(text(
            f"ALTER TABLE {new}_{y:04d}_{m:02d} "
            f"RENAME TO {_PART_TABLE}_{y:04d}_{m:02d}"
        ))
    for name, cols in _PART_INDEXES:
        bind.execute(text(f"CREATE INDEX {name} ON {_PART_TABLE} {cols}"))


# ---------------------------------------------------------------------------
# migration

def _convert(bind, target_type: str, from_type: str) -> None:
    inspector = sa.inspect(bind)
    tables    = set(inspector.get_table_names())

    for table, cols in _FLAT_COLUMNS.items():
        if table not in tables:
            continue
        for col in cols:
            if _data_type(bind, table, col) == from_type:
                _alter_column_type(bind, table, col, target_type)

    if _PART_TABLE in tables and _data_type(bind, _PART_TABLE, "created_at") == from_type:
        if _is_partitioned(bind, _PART_TABLE):
            _swap_partitioned(bind, target_type)
        else:
            # Fresh installs create this flat (baseline create_all cannot
            # partition); a plain ALTER is enough when it is not partitioned.
            for col in _PART_COLUMNS:
                if _data_type(bind, _PART_TABLE, col) == from_type:
                    _alter_column_type(bind, _PART_TABLE, col, target_type)


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    _convert(bind, "timestamptz", _NAIVE)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    _convert(bind, "timestamp", _AWARE)
