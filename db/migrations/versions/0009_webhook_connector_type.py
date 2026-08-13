# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""add connector_type and config columns to webhook_endpoints

Revision ID: 0009_webhook_connector_type
Revises: 0008_webhook_delivery_attempts
Create Date: 2026-07-30

v1.3.0 delivery pipeline (12b.1). Adds two nullable columns to
webhook_endpoints:

  * connector_type -- NULL means a generic HMAC-signed webhook
    (secret_enc is a signing secret). A connector slug ("splunk_hec",
    "datadog_logs", "sentinel_logs_ingestion", "elastic_ecs") routes the
    endpoint through a SIEM connector, in which case secret_enc holds
    that connector's ingest token/key.

  * config -- per-connector options (Sentinel dcr_immutable_id/
    stream_name, Elastic index, Splunk sourcetype, etc.). NULL for
    generic webhooks. JSONB on postgres, JSON on SQLite to match the
    JSONVariant alias in db/models.py.

Both columns are nullable with no server default, so the ADD is
non-locking on postgres (no table rewrite) and every existing row keeps
behaving as a generic webhook -- a safe, backward-compatible change on a
live table.

Idempotent against baseline drift, matching 0007/0008: 0001_baseline
runs create_all(checkfirst=True) off the CURRENT model, so fresh installs
already have these columns; existing v1.3.0-in-progress upgraders do not,
and the ADD path runs only for them. Guarded by a column-existence check
so a re-run (or a fresh install that already has them) is a no-op.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0009_webhook_connector_type"
down_revision: str | None = "0008_webhook_delivery_attempts"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_TABLE = "webhook_endpoints"


def upgrade() -> None:
    bind      = op.get_bind()
    inspector = sa.inspect(bind)

    # If the table itself is absent (should not happen after 0007), there is
    # nothing to alter; the model-driven baseline will create it in full.
    if _TABLE not in inspector.get_table_names():
        return

    existing = {col["name"] for col in inspector.get_columns(_TABLE)}

    if "connector_type" not in existing:
        op.add_column(_TABLE, sa.Column("connector_type", sa.Text(), nullable=True))

    if "config" not in existing:
        json_type = JSONB().with_variant(sa.JSON(), "sqlite")
        op.add_column(_TABLE, sa.Column("config", json_type, nullable=True))


def downgrade() -> None:
    bind      = op.get_bind()
    inspector = sa.inspect(bind)

    if _TABLE not in inspector.get_table_names():
        return

    existing = {col["name"] for col in inspector.get_columns(_TABLE)}

    if "config" in existing:
        op.drop_column(_TABLE, "config")

    if "connector_type" in existing:
        op.drop_column(_TABLE, "connector_type")
