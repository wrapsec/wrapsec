# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""add email_outbox table

Revision ID: 0014_email_outbox
Revises: 0013_user_tenant_locale
Create Date: 2026-08-12

v1.8.3 transactional email. A durable outbox: one row per notification, created
inside the business transaction that triggers it, delivered by a background
worker. Low volume (security notifications only), so a flat table -- no
partitioning, unlike webhook_delivery_attempts.

Timestamp columns are TIMESTAMPTZ (timezone=True), consistent with the Path A
timestamp architecture (migration 0010). The worker claim scan filters
(status, available_at), so the leading composite index serves it as a range
scan; a second index supports tenant-scoped audit listing.

Idempotent: guarded by a table-existence check, so a re-run or a fresh
model-driven create_all baseline that already has the table is a no-op.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision: str = "0014_email_outbox"
down_revision: str | None = "0013_user_tenant_locale"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_TABLE = "email_outbox"


def upgrade() -> None:
    bind      = op.get_bind()
    inspector = sa.inspect(bind)

    if _TABLE in inspector.get_table_names():
        return

    op.create_table(
        _TABLE,
        sa.Column("id",                  UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id",           UUID(as_uuid=True),
                                         sa.ForeignKey("tenants.id"), nullable=True),
        # Denormalized audit references (no FK): the outbox must not couple to
        # the user/department lifecycle, and the recipient address is
        # snapshotted below. department_id is NULL for tenant-level notifications
        # and belongs to tenant_id by construction (both copied from the user).
        sa.Column("department_id",       UUID(as_uuid=True), nullable=True),
        sa.Column("user_id",             UUID(as_uuid=True), nullable=True),
        sa.Column("notification_type",   sa.String(64),  nullable=False),
        sa.Column("recipient",           sa.String(255), nullable=False),
        sa.Column("locale",              sa.String(35),  nullable=True),
        sa.Column("subject",             sa.Text(),      nullable=False),
        sa.Column("body_text",           sa.Text(),      nullable=False),
        sa.Column("body_html",           sa.Text(),      nullable=True),
        sa.Column("status",              sa.String(20),  nullable=False, server_default="queued"),
        sa.Column("attempt_count",       sa.Integer(),   nullable=False, server_default="0"),
        sa.Column("available_at",        sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at",          sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at",          sa.DateTime(timezone=True), nullable=True),
        sa.Column("sending_at",          sa.DateTime(timezone=True), nullable=True),
        sa.Column("sent_at",             sa.DateTime(timezone=True), nullable=True),
        sa.Column("provider_message_id", sa.String(255), nullable=True),
        sa.Column("last_error",          sa.Text(),      nullable=True),
        sa.Column("trace_id",            sa.String(64),  nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_email_outbox_status_available", _TABLE, ["status", "available_at"])
    op.create_index("ix_email_outbox_tenant_created",   _TABLE, ["tenant_id", "created_at"])


def downgrade() -> None:
    bind      = op.get_bind()
    inspector = sa.inspect(bind)

    if _TABLE not in inspector.get_table_names():
        return

    op.drop_index("ix_email_outbox_tenant_created",   table_name=_TABLE)
    op.drop_index("ix_email_outbox_status_available", table_name=_TABLE)
    op.drop_table(_TABLE)
