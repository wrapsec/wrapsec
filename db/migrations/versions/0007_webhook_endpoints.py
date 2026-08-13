# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""add webhook_endpoints table with per-endpoint HMAC secret

Revision ID: 0007_webhook_endpoints
Revises: 0006_json_to_jsonb
Create Date: 2026-07-29

v1.3.0 groundwork. Adds `webhook_endpoints` for outbound webhook
destinations. Grain: one row per (tenant, url). Per-endpoint secret
(not per-tenant) so a tenant can route BLOCK events to multiple
destinations with independent verification material and rotate each
one in isolation.

Rotation: `old_secrets` is a JSON array of {ciphertext, expires_at}
entries that remain valid for signature verification until their
expiry -- receivers keep verifying with the old secret until it
expires, no hard cut-off.

Secrets envelope-encrypted at rest via security.encryption (v2 wire
format, per-record DEK). No plaintext column ever exists.

Circuit breaker: `disabled` + `first_failure_at` track consecutive
failure state; a background sweep in a later v1.3.0 commit flips
`disabled` after the configured grace window.

JSON columns use JSONB on postgres and JSON on SQLite so the model's
JSONVariant alias resolves consistently and unit tests keep working
against SQLite without dialect errors.

Idempotent against baseline drift. `0001_baseline` runs
`Base.metadata.create_all(checkfirst=True)` off the CURRENT model, so
fresh installs already have this table by the time we get here;
existing v1.2.x upgraders do not, and the ADD path runs for them.
Same pattern used in 0003_audit_session_hash.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "0007_webhook_endpoints"
down_revision: str | None = "0006_json_to_jsonb"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_TABLE = "webhook_endpoints"


def upgrade() -> None:
    bind      = op.get_bind()
    inspector = sa.inspect(bind)

    if _TABLE in inspector.get_table_names():
        return

    # JSONB on postgres, plain JSON on SQLite. Matches the JSONVariant alias
    # in db/models.py so we do not create the type-drift that migration 0006
    # had to sweep up. `.with_variant(JSON(), "sqlite")` lets unit tests hit
    # a SQLite in-memory DB without dialect errors.
    json_type = JSONB().with_variant(sa.JSON(), "sqlite")

    op.create_table(
        _TABLE,
        sa.Column("id",               UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id",        UUID(as_uuid=True), sa.ForeignKey("tenants.id"),
                                      nullable=False),
        sa.Column("url",              sa.Text(),    nullable=False),
        sa.Column("description",      sa.Text(),    nullable=True),
        sa.Column("secret_enc",       sa.Text(),    nullable=False),
        sa.Column("old_secrets",      json_type,    nullable=True),
        sa.Column("event_types",      json_type,    nullable=True),
        sa.Column("headers",          json_type,    nullable=True),
        sa.Column("disabled",         sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("first_failure_at", sa.DateTime(), nullable=True),
        sa.Column("rate_limit",       sa.Integer(), nullable=True),
        sa.Column("created_at",       sa.DateTime(), nullable=False),
        sa.Column("updated_at",       sa.DateTime(), nullable=True),
        sa.UniqueConstraint("tenant_id", "url", name="uq_webhook_endpoints_tenant_url"),
    )

    op.create_index(
        "ix_webhook_endpoints_tenant_disabled",
        _TABLE,
        ["tenant_id", "disabled"],
    )


def downgrade() -> None:
    bind      = op.get_bind()
    inspector = sa.inspect(bind)

    if _TABLE not in inspector.get_table_names():
        return

    existing_indexes = {ix["name"] for ix in inspector.get_indexes(_TABLE)}
    if "ix_webhook_endpoints_tenant_disabled" in existing_indexes:
        op.drop_index("ix_webhook_endpoints_tenant_disabled", table_name=_TABLE)

    op.drop_table(_TABLE)
