# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""align all JSON columns to JSONB on PostgreSQL

Revision ID: 0006_json_to_jsonb
Revises: 0005_add_auditor_role
Create Date: 2026-07-28

Every JSON-holding column in the schema is queried via jsonb operators
(jsonb_array_elements_text, cast(.., JSONB).contains(..)). Historically
the model declared these as `Column(JSON, ...)` but the live production
database had them as `jsonb` from a pre-baseline hand-alter that never
made it into a tracked migration. Testcontainers-driven fresh installs
(v1.2.3) exposed the drift: a clean 0001_baseline creates `json` columns
and the /v1/audit/stats endpoint fails with
`function jsonb_array_elements_text(json) does not exist`.

Twelve columns across seven tables are affected:

  tenants.global_policy                   applications.metadata
  departments.policy_override             applications.policy_override
  applications.rate_limit_override        audit_logs.threats
  audit_logs.detection_scores             audit_logs.guardrail_scores
  admin_events.metadata                   proxy_interactions.input_threats
  proxy_interactions.output_threats       proxy_interactions.output_flags

Idempotent by design: each ALTER is guarded by a lookup in
information_schema.columns that skips columns already at `jsonb`. On
pre-existing installs the up-dev database (9 already-jsonb, 3 json) sees
only the three proxy_interactions columns rewritten; on a fresh install
that has been through the updated 0001_baseline (create_all now sees
JSONVariant which maps to JSONB on postgres), every column is already
jsonb and every ALTER is a no-op.

Downgrade: unconditionally converts back to `json`. This is lossy for
whitespace and key ordering but not for structured payloads (threats
arrays, score dicts, policy objects) that WrapSec actually stores.

SQLite: no-op. SQLite has no jsonb type -- the JSONVariant defined in
db/models.py falls back to plain `json` (SQLAlchemy JSON) so unit tests
keep working without any schema changes.
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op
from sqlalchemy import text

revision: str = "0006_json_to_jsonb"
down_revision: str | None = "0005_add_auditor_role"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_TARGETS: list[tuple[str, str]] = [
    ("tenants",            "global_policy"),
    ("departments",        "policy_override"),
    ("applications",       "metadata"),
    ("applications",       "policy_override"),
    ("applications",       "rate_limit_override"),
    ("audit_logs",         "threats"),
    ("audit_logs",         "detection_scores"),
    ("audit_logs",         "guardrail_scores"),
    ("admin_events",       "metadata"),
    ("proxy_interactions", "input_threats"),
    ("proxy_interactions", "output_threats"),
    ("proxy_interactions", "output_flags"),
]


def _current_type(bind, table: str, column: str) -> str | None:
    row = bind.execute(
        text(
            "SELECT data_type FROM information_schema.columns "
            "WHERE table_name = :t AND column_name = :c"
        ),
        {"t": table, "c": column},
    ).first()
    return row[0] if row else None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        # SQLite / anything else: JSONVariant falls back to JSON. Nothing
        # to migrate.
        return

    for table, column in _TARGETS:
        if _current_type(bind, table, column) == "json":
            op.execute(
                f"ALTER TABLE {table} "
                f"ALTER COLUMN {column} TYPE jsonb USING {column}::jsonb"
            )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    for table, column in _TARGETS:
        if _current_type(bind, table, column) == "jsonb":
            op.execute(
                f"ALTER TABLE {table} "
                f"ALTER COLUMN {column} TYPE json USING {column}::json"
            )
