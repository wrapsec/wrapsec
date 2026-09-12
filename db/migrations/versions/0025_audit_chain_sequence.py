# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""order the audit chain by an explicit sequence instead of by the clock

Revision ID: 0025_audit_chain_sequence
Revises: 0024_ip_allowlist_jsonb
Create Date: 2026-09-11

The per-tenant hash chain selected its predecessor with
`ORDER BY created_at DESC LIMIT 1`, and `created_at` was stamped BEFORE the
advisory lock that serialises the write. Two writes whose timestamps are not in
insertion order -- a clock stepping back, or two requests that both stamped the
time before either took the lock -- therefore selected the same predecessor.
Both rows then carried the same `prev_hash`: a fork, with one row orphaned from
the chain.

Ordering cannot depend on a clock. This adds the column it depends on instead.

WHY NOT THE PRIMARY KEY. `audit_logs.id` is a UUID4 (`db/models.py`), which is
random. Ordering by it is not insertion order; it is arbitrary.

WHY PER TENANT. The chain is per tenant. A single global counter would be
monotonic but not dense within a tenant, so a verifier could not tell a gap left
by retention from a range in which that tenant simply wrote nothing.

TWO COLUMNS:

  chain_seq     BIGINT   -- position within this tenant's chain, from 1
  chain_format  SMALLINT -- which canonical field set this row was hashed under

`chain_format` exists because `chain_seq` is itself hashed from now on: ordering
that is not covered by the hash is ordering an attacker may renumber freely.
Adding a field changes the hash input, and every row already on disk was hashed
without it. Rather than recompute those -- which would destroy the only evidence
they carry -- each row records its own format and is verified under that format's
field set. Format 1 is the 34 fields of today; format 2 adds `chain_seq`.

THE BACKFILL DOES NOT REPAIR HISTORY. Existing rows get a `chain_seq` in
`created_at, id` order and keep `chain_format = 1` and their stored hashes
byte-for-byte. Where a fork already exists, the backfill numbers those rows in
the order they are in and leaves the fork intact, visible to the verifier. It is
not this migration's business to rewrite what happened; `id` is a tiebreaker for
determinism when two rows share a timestamp, not a claim about their order.

Rows with `record_hash IS NULL` -- written before the chain existed -- are left
with `chain_seq NULL`. They belong to no chain, and numbering them would say
otherwise.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

_TABLE = "audit_logs"
_INDEX = "ix_audit_logs_tenant_chain_seq"

# 0004 put a BEFORE UPDATE trigger on this table that raises on any update to a
# row whose record_hash is set. The backfill below writes chain_seq to exactly
# those rows, so the two cannot both hold: the migration completes on a database
# with no chained rows and aborts on every database that has any.
_IMMUTABILITY_TRIGGER = "audit_logs_no_update_on_chained"


def _inspector():
    return sa.inspect(op.get_bind())


def _immutability_trigger_armed(bind) -> bool:
    """Whether this database has the 0004 trigger installed and active.

    Checked rather than assumed. A database built from the models has the table
    without the trigger, because a trigger is not something a model declares, and
    disabling one that is not there is an error rather than a no-op.
    """
    if bind.dialect.name != "postgresql":
        return False
    return bool(
        bind.execute(
            sa.text(
                "SELECT 1 FROM pg_trigger"
                " WHERE tgrelid = CAST(:table AS regclass)"
                "   AND tgname  = :name"
                "   AND NOT tgisinternal"
                "   AND tgenabled <> 'D'"
            ),
            {"table": _TABLE, "name": _IMMUTABILITY_TRIGGER},
        ).scalar()
    )


def _existing_columns() -> set[str]:
    inspector = _inspector()
    if _TABLE not in inspector.get_table_names():
        return set()
    return {column["name"] for column in inspector.get_columns(_TABLE)}


def _existing_indexes() -> set[str]:
    inspector = _inspector()
    if _TABLE not in inspector.get_table_names():
        return set()
    return {str(i["name"]) for i in inspector.get_indexes(_TABLE) if i.get("name")}


revision      = "0025_audit_chain_sequence"
down_revision = "0024_ip_allowlist_jsonb"
branch_labels = None
depends_on    = None


def upgrade() -> None:
    # The baseline builds this table FROM THE MODELS, so a fresh database
    # already has both columns by the time this runs and `add_column` would
    # fail with a duplicate. An upgraded database does not. Both paths reach the
    # same head, so every step has to tolerate either -- the same guard 0023
    # uses for the same reason.
    present = _existing_columns()
    if not present:
        return  # table absent on a throwaway database; nothing to alter

    if "chain_seq" not in present:
        op.add_column(_TABLE, sa.Column("chain_seq", sa.BigInteger(), nullable=True))
    if "chain_format" not in present:
        op.add_column(
            _TABLE,
            sa.Column("chain_format", sa.SmallInteger(), nullable=False, server_default="1"),
        )

    bind = op.get_bind()

    # THE ROWS THAT NEED NUMBERING ARE THE ROWS THAT CANNOT BE UPDATED.
    #
    # Suspended for the backfill, then re-armed, both inside this migration's
    # transaction: if anything below raises, the rollback takes the suspension
    # with it and the table is never left writable. DISABLE TRIGGER needs table
    # ownership rather than superuser, so it works where the application role
    # owns its own schema.
    #
    # WHAT THE TRIGGER PROTECTS IS NOT WEAKENED. It exists so a chained row's
    # hashed content cannot change. `chain_seq` is not hashed under format 1
    # (`CANONICAL_FIELDS` in security/audit_chain.py; only `CANONICAL_FIELDS_V2`
    # includes it), and the backfill writes nothing else, so every historical
    # row keeps its stored hash byte-for-byte and stays verifiable under the
    # field set it was hashed with. The alternative -- teaching the trigger to
    # permit some updates -- would widen what is mutable for good, to buy a
    # one-off.
    #
    # LEAVING THE ROWS NULL IS NOT AN OPTION. The writer's tip lookup selects
    # `WHERE record_hash IS NOT NULL ORDER BY chain_seq DESC LIMIT 1`, and
    # Postgres sorts nulls FIRST under DESC. A chained row left at NULL would be
    # picked as the tip by every subsequent write, each restarting the sequence
    # at 1 and chaining from the same arbitrary ancestor -- the fork this
    # migration exists to prevent.
    trigger_was_armed = _immutability_trigger_armed(bind)
    if trigger_was_armed:
        op.execute(f"ALTER TABLE {_TABLE} DISABLE TRIGGER {_IMMUTABILITY_TRIGGER}")

    # Backfill per tenant, in the order the rows already have. Chained rows only:
    # an unchained row (record_hash IS NULL) has no position to be given.
    #
    # Written as one UPDATE from a window function so the numbering is computed
    # by the database in a single pass rather than row by row from Python -- an
    # audit table is the one table that is large by design.
    if bind.dialect.name == "postgresql":
        op.execute(
            """
            WITH ordered AS (
                SELECT id,
                       ROW_NUMBER() OVER (
                           PARTITION BY tenant_id
                           ORDER BY created_at, id
                       ) AS seq
                FROM audit_logs
                WHERE tenant_id IS NOT NULL
                  AND record_hash IS NOT NULL
            )
            UPDATE audit_logs AS a
               SET chain_seq = ordered.seq
              FROM ordered
             WHERE a.id = ordered.id
            """
        )
    else:
        # SQLite supports the same window function from 3.25; the UPDATE ... FROM
        # form differs, so the correlated subquery is used instead.
        op.execute(
            """
            UPDATE audit_logs
               SET chain_seq = (
                   SELECT COUNT(*)
                     FROM audit_logs AS earlier
                    WHERE earlier.tenant_id = audit_logs.tenant_id
                      AND earlier.record_hash IS NOT NULL
                      AND (earlier.created_at < audit_logs.created_at
                           OR (earlier.created_at = audit_logs.created_at
                               AND earlier.id <= audit_logs.id))
               )
             WHERE tenant_id IS NOT NULL
               AND record_hash IS NOT NULL
            """
        )

    # Re-armed the moment the backfill is done, before anything else runs. The
    # transaction would restore it on a rollback anyway; doing it here means the
    # table is not writable for one statement longer than the backfill needs.
    if trigger_was_armed:
        op.execute(f"ALTER TABLE {_TABLE} ENABLE TRIGGER {_IMMUTABILITY_TRIGGER}")

        # Verified rather than assumed. A migration that left this table mutable
        # would remove the control silently, and the next thing to notice would
        # be an audit trail nobody could trust.
        if not _immutability_trigger_armed(bind):
            raise RuntimeError(
                f"{_IMMUTABILITY_TRIGGER} was not re-armed after the chain_seq "
                f"backfill; refusing to finish with {_TABLE} left mutable"
            )

    # The writer's tip lookup is `WHERE tenant_id = :t AND record_hash IS NOT NULL
    # ORDER BY chain_seq DESC LIMIT 1`, under the advisory lock. This index makes
    # that a backwards index scan of one row rather than a sort of the tenant's
    # whole history, which matters because it runs inside the lock.
    if _INDEX not in _existing_indexes():
        op.create_index(_INDEX, _TABLE, ["tenant_id", "chain_seq"])


def downgrade() -> None:
    if _INDEX in _existing_indexes():
        op.drop_index(_INDEX, table_name=_TABLE)
    present = _existing_columns()
    if "chain_format" in present:
        op.drop_column(_TABLE, "chain_format")
    if "chain_seq" in present:
        op.drop_column(_TABLE, "chain_seq")
