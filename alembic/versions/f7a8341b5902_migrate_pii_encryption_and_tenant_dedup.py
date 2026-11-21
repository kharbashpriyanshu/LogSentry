"""migrate pii encryption backfill, tenant dedup index, and durable enrichment jobs

Revision ID: f7a8341b5902
Revises: e4f912bc7810
Create Date: 2026-11-22 02:30:00.000000

"""

import sqlalchemy as sa
from sqlalchemy.sql import column, select, table

from alembic import op
from app.core.crypto import decrypt_pii, encrypt_pii

# revision identifiers, used by Alembic.
revision = "f7a8341b5902"
down_revision = "e4f912bc7810"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"
    inspector = sa.inspect(bind)

    # 1. Update threat_observables schema: drop old global unique constraint & add composite index
    if is_postgres:
        for cname in ["threat_observables_fingerprint_key", "uq_threat_observables_fingerprint"]:
            try:
                op.execute(f"ALTER TABLE threat_observables DROP CONSTRAINT IF EXISTS {cname}")
            except Exception:
                pass
        with op.batch_alter_table("threat_observables") as batch_op:
            batch_op.create_index(
                "ix_threat_observables_tenant_fingerprint",
                ["tenant_id", "fingerprint"],
            )
    else:
        # SQLite reflection check
        uqs = inspector.get_unique_constraints("threat_observables")
        has_uq = any("fingerprint" in (uq.get("column_names") or []) for uq in uqs)
        naming_convention = {"uq": "uq_%(table_name)s_%(column_0_name)s"}
        with op.batch_alter_table("threat_observables", naming_convention=naming_convention) as batch_op:
            if has_uq:
                try:
                    batch_op.drop_constraint("uq_threat_observables_fingerprint", type_="unique")
                except Exception:
                    pass
            batch_op.create_index(
                "ix_threat_observables_tenant_fingerprint",
                ["tenant_id", "fingerprint"],
            )

    # 2. Create durable persistent threat enrichment jobs queue table with leases & retries
    op.create_table(
        "threat_enrichment_jobs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "observable_id",
            sa.String(length=36),
            sa.ForeignKey("threat_observables.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("observable_value", sa.String(length=2048), nullable=False),
        sa.Column("observable_type", sa.String(length=32), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False, server_default="default"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("locked_by", sa.String(length=128), nullable=True),
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("event_id", sa.String(), nullable=True),
        sa.Column("alert_id", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_threat_enrichment_jobs_observable_id", "threat_enrichment_jobs", ["observable_id"])
    op.create_index("ix_threat_enrichment_jobs_status", "threat_enrichment_jobs", ["status"])
    op.create_index("ix_threat_enrichment_jobs_tenant_id", "threat_enrichment_jobs", ["tenant_id"])
    op.create_index("ix_threat_enrichment_jobs_event_id", "threat_enrichment_jobs", ["event_id"])
    op.create_index("ix_threat_enrichment_jobs_alert_id", "threat_enrichment_jobs", ["alert_id"])
    op.create_index(
        "ix_threat_enrichment_jobs_claim",
        "threat_enrichment_jobs",
        ["status", "next_retry_at", "locked_until"],
    )

    # 3. Data Migration: Backfill existing unencrypted PII records (Strict Fail-Closed)
    observables_tbl = table(
        "threat_observables",
        column("id", sa.String),
        column("type", sa.String),
        column("value", sa.String),
        column("raw_masked", sa.String),
        column("encrypted_value", sa.Text),
    )

    rows = bind.execute(
        select(
            observables_tbl.c.id,
            observables_tbl.c.type,
            observables_tbl.c.value,
            observables_tbl.c.raw_masked,
            observables_tbl.c.encrypted_value,
        ).where(
            observables_tbl.c.type.in_(["email", "phone"])
        )
    ).fetchall()

    migrated_count = 0
    for row in rows:
        r_id, r_type, r_val, r_masked, r_enc = row
        # If unencrypted or containing raw plaintext
        if not r_enc or r_enc.strip() == "":
            try:
                ct = encrypt_pii(r_val)
                # Verify round-trip decryption
                decrypted = decrypt_pii(ct)
                if decrypted != r_val:
                    raise ValueError(f"Round-trip decryption verification failed for observable {r_id}")
                
                # Overwrite value with masked representation and populate encrypted_value
                bind.execute(
                    observables_tbl.update()
                    .where(observables_tbl.c.id == r_id)
                    .values(encrypted_value=ct, value=r_masked or "REDACTED")
                )
                migrated_count += 1
            except Exception as e:
                # Strictly fail-closed: Never accept partial unencrypted state
                raise RuntimeError(
                    f"CRITICAL: PII migration failed closed on record {r_id} ({r_type}): {e}. "
                    "Rolling back transaction to prevent data exposure."
                ) from e

    print(f"PII Migration: Successfully verified and encrypted {migrated_count} legacy records.")


def downgrade():
    op.drop_table("threat_enrichment_jobs")
    with op.batch_alter_table("threat_observables") as batch_op:
        batch_op.drop_index("ix_threat_observables_tenant_fingerprint")
