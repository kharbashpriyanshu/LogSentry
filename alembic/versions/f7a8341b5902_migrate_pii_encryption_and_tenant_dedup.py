"""migrate pii encryption backfill, tenant dedup index, and durable enrichment jobs

Revision ID: f7a8341b5902
Revises: e4f912bc7810
Create Date: 2026-11-22 02:30:00.000000

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import table, column, select

from app.core.crypto import encrypt_pii, decrypt_pii

# revision identifiers, used by Alembic.
revision = "f7a8341b5902"
down_revision = "e4f912bc7810"
branch_labels = None
depends_on = None


def upgrade():
    # 1. Update threat_observables schema: add tenant composite index
    with op.batch_alter_table("threat_observables") as batch_op:
        batch_op.create_index(
            "ix_threat_observables_tenant_fingerprint",
            ["tenant_id", "fingerprint"],
        )

    # 2. Create durable persistent threat enrichment jobs queue table
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

    # 3. Data Migration: Backfill existing unencrypted PII records (Issue A)
    bind = op.get_bind()
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

    for row in rows:
        r_id, r_type, r_val, r_masked, r_enc = row
        # If unencrypted or containing raw plaintext
        if not r_enc or r_enc.strip() == "":
            try:
                ct = encrypt_pii(r_val)
                # Verify round-trip decryption
                assert decrypt_pii(ct) == r_val, "Decryption verification failed during migration"
                
                # Overwrite value with masked representation and populate encrypted_value
                bind.execute(
                    observables_tbl.update()
                    .where(observables_tbl.c.id == r_id)
                    .values(encrypted_value=ct, value=r_masked or "REDACTED")
                )
            except Exception as e:
                # Log error and ensure safe migration without data corruption
                print(f"Warning: could not encrypt existing PII record {r_id}: {e}")


def downgrade():
    op.drop_table("threat_enrichment_jobs")
    with op.batch_alter_table("threat_observables") as batch_op:
        batch_op.drop_index("ix_threat_observables_tenant_fingerprint")
