"""add pii encryption and tenant isolation to threat_observables

Revision ID: e4f912bc7810
Revises: d3e819fa2b41
Create Date: 2026-11-22 01:50:00.000000

"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "e4f912bc7810"
down_revision = "d3e819fa2b41"
branch_labels = None
depends_on = None


def upgrade():
    # Add tenant_id, is_shared, and encrypted_value to threat_observables
    with op.batch_alter_table("threat_observables") as batch_op:
        batch_op.add_column(sa.Column("tenant_id", sa.String(64), nullable=True))
        batch_op.add_column(
            sa.Column("is_shared", sa.Boolean(), nullable=False, server_default=sa.text("0"))
        )
        batch_op.add_column(sa.Column("encrypted_value", sa.Text(), nullable=True))
        batch_op.create_index("ix_threat_observables_tenant_id", ["tenant_id"])
        batch_op.create_index("ix_threat_observables_is_shared", ["is_shared"])


def downgrade():
    with op.batch_alter_table("threat_observables") as batch_op:
        batch_op.drop_index("ix_threat_observables_is_shared")
        batch_op.drop_index("ix_threat_observables_tenant_id")
        batch_op.drop_column("encrypted_value")
        batch_op.drop_column("is_shared")
        batch_op.drop_column("tenant_id")
