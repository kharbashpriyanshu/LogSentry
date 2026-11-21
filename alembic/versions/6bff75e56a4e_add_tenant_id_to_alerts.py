"""add tenant_id to alerts

Revision ID: 6bff75e56a4e
Revises: 14aed272f8ba
Create Date: 2026-11-21 11:01:30.655671

"""
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '6bff75e56a4e'
down_revision: Union[str, None] = '14aed272f8ba'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add tenant isolation to alerts table
    op.add_column(
        "alerts",
        sa.Column(
            "tenant_id",
            sa.String(length=64),
            server_default="default",
            nullable=True,
        ),
    )

    # Add telemetry enrichment fields to log_events table
    op.add_column("log_events", sa.Column("user", sa.String(length=128), nullable=True))
    op.add_column("log_events", sa.Column("event_id", sa.String(length=64), nullable=True))
    op.add_column("log_events", sa.Column("action", sa.String(length=128), nullable=True))
    op.add_column("log_events", sa.Column("tenant_id", sa.String(length=64), server_default="default", nullable=True))


def downgrade() -> None:
    op.drop_column("alerts", "tenant_id")
    op.drop_column("log_events", "tenant_id")
    op.drop_column("log_events", "action")
    op.drop_column("log_events", "event_id")
    op.drop_column("log_events", "user")
