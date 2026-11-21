"""add tenant_id to alerts

Revision ID: 6bff75e56a4e
Revises: 14aed272f8ba
Create Date: 2026-11-21 11:01:30.655671

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '6bff75e56a4e'
down_revision: Union[str, None] = '14aed272f8ba'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    try:
        op.add_column(
            "alerts",
            sa.Column(
                "tenant_id",
                sa.String(length=64),
                server_default="default",
                nullable=True,
            ),
        )
    except Exception:
        pass

    for col, col_type in [
        ("user", sa.String(length=128)),
        ("event_id", sa.String(length=64)),
        ("action", sa.String(length=128)),
        ("tenant_id", sa.String(length=64)),
    ]:
        try:
            op.add_column("log_events", sa.Column(col, col_type, nullable=True))
        except Exception:
            pass


def downgrade() -> None:
    try:
        op.drop_column("alerts", "tenant_id")
    except Exception:
        pass
    for col in ["user", "event_id", "action", "tenant_id"]:
        try:
            op.drop_column("log_events", col)
        except Exception:
            pass
