"""add tiore threat intelligence tables

Revision ID: d3e819fa2b41
Revises: c2d91b4a0f8e
Create Date: 2026-11-22 00:05:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'd3e819fa2b41'
down_revision: Union[str, None] = 'c2d91b4a0f8e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. threat_observables
    op.create_table(
        'threat_observables',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('type', sa.String(length=32), nullable=False),
        sa.Column('value', sa.String(length=2048), nullable=False),
        sa.Column('raw_masked', sa.String(length=2048), nullable=False),
        sa.Column('fingerprint', sa.String(length=64), unique=True, nullable=False),
        sa.Column('validation_status', sa.String(length=32), nullable=False, server_default='valid'),
        sa.Column('privacy_classification', sa.String(length=32), nullable=False, server_default='public_routable'),
        sa.Column('is_eligible_for_external_lookup', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_threat_observables_type', 'threat_observables', ['type'])
    op.create_index('ix_threat_observables_value', 'threat_observables', ['value'])
    op.create_index('ix_threat_observables_fingerprint', 'threat_observables', ['fingerprint'])

    # 2. threat_sources
    op.create_table(
        'threat_sources',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('category', sa.String(length=64), nullable=False),
        sa.Column('reliability_tier', sa.Integer(), nullable=False, server_default='3'),
        sa.Column('is_enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('supported_types', sa.JSON(), nullable=True),
        sa.Column('rate_limit_state', sa.JSON(), nullable=True),
        sa.Column('last_sync', sa.DateTime(timezone=True), nullable=True),
        sa.Column('health_status', sa.String(length=32), nullable=False, server_default='healthy'),
    )

    # 3. threat_records
    op.create_table(
        'threat_records',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('observable_id', sa.String(length=36), sa.ForeignKey('threat_observables.id', ondelete='CASCADE'), nullable=False),
        sa.Column('source_id', sa.String(length=64), sa.ForeignKey('threat_sources.id', ondelete='CASCADE'), nullable=False),
        sa.Column('classification', sa.String(length=32), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('threat_types', sa.JSON(), nullable=True),
        sa.Column('evidence', sa.JSON(), nullable=True),
        sa.Column('raw_payload', sa.JSON(), nullable=True),
        sa.Column('first_reported', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_reported', sa.DateTime(timezone=True), nullable=True),
        sa.Column('retrieved_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_threat_records_observable_id', 'threat_records', ['observable_id'])
    op.create_index('ix_threat_records_source_id', 'threat_records', ['source_id'])
    op.create_index('ix_threat_records_classification', 'threat_records', ['classification'])

    # 4. event_observables
    op.create_table(
        'event_observables',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('event_id', sa.String(), sa.ForeignKey('log_events.id', ondelete='CASCADE'), nullable=False),
        sa.Column('observable_id', sa.String(length=36), sa.ForeignKey('threat_observables.id', ondelete='CASCADE'), nullable=False),
        sa.Column('field_name', sa.String(length=64), nullable=False),
        sa.Column('tenant_id', sa.String(length=64), nullable=False, server_default='default'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_event_observables_event_id', 'event_observables', ['event_id'])
    op.create_index('ix_event_observables_observable_id', 'event_observables', ['observable_id'])
    op.create_index('ix_event_observables_tenant_id', 'event_observables', ['tenant_id'])

    # 5. threat_matches
    op.create_table(
        'threat_matches',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('observable_id', sa.String(length=36), sa.ForeignKey('threat_observables.id', ondelete='CASCADE'), nullable=False),
        sa.Column('event_id', sa.String(), sa.ForeignKey('log_events.id', ondelete='SET NULL'), nullable=True),
        sa.Column('alert_id', sa.String(), sa.ForeignKey('alerts.id', ondelete='SET NULL'), nullable=True),
        sa.Column('incident_id', sa.String(), sa.ForeignKey('incidents.id', ondelete='SET NULL'), nullable=True),
        sa.Column('classification', sa.String(length=32), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('verdict_reason', sa.String(length=512), nullable=False),
        sa.Column('tenant_id', sa.String(length=64), nullable=False, server_default='default'),
        sa.Column('review_status', sa.String(length=32), nullable=False, server_default='unreviewed'),
        sa.Column('reviewed_by', sa.String(length=64), nullable=True),
        sa.Column('analyst_notes', sa.Text(), nullable=True),
        sa.Column('matched_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_threat_matches_observable_id', 'threat_matches', ['observable_id'])
    op.create_index('ix_threat_matches_tenant_id', 'threat_matches', ['tenant_id'])
    op.create_index('ix_threat_matches_classification', 'threat_matches', ['classification'])

    # 6. threat_intel_audits
    op.create_table(
        'threat_intel_audits',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('actor_id', sa.String(length=64), nullable=False),
        sa.Column('actor_username', sa.String(length=64), nullable=False),
        sa.Column('actor_role', sa.String(length=32), nullable=False),
        sa.Column('tenant_id', sa.String(length=64), nullable=False, server_default='default'),
        sa.Column('observable_type', sa.String(length=32), nullable=False),
        sa.Column('masked_value', sa.String(length=255), nullable=False),
        sa.Column('fingerprint', sa.String(length=64), nullable=False),
        sa.Column('lookup_method', sa.String(length=32), nullable=False),
        sa.Column('external_disclosed', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('disclosed_to', sa.JSON(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_threat_intel_audits_tenant_id', 'threat_intel_audits', ['tenant_id'])
    op.create_index('ix_threat_intel_audits_fingerprint', 'threat_intel_audits', ['fingerprint'])


def downgrade() -> None:
    op.drop_table('threat_intel_audits')
    op.drop_table('threat_matches')
    op.drop_table('event_observables')
    op.drop_table('threat_records')
    op.drop_table('threat_sources')
    op.drop_table('threat_observables')
