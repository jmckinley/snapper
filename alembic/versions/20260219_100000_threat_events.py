"""Add threat_events table for heuristic-based threat detection.

Revision ID: ee50ff61aa72
Revises: dd49ee50ff61
Create Date: 2026-02-19 10:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "ee50ff61aa72"
down_revision: Union[str, None] = "dd49ee50ff61"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "threat_events",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "agent_id",
            UUID(as_uuid=True),
            sa.ForeignKey("agents.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "organization_id",
            UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="SET NULL"),
            nullable=True,
            index=True,
        ),
        sa.Column("threat_type", sa.String(50), nullable=False, index=True),
        sa.Column("severity", sa.String(20), nullable=False, index=True),
        sa.Column("threat_score", sa.Float, nullable=False, default=0.0),
        sa.Column("kill_chain", sa.String(100), nullable=True),
        sa.Column("signals", JSONB, nullable=False, server_default="[]"),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("details", JSONB, nullable=False, server_default="{}"),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", UUID(as_uuid=True), nullable=True),
        sa.Column("resolution_notes", sa.Text, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
            index=True,
        ),
    )

    op.create_index(
        "ix_threat_events_agent_status",
        "threat_events",
        ["agent_id", "status"],
    )
    op.create_index(
        "ix_threat_events_severity_time",
        "threat_events",
        ["severity", "created_at"],
    )
    op.create_index(
        "ix_threat_events_type",
        "threat_events",
        ["threat_type"],
    )


def downgrade() -> None:
    op.drop_table("threat_events")
