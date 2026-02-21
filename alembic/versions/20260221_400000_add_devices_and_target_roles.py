"""Add devices table and target_roles column to rules.

Revision ID: jj05kk16ll27
Revises: ii94jj05kk16
Create Date: 2026-02-21 04:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "jj05kk16ll27"
down_revision: Union[str, None] = "ii94jj05kk16"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create devices table
    op.create_table(
        "devices",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("device_id", sa.String(36), unique=True, nullable=False, index=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
            index=True,
        ),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="SET NULL"),
            nullable=True,
            index=True,
        ),
        sa.Column("name", sa.String(255), nullable=True),
        sa.Column("platform", sa.String(100), nullable=True),
        sa.Column("browser", sa.String(200), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("metadata", postgresql.JSONB, nullable=True),
    )

    op.create_index("ix_devices_user_org", "devices", ["user_id", "organization_id"])

    # Add target_roles to rules table
    op.add_column(
        "rules",
        sa.Column(
            "target_roles",
            postgresql.JSONB,
            nullable=True,
            comment="If set, rule only applies to users with these roles. Null = all users.",
        ),
    )


def downgrade() -> None:
    op.drop_column("rules", "target_roles")
    op.drop_index("ix_devices_user_org", table_name="devices")
    op.drop_table("devices")
