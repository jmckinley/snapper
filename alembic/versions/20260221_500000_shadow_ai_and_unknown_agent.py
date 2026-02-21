"""Add shadow_ai_detections and mcp_server_catalog tables.

Revision ID: kk16ll27mm38
Revises: jj05kk16ll27
Create Date: 2026-02-21 05:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "kk16ll27mm38"
down_revision: Union[str, None] = "jj05kk16ll27"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Shadow AI detections table
    op.create_table(
        "shadow_ai_detections",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("detection_type", sa.String(50), nullable=False, index=True),
        sa.Column("process_name", sa.String(255), nullable=True),
        sa.Column("pid", sa.Integer, nullable=True),
        sa.Column("command_line", sa.Text, nullable=True),
        sa.Column("destination", sa.String(500), nullable=True),
        sa.Column("container_id", sa.String(100), nullable=True),
        sa.Column("container_image", sa.String(500), nullable=True),
        sa.Column(
            "host_identifier",
            sa.String(255),
            nullable=False,
            index=True,
        ),
        sa.Column("details", postgresql.JSONB, default={}, nullable=True),
        sa.Column(
            "status",
            sa.String(20),
            nullable=False,
            server_default="active",
            index=True,
        ),
        sa.Column(
            "resolved_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.Column("occurrence_count", sa.Integer, nullable=False, server_default="1"),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="SET NULL"),
            nullable=True,
            index=True,
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
    )
    op.create_index(
        "ix_shadow_ai_host_type",
        "shadow_ai_detections",
        ["host_identifier", "detection_type"],
    )
    op.create_index(
        "ix_shadow_ai_status_time",
        "shadow_ai_detections",
        ["status", "last_seen_at"],
    )
    op.create_index(
        "ix_shadow_ai_org_status",
        "shadow_ai_detections",
        ["organization_id", "status"],
    )

    # MCP Server Catalog table
    op.create_table(
        "mcp_server_catalog",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column(
            "normalized_name",
            sa.String(255),
            unique=True,
            nullable=False,
            index=True,
        ),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("tools", postgresql.JSONB, default=[], nullable=True),
        sa.Column("repository", sa.String(500), nullable=True),
        sa.Column("homepage", sa.String(500), nullable=True),
        sa.Column("source", sa.String(50), nullable=False, index=True),
        sa.Column(
            "last_synced_at",
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
    )
    op.create_index(
        "ix_mcp_catalog_source_name",
        "mcp_server_catalog",
        ["source", "normalized_name"],
    )


def downgrade() -> None:
    op.drop_table("mcp_server_catalog")
    op.drop_table("shadow_ai_detections")
