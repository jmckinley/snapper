"""Enrich MCP catalog with trust tier, auth, popularity, and sync state.

Revision ID: 20260221_600000
Revises: 20260221_500000
Create Date: 2026-02-21
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "20260221_600000"
down_revision = "20260221_500000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add new columns to mcp_server_catalog
    op.add_column("mcp_server_catalog", sa.Column("trust_tier", sa.String(20), server_default="unknown", nullable=False))
    op.add_column("mcp_server_catalog", sa.Column("security_metadata", JSONB, server_default="{}", nullable=False))
    op.add_column("mcp_server_catalog", sa.Column("auth_type", sa.String(50), nullable=True))
    op.add_column("mcp_server_catalog", sa.Column("popularity_score", sa.Integer(), server_default="0", nullable=False))
    op.add_column("mcp_server_catalog", sa.Column("tools_count", sa.Integer(), server_default="0", nullable=False))
    op.add_column("mcp_server_catalog", sa.Column("categories", JSONB, server_default="[]", nullable=False))
    op.add_column("mcp_server_catalog", sa.Column("is_official", sa.Boolean(), server_default="false", nullable=False))
    op.add_column("mcp_server_catalog", sa.Column("pulsemcp_id", sa.String(255), nullable=True))
    op.add_column("mcp_server_catalog", sa.Column("glama_id", sa.String(255), nullable=True))

    op.create_index("ix_mcp_catalog_trust_tier", "mcp_server_catalog", ["trust_tier"])
    op.create_index("ix_mcp_catalog_popularity", "mcp_server_catalog", [sa.text("popularity_score DESC")])

    # Create sync state table
    op.create_table(
        "mcp_catalog_sync_state",
        sa.Column("source", sa.String(50), primary_key=True),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_cursor", sa.String(500), nullable=True),
        sa.Column("entries_count", sa.Integer(), server_default="0", nullable=False),
    )


def downgrade() -> None:
    op.drop_table("mcp_catalog_sync_state")
    op.drop_index("ix_mcp_catalog_popularity", table_name="mcp_server_catalog")
    op.drop_index("ix_mcp_catalog_trust_tier", table_name="mcp_server_catalog")
    op.drop_column("mcp_server_catalog", "glama_id")
    op.drop_column("mcp_server_catalog", "pulsemcp_id")
    op.drop_column("mcp_server_catalog", "is_official")
    op.drop_column("mcp_server_catalog", "categories")
    op.drop_column("mcp_server_catalog", "tools_count")
    op.drop_column("mcp_server_catalog", "popularity_score")
    op.drop_column("mcp_server_catalog", "auth_type")
    op.drop_column("mcp_server_catalog", "security_metadata")
    op.drop_column("mcp_server_catalog", "trust_tier")
