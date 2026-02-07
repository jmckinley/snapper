"""Add PII vault entries table.

Revision ID: a1b2c3d4e5f6
Revises: 7ce34501cc0e
Create Date: 2026-02-06 20:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, None] = "7ce34501cc0e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "pii_vault_entries",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("owner_chat_id", sa.String(100), nullable=False, comment="Telegram chat ID of the PII owner"),
        sa.Column("owner_name", sa.String(255), nullable=True, comment="Display name of the PII owner"),
        sa.Column(
            "agent_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("agents.id", ondelete="SET NULL"),
            nullable=True,
            comment="Agent this entry is restricted to, null for any agent",
        ),
        sa.Column("label", sa.String(255), nullable=False, comment="Human-readable label"),
        sa.Column("category", sa.String(50), nullable=False),
        sa.Column("token", sa.String(30), nullable=False, unique=True, comment="Vault reference token"),
        sa.Column("encrypted_value", sa.LargeBinary(), nullable=False, comment="Fernet-encrypted PII value"),
        sa.Column("masked_value", sa.String(255), nullable=False, comment="Masked display value"),
        sa.Column(
            "allowed_domains",
            postgresql.JSONB(),
            nullable=True,
            server_default="[]",
            comment="Domains where this PII can be submitted",
        ),
        sa.Column("max_uses", sa.Integer(), nullable=True, comment="Maximum uses (null = unlimited)"),
        sa.Column("use_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_domain", sa.String(255), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True, comment="Entry expiration time"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("is_deleted", sa.Boolean(), nullable=False, server_default="false"),
        sa.PrimaryKeyConstraint("id"),
    )

    # Indexes
    op.create_index("ix_pii_vault_entries_owner_chat_id", "pii_vault_entries", ["owner_chat_id"])
    op.create_index("ix_pii_vault_entries_agent_id", "pii_vault_entries", ["agent_id"])
    op.create_index("ix_pii_vault_entries_category", "pii_vault_entries", ["category"])
    op.create_index("ix_pii_vault_entries_token", "pii_vault_entries", ["token"], unique=True)
    op.create_index("ix_vault_owner_category", "pii_vault_entries", ["owner_chat_id", "category"])
    op.create_index("ix_vault_active", "pii_vault_entries", ["is_deleted", "owner_chat_id"])


def downgrade() -> None:
    op.drop_index("ix_vault_active", table_name="pii_vault_entries")
    op.drop_index("ix_vault_owner_category", table_name="pii_vault_entries")
    op.drop_index("ix_pii_vault_entries_token", table_name="pii_vault_entries")
    op.drop_index("ix_pii_vault_entries_category", table_name="pii_vault_entries")
    op.drop_index("ix_pii_vault_entries_agent_id", table_name="pii_vault_entries")
    op.drop_index("ix_pii_vault_entries_owner_chat_id", table_name="pii_vault_entries")
    op.drop_table("pii_vault_entries")
