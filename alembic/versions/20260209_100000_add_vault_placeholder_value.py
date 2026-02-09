"""Add placeholder_value column to pii_vault_entries.

Allows vault entries to have a safe dummy value (e.g., Stripe test card)
that agents can use in place of the vault token. When Snapper detects the
placeholder in tool input, it matches it to the vault entry for resolution.

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-02-09 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "d4e5f6a7b8c9"
down_revision: Union[str, None] = "c3d4e5f6a7b8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "pii_vault_entries",
        sa.Column(
            "placeholder_value",
            sa.String(255),
            nullable=True,
            comment="Safe dummy value agents use instead of vault token (e.g., Stripe test card 4242424242424242)",
        ),
    )
    op.create_index(
        "ix_vault_placeholder",
        "pii_vault_entries",
        ["placeholder_value", "is_deleted", "owner_chat_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_vault_placeholder", table_name="pii_vault_entries")
    op.drop_column("pii_vault_entries", "placeholder_value")
