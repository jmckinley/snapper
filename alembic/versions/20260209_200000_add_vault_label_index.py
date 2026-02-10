"""Add composite index for vault label lookups.

Enables fast case-insensitive label lookups scoped by owner_chat_id.
Used by vault:Label references (e.g., vault:My Visa).

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-02-09 20:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "e5f6a7b8c9d0"
down_revision: Union[str, None] = "d4e5f6a7b8c9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "CREATE INDEX ix_vault_owner_label ON pii_vault_entries (owner_chat_id, lower(label))"
    )


def downgrade() -> None:
    op.drop_index("ix_vault_owner_label", table_name="pii_vault_entries")
