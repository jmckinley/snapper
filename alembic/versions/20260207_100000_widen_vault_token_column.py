"""Widen vault token column for 128-bit entropy tokens.

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-02-07 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "b2c3d4e5f6a7"
down_revision: Union[str, None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Widen token column from String(30) to String(52) to accommodate
    # new 128-bit tokens: {{SNAPPER_VAULT:<32-hex>}} = 49 chars
    # Old 32-bit tokens (8 hex chars) still fit fine
    op.alter_column(
        "pii_vault_entries",
        "token",
        existing_type=sa.String(30),
        type_=sa.String(52),
        existing_nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "pii_vault_entries",
        "token",
        existing_type=sa.String(52),
        type_=sa.String(30),
        existing_nullable=False,
    )
