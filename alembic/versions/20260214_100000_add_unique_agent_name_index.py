"""Add partial unique index on agent name for active agents.

Prevents duplicate agent names among non-deleted agents.

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-02-14 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f6a7b8c9d0e1"
down_revision: Union[str, None] = "e5f6a7b8c9d0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_agents_name_active "
        "ON agents (name) WHERE is_deleted = false"
    )


def downgrade() -> None:
    op.drop_index("uq_agents_name_active", table_name="agents")
