"""Add owner_chat_id to agents table for per-user notifications.

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-02-07 10:00:01.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "c3d4e5f6a7b8"
down_revision: Union[str, None] = "b2c3d4e5f6a7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "agents",
        sa.Column(
            "owner_chat_id",
            sa.String(100),
            nullable=True,
            comment="Telegram chat ID of the agent owner for per-user notifications",
        ),
    )
    op.create_index("ix_agents_owner_chat_id", "agents", ["owner_chat_id"])


def downgrade() -> None:
    op.drop_index("ix_agents_owner_chat_id", table_name="agents")
    op.drop_column("agents", "owner_chat_id")
