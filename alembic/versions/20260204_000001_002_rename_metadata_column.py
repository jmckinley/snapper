"""Rename metadata column to agent_metadata

Revision ID: 002
Revises: 001
Create Date: 2026-02-04 00:00:01

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = '002'
down_revision: Union[str, None] = '001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Rename the column from 'metadata' to 'agent_metadata' to avoid
    # conflict with SQLAlchemy Base.metadata
    op.alter_column('agents', 'metadata', new_column_name='agent_metadata')


def downgrade() -> None:
    op.alter_column('agents', 'agent_metadata', new_column_name='metadata')
