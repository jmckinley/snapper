"""Add API key and learning mode fields

Revision ID: 7ce34501cc0e
Revises: 08ffce791cd8
Create Date: 2026-02-06 14:58:26.537054

"""
import secrets
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7ce34501cc0e'
down_revision: Union[str, None] = '08ffce791cd8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def generate_api_key() -> str:
    """Generate a secure API key with snp_ prefix."""
    return f"snp_{secrets.token_urlsafe(32)}"


def upgrade() -> None:
    # Add api_key column as nullable first
    op.add_column('agents', sa.Column('api_key', sa.String(length=64), nullable=True, comment='API key for agent authentication (snp_...)'))
    op.add_column('agents', sa.Column('api_key_last_used', sa.DateTime(timezone=True), nullable=True, comment='Last time the API key was used'))

    # Generate API keys for existing agents
    connection = op.get_bind()
    agents = connection.execute(sa.text("SELECT id FROM agents WHERE api_key IS NULL"))
    for agent in agents:
        api_key = generate_api_key()
        connection.execute(
            sa.text("UPDATE agents SET api_key = :api_key WHERE id = :id"),
            {"api_key": api_key, "id": agent.id}
        )

    # Now make api_key non-nullable and add unique index
    op.alter_column('agents', 'api_key', nullable=False)
    op.create_index(op.f('ix_agents_api_key'), 'agents', ['api_key'], unique=True)


def downgrade() -> None:
    op.drop_index(op.f('ix_agents_api_key'), table_name='agents')
    op.drop_column('agents', 'api_key_last_used')
    op.drop_column('agents', 'api_key')
