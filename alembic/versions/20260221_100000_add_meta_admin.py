"""Add meta admin fields.

Revision ID: gg72hh83ii94
Revises: ff61cc94dd05
Create Date: 2026-02-21 10:00:00.000000+00:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "gg72hh83ii94"
down_revision = "ff61cc94dd05"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # User: is_meta_admin
    op.add_column(
        "users",
        sa.Column(
            "is_meta_admin",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
    )
    op.create_index(
        "ix_users_meta_admin",
        "users",
        ["is_meta_admin"],
        postgresql_where=sa.text("is_meta_admin = true"),
    )

    # Organization: allowed_email_domains, max_seats
    op.add_column(
        "organizations",
        sa.Column(
            "allowed_email_domains",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
    )
    op.add_column(
        "organizations",
        sa.Column("max_seats", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("organizations", "max_seats")
    op.drop_column("organizations", "allowed_email_domains")
    op.drop_index("ix_users_meta_admin", table_name="users")
    op.drop_column("users", "is_meta_admin")
