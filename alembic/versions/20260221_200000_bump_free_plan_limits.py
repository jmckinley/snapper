"""Bump free plan limits for pilots + add per-org quota overrides.

Free plan was too restrictive (1 agent, 10 rules) for pilot customers.
Increase limits so pilots can meaningfully evaluate the product.
Add per-org override columns so meta admin can customize limits per customer.

Revision ID: hh83ii94jj05
Revises: gg72hh83ii94
Create Date: 2026-02-21 20:00:00.000000+00:00
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "hh83ii94jj05"
down_revision = "gg72hh83ii94"
branch_labels = None
depends_on = None


def upgrade():
    # Bump free plan limits for pilots
    op.execute("""
        UPDATE plans SET
            max_agents = 25,
            max_rules = 250,
            max_vault_entries = 50,
            max_team_members = 5,
            max_teams = 2,
            features = '{"slack_integration": true, "oauth_login": false, "sso": false, "audit_export": false}'
        WHERE id = 'free'
    """)

    # Add per-org quota override columns (meta admin can set per customer)
    op.add_column(
        "organizations",
        sa.Column(
            "max_agents_override",
            sa.Integer(),
            nullable=True,
            comment="Override plan max_agents. NULL = use plan default.",
        ),
    )
    op.add_column(
        "organizations",
        sa.Column(
            "max_rules_override",
            sa.Integer(),
            nullable=True,
            comment="Override plan max_rules. NULL = use plan default.",
        ),
    )
    op.add_column(
        "organizations",
        sa.Column(
            "max_vault_entries_override",
            sa.Integer(),
            nullable=True,
            comment="Override plan max_vault_entries. NULL = use plan default.",
        ),
    )


def downgrade():
    op.drop_column("organizations", "max_vault_entries_override")
    op.drop_column("organizations", "max_rules_override")
    op.drop_column("organizations", "max_agents_override")

    op.execute("""
        UPDATE plans SET
            max_agents = 1,
            max_rules = 10,
            max_vault_entries = 5,
            max_team_members = 1,
            max_teams = 1,
            features = '{"slack_integration": false, "oauth_login": false, "sso": false, "audit_export": false}'
        WHERE id = 'free'
    """)
