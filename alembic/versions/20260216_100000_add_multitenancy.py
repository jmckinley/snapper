"""Add multi-tenancy: organizations, teams, memberships, invitations, plans.

Adds organization_id columns to agents, rules, pii_vault_entries, audit_logs, users.
Seeds free/pro/enterprise plans.

Revision ID: aa16bb27cc38
Revises: f6a7b8c9d0e1
Create Date: 2026-02-16 10:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "aa16bb27cc38"
down_revision: Union[str, None] = "f6a7b8c9d0e1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- Plans table ---
    op.create_table(
        "plans",
        sa.Column("id", sa.String(50), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("stripe_price_id_monthly", sa.String(255), nullable=True),
        sa.Column("stripe_price_id_yearly", sa.String(255), nullable=True),
        sa.Column("max_agents", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("max_rules", sa.Integer(), nullable=False, server_default="10"),
        sa.Column("max_vault_entries", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("max_team_members", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("max_teams", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("features", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("price_monthly_cents", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("price_yearly_cents", sa.Integer(), nullable=False, server_default="0"),
    )

    # Seed plans
    op.execute("""
        INSERT INTO plans (id, name, max_agents, max_rules, max_vault_entries, max_team_members, max_teams, features, price_monthly_cents, price_yearly_cents)
        VALUES
            ('free', 'Free', 25, 250, 50, 5, 2, '{"slack_integration": true, "oauth_login": false, "sso": false, "audit_export": false}', 0, 0),
            ('pro', 'Pro', 10, 100, 50, 5, 3, '{"slack_integration": true, "oauth_login": true, "sso": false, "audit_export": true}', 2900, 29000),
            ('enterprise', 'Enterprise', -1, -1, -1, -1, -1, '{"slack_integration": true, "oauth_login": true, "sso": true, "audit_export": true}', 9900, 99000)
        ON CONFLICT (id) DO NOTHING
    """)

    # --- Organizations table ---
    op.create_table(
        "organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), unique=True, nullable=False),
        sa.Column("plan_id", sa.String(50), sa.ForeignKey("plans.id"), nullable=False, server_default="free"),
        sa.Column("stripe_customer_id", sa.String(255), nullable=True, unique=True),
        sa.Column("stripe_subscription_id", sa.String(255), nullable=True),
        sa.Column("subscription_status", sa.String(50), nullable=True),
        sa.Column("plan_period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("feature_overrides", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("settings", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_organizations_slug", "organizations", ["slug"])
    op.create_index("ix_organizations_active", "organizations", ["is_active", "deleted_at"])

    # --- Teams table ---
    op.create_table(
        "teams",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False),
        sa.Column("is_default", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("organization_id", "slug", name="uq_teams_org_slug"),
    )
    op.create_index("ix_teams_organization_id", "teams", ["organization_id"])

    # --- Organization Memberships table ---
    op.create_table(
        "organization_memberships",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", sa.String(20), nullable=False, server_default="member"),
        sa.Column("invited_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("invited_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("user_id", "organization_id", name="uq_membership_user_org"),
    )
    op.create_index("ix_memberships_user_id", "organization_memberships", ["user_id"])
    op.create_index("ix_memberships_org_id", "organization_memberships", ["organization_id"])

    # --- Invitations table ---
    op.create_table(
        "invitations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("role", sa.String(20), nullable=False, server_default="member"),
        sa.Column("token", sa.String(100), unique=True, nullable=False),
        sa.Column("invited_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_invitations_org_id", "invitations", ["organization_id"])
    op.create_index("ix_invitations_email", "invitations", ["email"])
    op.create_index("ix_invitations_pending", "invitations", ["status", "expires_at"])

    # --- Add organization_id to existing tables ---

    # Agents
    op.add_column("agents", sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("agents", sa.Column("team_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key("fk_agents_organization", "agents", "organizations", ["organization_id"], ["id"], ondelete="SET NULL")
    op.create_foreign_key("fk_agents_team", "agents", "teams", ["team_id"], ["id"], ondelete="SET NULL")
    op.create_index("ix_agents_organization_id", "agents", ["organization_id"])
    op.create_index("ix_agents_team_id", "agents", ["team_id"])

    # Rules
    op.add_column("rules", sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key("fk_rules_organization", "rules", "organizations", ["organization_id"], ["id"], ondelete="SET NULL")
    op.create_index("ix_rules_organization_id", "rules", ["organization_id"])

    # PII Vault Entries
    op.add_column("pii_vault_entries", sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key("fk_vault_organization", "pii_vault_entries", "organizations", ["organization_id"], ["id"], ondelete="SET NULL")
    op.create_index("ix_vault_organization_id", "pii_vault_entries", ["organization_id"])

    # Audit Logs
    op.add_column("audit_logs", sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key("fk_audit_organization", "audit_logs", "organizations", ["organization_id"], ["id"], ondelete="SET NULL")
    op.create_index("ix_audit_organization_id", "audit_logs", ["organization_id"])

    # Users - new columns
    op.add_column("users", sa.Column("default_organization_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("users", sa.Column("oauth_provider", sa.String(50), nullable=True))
    op.add_column("users", sa.Column("oauth_provider_id", sa.String(255), nullable=True))
    op.add_column("users", sa.Column("email_verification_token", sa.String(255), nullable=True))
    op.add_column("users", sa.Column("password_reset_token", sa.String(255), nullable=True))
    op.add_column("users", sa.Column("password_reset_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.create_foreign_key("fk_users_default_org", "users", "organizations", ["default_organization_id"], ["id"], ondelete="SET NULL")
    op.create_index("ix_users_default_org", "users", ["default_organization_id"])
    op.create_index("ix_users_oauth", "users", ["oauth_provider", "oauth_provider_id"])


def downgrade() -> None:
    # Users - remove new columns
    op.drop_index("ix_users_oauth", table_name="users")
    op.drop_index("ix_users_default_org", table_name="users")
    op.drop_constraint("fk_users_default_org", "users", type_="foreignkey")
    op.drop_column("users", "password_reset_expires_at")
    op.drop_column("users", "password_reset_token")
    op.drop_column("users", "email_verification_token")
    op.drop_column("users", "oauth_provider_id")
    op.drop_column("users", "oauth_provider")
    op.drop_column("users", "default_organization_id")

    # Audit Logs
    op.drop_index("ix_audit_organization_id", table_name="audit_logs")
    op.drop_constraint("fk_audit_organization", "audit_logs", type_="foreignkey")
    op.drop_column("audit_logs", "organization_id")

    # PII Vault
    op.drop_index("ix_vault_organization_id", table_name="pii_vault_entries")
    op.drop_constraint("fk_vault_organization", "pii_vault_entries", type_="foreignkey")
    op.drop_column("pii_vault_entries", "organization_id")

    # Rules
    op.drop_index("ix_rules_organization_id", table_name="rules")
    op.drop_constraint("fk_rules_organization", "rules", type_="foreignkey")
    op.drop_column("rules", "organization_id")

    # Agents
    op.drop_index("ix_agents_team_id", table_name="agents")
    op.drop_index("ix_agents_organization_id", table_name="agents")
    op.drop_constraint("fk_agents_team", "agents", type_="foreignkey")
    op.drop_constraint("fk_agents_organization", "agents", type_="foreignkey")
    op.drop_column("agents", "team_id")
    op.drop_column("agents", "organization_id")

    # Drop tables (reverse order)
    op.drop_table("invitations")
    op.drop_table("organization_memberships")
    op.drop_table("teams")
    op.drop_table("organizations")
    op.drop_table("plans")
