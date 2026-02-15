"""Migrate existing data to default organization.

Creates a "Default Organization" on enterprise plan and assigns all
orphaned agents, rules, vault entries, and audit logs to it.

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-02-16 10:00:01.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b2c3d4e5f6a7"
down_revision: Union[str, None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()

    # Check if there are any agents without an organization
    result = conn.execute(
        sa.text("SELECT COUNT(*) FROM agents WHERE organization_id IS NULL AND is_deleted = false")
    )
    orphan_count = result.scalar()

    if orphan_count == 0:
        return  # Nothing to migrate

    # Create the default organization (enterprise plan = no limits)
    org_id = conn.execute(
        sa.text("""
            INSERT INTO organizations (name, slug, plan_id, is_active)
            VALUES ('Default Organization', 'default', 'enterprise', true)
            RETURNING id
        """)
    ).scalar()

    # Create default team
    conn.execute(
        sa.text("""
            INSERT INTO teams (organization_id, name, slug, is_default)
            VALUES (:org_id, 'Default Team', 'default', true)
        """),
        {"org_id": org_id},
    )

    # Assign orphaned agents
    conn.execute(
        sa.text("UPDATE agents SET organization_id = :org_id WHERE organization_id IS NULL"),
        {"org_id": org_id},
    )

    # Assign orphaned rules
    conn.execute(
        sa.text("UPDATE rules SET organization_id = :org_id WHERE organization_id IS NULL"),
        {"org_id": org_id},
    )

    # Assign orphaned vault entries
    conn.execute(
        sa.text("UPDATE pii_vault_entries SET organization_id = :org_id WHERE organization_id IS NULL"),
        {"org_id": org_id},
    )

    # Assign orphaned audit logs
    conn.execute(
        sa.text("UPDATE audit_logs SET organization_id = :org_id WHERE organization_id IS NULL"),
        {"org_id": org_id},
    )


def downgrade() -> None:
    conn = op.get_bind()

    # Clear organization_id from all entities that point to the default org
    result = conn.execute(
        sa.text("SELECT id FROM organizations WHERE slug = 'default' LIMIT 1")
    )
    row = result.fetchone()
    if not row:
        return

    org_id = row[0]

    conn.execute(sa.text("UPDATE agents SET organization_id = NULL WHERE organization_id = :org_id"), {"org_id": org_id})
    conn.execute(sa.text("UPDATE rules SET organization_id = NULL WHERE organization_id = :org_id"), {"org_id": org_id})
    conn.execute(sa.text("UPDATE pii_vault_entries SET organization_id = NULL WHERE organization_id = :org_id"), {"org_id": org_id})
    conn.execute(sa.text("UPDATE audit_logs SET organization_id = NULL WHERE organization_id = :org_id"), {"org_id": org_id})

    # Delete default team and org
    conn.execute(sa.text("DELETE FROM teams WHERE organization_id = :org_id"), {"org_id": org_id})
    conn.execute(sa.text("DELETE FROM organizations WHERE id = :org_id"), {"org_id": org_id})
