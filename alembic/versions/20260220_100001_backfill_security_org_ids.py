"""Backfill organization_id on existing policy_violations, alerts, security_recommendations.

Revision ID: ff61bb83cc94
Revises: ff61aa72bb83
Create Date: 2026-02-20 10:00:01.000000

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "ff61bb83cc94"
down_revision: Union[str, None] = "ff61aa72bb83"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Backfill organization_id from the associated agent
    op.execute("""
        UPDATE policy_violations pv
        SET organization_id = a.organization_id
        FROM agents a
        WHERE pv.agent_id = a.id
          AND pv.organization_id IS NULL
          AND a.organization_id IS NOT NULL
    """)

    op.execute("""
        UPDATE alerts al
        SET organization_id = a.organization_id
        FROM agents a
        WHERE al.agent_id = a.id
          AND al.organization_id IS NULL
          AND a.organization_id IS NOT NULL
    """)

    op.execute("""
        UPDATE security_recommendations sr
        SET organization_id = a.organization_id
        FROM agents a
        WHERE sr.agent_id = a.id
          AND sr.organization_id IS NULL
          AND a.organization_id IS NOT NULL
    """)


def downgrade() -> None:
    # Cannot reliably undo a backfill — just leave the data as-is
    pass
