"""Add organization_id to policy_violations, alerts, security_recommendations.

Revision ID: ff61aa72bb83
Revises: ee50ff61aa72
Create Date: 2026-02-20 10:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "ff61aa72bb83"
down_revision: Union[str, None] = "ee50ff61aa72"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # policy_violations
    op.add_column(
        "policy_violations",
        sa.Column("organization_id", UUID(as_uuid=True), nullable=True),
    )
    op.create_index(
        "ix_policy_violations_organization_id",
        "policy_violations",
        ["organization_id"],
    )
    op.create_foreign_key(
        "fk_policy_violations_org",
        "policy_violations",
        "organizations",
        ["organization_id"],
        ["id"],
        ondelete="SET NULL",
    )

    # alerts
    op.add_column(
        "alerts",
        sa.Column("organization_id", UUID(as_uuid=True), nullable=True),
    )
    op.create_index(
        "ix_alerts_organization_id",
        "alerts",
        ["organization_id"],
    )
    op.create_foreign_key(
        "fk_alerts_org",
        "alerts",
        "organizations",
        ["organization_id"],
        ["id"],
        ondelete="SET NULL",
    )

    # security_recommendations
    op.add_column(
        "security_recommendations",
        sa.Column("organization_id", UUID(as_uuid=True), nullable=True),
    )
    op.create_index(
        "ix_security_recommendations_organization_id",
        "security_recommendations",
        ["organization_id"],
    )
    op.create_foreign_key(
        "fk_security_recommendations_org",
        "security_recommendations",
        "organizations",
        ["organization_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_security_recommendations_org", "security_recommendations", type_="foreignkey")
    op.drop_index("ix_security_recommendations_organization_id", "security_recommendations")
    op.drop_column("security_recommendations", "organization_id")

    op.drop_constraint("fk_alerts_org", "alerts", type_="foreignkey")
    op.drop_index("ix_alerts_organization_id", "alerts")
    op.drop_column("alerts", "organization_id")

    op.drop_constraint("fk_policy_violations_org", "policy_violations", type_="foreignkey")
    op.drop_index("ix_policy_violations_organization_id", "policy_violations")
    op.drop_column("policy_violations", "organization_id")
