"""Add composite indexes on audit_logs for dashboard and rule engine queries.

Revision ID: ii94jj05kk16
Revises: hh83ii94jj05
Create Date: 2026-02-21 03:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "ii94jj05kk16"
down_revision: Union[str, None] = "hh83ii94jj05"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(
        "ix_audit_logs_org_action_time",
        "audit_logs",
        ["organization_id", "action", "created_at"],
        postgresql_using="btree",
    )
    op.create_index(
        "ix_audit_logs_org_time",
        "audit_logs",
        ["organization_id", sa.text("created_at DESC")],
        postgresql_using="btree",
    )


def downgrade() -> None:
    op.drop_index("ix_audit_logs_org_time", table_name="audit_logs")
    op.drop_index("ix_audit_logs_org_action_time", table_name="audit_logs")
