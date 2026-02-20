"""Add org_issue_mitigations table for per-org CVE mitigation tracking.

Revision ID: ff61cc94dd05
Revises: ff61bb83cc94
Create Date: 2026-02-20 10:00:02.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "ff61cc94dd05"
down_revision: Union[str, None] = "ff61bb83cc94"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "org_issue_mitigations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("organization_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("issue_id", UUID(as_uuid=True), sa.ForeignKey("security_issues.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("mitigated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rule_ids", JSONB, nullable=False, server_default="[]"),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("organization_id", "issue_id", name="uq_org_issue_mitigation"),
    )


def downgrade() -> None:
    op.drop_table("org_issue_mitigations")
