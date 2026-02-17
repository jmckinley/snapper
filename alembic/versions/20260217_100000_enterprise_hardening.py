"""Enterprise hardening: MFA/TOTP fields, API key rotation, vault key version, SCIM Groups.

Adds totp_secret, totp_enabled, totp_backup_codes to users;
api_key_rotated_at to agents;
encryption_key_version to pii_vault_entries;
external_id to teams.

Revision ID: bb27cc38dd49
Revises: aa16bb27cc38
Create Date: 2026-02-17 10:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "bb27cc38dd49"
down_revision: Union[str, None] = "aa16bb27cc38"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Users: MFA/TOTP
    op.add_column("users", sa.Column("totp_secret", sa.String(255), nullable=True))
    op.add_column(
        "users", sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default="false")
    )
    op.add_column(
        "users", sa.Column("totp_backup_codes", postgresql.JSONB(), nullable=True)
    )

    # Agents: API key rotation tracking
    op.add_column(
        "agents",
        sa.Column("api_key_rotated_at", sa.DateTime(timezone=True), nullable=True),
    )

    # PII Vault: encryption key versioning
    op.add_column(
        "pii_vault_entries",
        sa.Column(
            "encryption_key_version",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
    )

    # Teams: SCIM Group external ID
    op.add_column("teams", sa.Column("external_id", sa.String(255), nullable=True))


def downgrade() -> None:
    op.drop_column("teams", "external_id")
    op.drop_column("pii_vault_entries", "encryption_key_version")
    op.drop_column("agents", "api_key_rotated_at")
    op.drop_column("users", "totp_backup_codes")
    op.drop_column("users", "totp_enabled")
    op.drop_column("users", "totp_secret")
