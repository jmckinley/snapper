"""Migrate PII Vault encryption scheme from Fernet to AES-256-GCM.

Adds encryption_scheme column to pii_vault_entries. Existing entries default
to 'fernet' (backward compatible). New entries use 'aes-256-gcm'.

Revision ID: dd49ee50ff61
Revises: cc38dd49ee50
Create Date: 2026-02-18 10:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "dd49ee50ff61"
down_revision: Union[str, None] = "cc38dd49ee50"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add encryption_scheme column — existing rows get 'fernet' since they
    # were encrypted with Fernet. New rows will default to 'aes-256-gcm'
    # via the model default.
    op.add_column(
        "pii_vault_entries",
        sa.Column(
            "encryption_scheme",
            sa.String(20),
            nullable=False,
            server_default="fernet",
        ),
    )
    # Change the server_default for future inserts to 'aes-256-gcm'
    op.alter_column(
        "pii_vault_entries",
        "encryption_scheme",
        server_default="aes-256-gcm",
    )


def downgrade() -> None:
    op.drop_column("pii_vault_entries", "encryption_scheme")
