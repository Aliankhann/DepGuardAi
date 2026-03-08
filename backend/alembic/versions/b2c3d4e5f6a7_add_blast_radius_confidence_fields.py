"""add_blast_radius_confidence_fields

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-03-08 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('analyses', sa.Column('blast_radius_label', sa.String(), nullable=True))
    op.add_column('analyses', sa.Column('confidence_percent', sa.Integer(), nullable=True))
    op.add_column('analyses', sa.Column('confidence_reasons', sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column('analyses', 'confidence_reasons')
    op.drop_column('analyses', 'confidence_percent')
    op.drop_column('analyses', 'blast_radius_label')
