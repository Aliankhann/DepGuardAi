"""add_context_fields_to_usage_locations

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-03-08 03:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e5f6a7b8c9d0'
down_revision: Union[str, None] = 'd4e5f6a7b8c9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('usage_locations', sa.Column('sensitivity_level', sa.String(), nullable=True))
    op.add_column('usage_locations', sa.Column('sensitive_surface_reason', sa.String(), nullable=True))
    op.add_column('usage_locations', sa.Column('subsystem_labels', sa.JSON(), nullable=True))
    op.add_column('usage_locations', sa.Column('user_input_proximity', sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column('usage_locations', 'user_input_proximity')
    op.drop_column('usage_locations', 'subsystem_labels')
    op.drop_column('usage_locations', 'sensitive_surface_reason')
    op.drop_column('usage_locations', 'sensitivity_level')
