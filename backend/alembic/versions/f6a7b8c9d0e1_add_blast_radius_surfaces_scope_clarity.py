"""add_blast_radius_surfaces_scope_clarity

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-03-08 04:00:00.000000

Adds two new columns to analyses table produced by blast_radius_agent:
  - affected_surfaces: JSON list of security surface labels (e.g. ["auth", "api"])
  - scope_clarity:     string "high" | "medium" | "low" — confidence in scope estimate
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'f6a7b8c9d0e1'
down_revision: Union[str, None] = 'e5f6a7b8c9d0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('analyses', sa.Column('affected_surfaces', sa.JSON(), nullable=True))
    op.add_column('analyses', sa.Column('scope_clarity', sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column('analyses', 'scope_clarity')
    op.drop_column('analyses', 'affected_surfaces')
