"""Persist baseline and current architecture graph snapshots.

Revision ID: 20261007_graph_snapshots
Revises: edd72b7c7c5d
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision: str = "20261007_graph_snapshots"
down_revision: Union[str, Sequence[str], None] = "edd72b7c7c5d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    if not inspect(op.get_bind()).has_table("graph_snapshots"):
        op.create_table(
            "graph_snapshots",
            sa.Column("snapshot_name", sa.String(length=20), primary_key=True),
            sa.Column("graph_data", sa.JSON(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )


def downgrade() -> None:
    if inspect(op.get_bind()).has_table("graph_snapshots"):
        op.drop_table("graph_snapshots")
