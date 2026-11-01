# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""Analytics time buckets (T-013)

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-01
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "analytics_buckets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("bucket_start", sa.BigInteger(), nullable=False),
        sa.Column("product_id", sa.Integer(), nullable=False),
        sa.Column("api_id", sa.Integer(), nullable=False),
        sa.Column("route", sa.String(length=500), nullable=False),
        sa.Column("method", sa.String(length=10), nullable=False),
        sa.Column("consumer", sa.String(length=128), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("requests", sa.Integer(), nullable=False),
        sa.Column("latency_sum_ms", sa.Float(), nullable=False),
        sa.Column("latency_max_ms", sa.Float(), nullable=False),
        sa.Column("bytes_in", sa.BigInteger(), nullable=False),
        sa.Column("bytes_out", sa.BigInteger(), nullable=False),
        sa.Column("h0", sa.Integer(), nullable=False),
        sa.Column("h1", sa.Integer(), nullable=False),
        sa.Column("h2", sa.Integer(), nullable=False),
        sa.Column("h3", sa.Integer(), nullable=False),
        sa.Column("h4", sa.Integer(), nullable=False),
        sa.Column("h5", sa.Integer(), nullable=False),
        sa.Column("h6", sa.Integer(), nullable=False),
        sa.Column("h7", sa.Integer(), nullable=False),
        sa.Column("h8", sa.Integer(), nullable=False),
        sa.Column("h9", sa.Integer(), nullable=False),
        sa.Column("h10", sa.Integer(), nullable=False),
        sa.Column("h11", sa.Integer(), nullable=False),
        sa.Column("h12", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_analytics_buckets_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_analytics_buckets")),
    )
    op.create_index(
        op.f("ix_analytics_buckets_bucket_start"), "analytics_buckets", ["bucket_start"]
    )
    op.create_index(
        "ix_analytics_buckets_tenant_time", "analytics_buckets", ["tenant_id", "bucket_start"]
    )


def downgrade() -> None:
    op.drop_index("ix_analytics_buckets_tenant_time", table_name="analytics_buckets")
    op.drop_index(op.f("ix_analytics_buckets_bucket_start"), table_name="analytics_buckets")
    op.drop_table("analytics_buckets")
