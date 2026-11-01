# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""APIs, upstreams and routes inside products (T-006)

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-01
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _tenant_fk(table: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["tenant_id"],
        ["tenants.id"],
        name=op.f(f"fk_{table}_tenant_id_tenants"),
        ondelete="CASCADE",
    )


def _api_fk(table: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["api_id"], ["apis.id"], name=op.f(f"fk_{table}_api_id_apis"), ondelete="CASCADE"
    )


def upgrade() -> None:
    op.create_table(
        "apis",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("product_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("base_path", sa.String(length=255), nullable=False),
        sa.Column("timeout_ms", sa.Integer(), nullable=False),
        sa.Column("lifecycle", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "lifecycle IN ('draft', 'published', 'deprecated', 'retired')",
            name=op.f("ck_apis_lifecycle"),
        ),
        _tenant_fk("apis"),
        sa.ForeignKeyConstraint(
            ["product_id"],
            ["products.id"],
            name=op.f("fk_apis_product_id_products"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_apis")),
        sa.UniqueConstraint("tenant_id", "base_path", name="uq_apis_tenant_id_base_path"),
        sa.UniqueConstraint(
            "product_id", "name", "version", name="uq_apis_product_id_name_version"
        ),
    )
    op.create_index(op.f("ix_apis_tenant_id"), "apis", ["tenant_id"])
    op.create_index(op.f("ix_apis_product_id"), "apis", ["product_id"])

    op.create_table(
        "api_upstreams",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("api_id", sa.Integer(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("weight", sa.Integer(), nullable=False),
        _tenant_fk("api_upstreams"),
        _api_fk("api_upstreams"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_api_upstreams")),
    )
    op.create_index(op.f("ix_api_upstreams_tenant_id"), "api_upstreams", ["tenant_id"])
    op.create_index(op.f("ix_api_upstreams_api_id"), "api_upstreams", ["api_id"])

    op.create_table(
        "api_routes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("api_id", sa.Integer(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("methods", sa.String(length=64), nullable=False),
        sa.Column("path", sa.String(length=500), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        _tenant_fk("api_routes"),
        _api_fk("api_routes"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_api_routes")),
    )
    op.create_index(op.f("ix_api_routes_tenant_id"), "api_routes", ["tenant_id"])
    op.create_index(op.f("ix_api_routes_api_id"), "api_routes", ["api_id"])


def downgrade() -> None:
    for table in ("api_routes", "api_upstreams"):
        op.drop_index(op.f(f"ix_{table}_api_id"), table_name=table)
        op.drop_index(op.f(f"ix_{table}_tenant_id"), table_name=table)
        op.drop_table(table)
    op.drop_index(op.f("ix_apis_product_id"), table_name="apis")
    op.drop_index(op.f("ix_apis_tenant_id"), table_name="apis")
    op.drop_table("apis")
