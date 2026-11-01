# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""products and product owners (T-005)

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-01

Adds ``products`` and ``product_owners`` and the foreign key from ``role_assignments.product_id``
to ``products.id`` (product-scoped grants are removed with their product). Product-scoped grants
created before this revision cannot point at a real product and are deleted first.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "products",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("lifecycle", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "lifecycle IN ('draft', 'published', 'deprecated', 'retired')",
            name=op.f("ck_products_lifecycle"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_products_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_products")),
        sa.UniqueConstraint("tenant_id", "name", name="uq_products_tenant_id_name"),
    )
    op.create_index(op.f("ix_products_tenant_id"), "products", ["tenant_id"])
    op.create_table(
        "product_owners",
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("product_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["product_id"],
            ["products.id"],
            name=op.f("fk_product_owners_product_id_products"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_product_owners_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_product_owners_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("product_id", "user_id", name=op.f("pk_product_owners")),
    )
    op.create_index(op.f("ix_product_owners_tenant_id"), "product_owners", ["tenant_id"])
    op.create_index(op.f("ix_product_owners_user_id"), "product_owners", ["user_id"])

    op.execute("DELETE FROM role_assignments WHERE product_id IS NOT NULL")
    with op.batch_alter_table("role_assignments") as batch:
        batch.create_index(batch.f("ix_role_assignments_product_id"), ["product_id"])
        batch.create_foreign_key(
            batch.f("fk_role_assignments_product_id_products"),
            "products",
            ["product_id"],
            ["id"],
            ondelete="CASCADE",
        )


def downgrade() -> None:
    with op.batch_alter_table("role_assignments") as batch:
        batch.drop_constraint(
            batch.f("fk_role_assignments_product_id_products"), type_="foreignkey"
        )
        batch.drop_index(batch.f("ix_role_assignments_product_id"))
    op.drop_index(op.f("ix_product_owners_user_id"), table_name="product_owners")
    op.drop_index(op.f("ix_product_owners_tenant_id"), table_name="product_owners")
    op.drop_table("product_owners")
    op.drop_index(op.f("ix_products_tenant_id"), table_name="products")
    op.drop_table("products")
