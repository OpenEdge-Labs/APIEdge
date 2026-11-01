# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Policy chains, API keys and the apikey permissions (T-008)

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Frozen copy of the catalog additions in apiedge.security.rbac.
PERMISSIONS = [
    ("apikey:read", "View API keys"),
    ("apikey:manage", "Create and revoke API keys"),
]
GRANTS = {
    "SuperAdmin": ["apikey:read", "apikey:manage"],
    "TenantAdmin": ["apikey:read", "apikey:manage"],
    "ProductOwner": ["apikey:read", "apikey:manage"],
    "APIDeveloper": ["apikey:read", "apikey:manage"],
    "Viewer": ["apikey:read"],
}


def upgrade() -> None:
    with op.batch_alter_table("apis") as b:
        b.add_column(sa.Column("policies", sa.Text(), nullable=False, server_default="[]"))
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("product_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("prefix", sa.String(length=16), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_api_keys_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["product_id"],
            ["products.id"],
            name=op.f("fk_api_keys_product_id_products"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_api_keys")),
        sa.UniqueConstraint("key_hash", name=op.f("uq_api_keys_key_hash")),
    )
    op.create_index(op.f("ix_api_keys_tenant_id"), "api_keys", ["tenant_id"])
    op.create_index(op.f("ix_api_keys_product_id"), "api_keys", ["product_id"])

    perms = sa.table("permissions", sa.column("name", sa.String), sa.column("description"))
    op.bulk_insert(perms, [{"name": n, "description": d} for n, d in PERMISSIONS])
    conn = op.get_bind()
    roles = dict(
        conn.execute(
            sa.text("SELECT name, id FROM roles WHERE tenant_id IS NULL AND is_builtin")
        ).all()
    )
    role_perms = sa.table("role_permissions", sa.column("role_id"), sa.column("permission"))
    op.bulk_insert(
        role_perms,
        [
            {"role_id": roles[name], "permission": p}
            for name, ps in GRANTS.items()
            if name in roles
            for p in ps
        ],
    )


def downgrade() -> None:
    names = [n for n, _ in PERMISSIONS]
    conn = op.get_bind()
    for name in names:
        conn.execute(sa.text("DELETE FROM role_permissions WHERE permission = :p"), {"p": name})
        conn.execute(sa.text("DELETE FROM permissions WHERE name = :p"), {"p": name})
    op.drop_index(op.f("ix_api_keys_product_id"), table_name="api_keys")
    op.drop_index(op.f("ix_api_keys_tenant_id"), table_name="api_keys")
    op.drop_table("api_keys")
    with op.batch_alter_table("apis") as b:
        b.drop_column("policies")
