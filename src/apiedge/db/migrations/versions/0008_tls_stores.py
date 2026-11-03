# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Truststores, keystores and the tls permissions (T-023)

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Frozen copy of the catalog additions in apiedge.security.rbac.
PERMISSIONS = [
    ("tls:read", "View TLS profiles, keystores and truststores"),
    ("tls:manage", "Create, change and delete TLS profiles, keystores and truststores"),
]
GRANTS = {
    "SuperAdmin": ["tls:read", "tls:manage"],
    "TenantAdmin": ["tls:read", "tls:manage"],
    "ProductOwner": ["tls:read"],
    "APIDeveloper": ["tls:read"],
    "Viewer": ["tls:read"],
}


def _common() -> list[sa.Column[object]]:
    return [
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
    ]


def _tail(table: str) -> list[sa.SchemaItem]:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f(f"fk_{table}_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{table}")),
        sa.UniqueConstraint("tenant_id", "name", name=f"uq_{table}_tenant_id_name"),
    ]


def upgrade() -> None:
    op.create_table(
        "truststores",
        *_common(),
        sa.Column("certificates", sa.Text(), nullable=False),
        *_tail("truststores"),
    )
    op.create_index(op.f("ix_truststores_tenant_id"), "truststores", ["tenant_id"])
    op.create_table(
        "keystores",
        *_common(),
        sa.Column("certificate_chain", sa.Text(), nullable=False),
        sa.Column("private_key", sa.Text(), nullable=False),
        sa.Column("key_type", sa.String(length=32), nullable=False),
        sa.Column("fingerprint_sha256", sa.String(length=64), nullable=False),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=False),
        *_tail("keystores"),
    )
    op.create_index(op.f("ix_keystores_tenant_id"), "keystores", ["tenant_id"])

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
    conn = op.get_bind()
    for name, _ in PERMISSIONS:
        conn.execute(sa.text("DELETE FROM role_permissions WHERE permission = :p"), {"p": name})
        conn.execute(sa.text("DELETE FROM permissions WHERE name = :p"), {"p": name})
    op.drop_index(op.f("ix_keystores_tenant_id"), table_name="keystores")
    op.drop_table("keystores")
    op.drop_index(op.f("ix_truststores_tenant_id"), table_name="truststores")
    op.drop_table("truststores")
