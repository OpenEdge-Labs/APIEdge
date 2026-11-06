# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""LDAP / Active Directory directories (T-023)

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-06
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Frozen copy of the catalog additions in apiedge.security.rbac.
PERMISSIONS = [
    ("ldap:read", "View LDAP and Active Directory directories"),
    ("ldap:manage", "Create, change, test and delete LDAP and Active Directory directories"),
]
GRANTS = {
    "SuperAdmin": ["ldap:read", "ldap:manage"],
    "TenantAdmin": ["ldap:read", "ldap:manage"],
    "ProductOwner": ["ldap:read"],
    "APIDeveloper": ["ldap:read"],
    "Viewer": ["ldap:read"],
}


def upgrade() -> None:
    op.create_table(
        "ldap_directories",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("security", sa.String(length=16), nullable=False),
        sa.Column("truststore_id", sa.Integer(), nullable=True),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("bind_dn", sa.String(length=1024), nullable=False),
        sa.Column("bind_password", sa.Text(), nullable=True),
        sa.Column("user_base_dn", sa.String(length=1024), nullable=False),
        sa.Column("user_filter", sa.String(length=1024), nullable=False),
        sa.Column("user_dn_template", sa.String(length=1024), nullable=False),
        sa.Column("username_attribute", sa.String(length=128), nullable=False),
        sa.Column("email_attribute", sa.String(length=128), nullable=False),
        sa.Column("name_attribute", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "security IN ('ldaps', 'starttls', 'plain')",
            name=op.f("ck_ldap_directories_security"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_ldap_directories_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["truststore_id"],
            ["truststores.id"],
            name=op.f("fk_ldap_directories_truststore_id_truststores"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ldap_directories")),
        sa.UniqueConstraint("tenant_id", "name", name="uq_ldap_directories_tenant_id_name"),
    )
    op.create_index(op.f("ix_ldap_directories_tenant_id"), "ldap_directories", ["tenant_id"])

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
    op.drop_index(op.f("ix_ldap_directories_tenant_id"), table_name="ldap_directories")
    op.drop_table("ldap_directories")
