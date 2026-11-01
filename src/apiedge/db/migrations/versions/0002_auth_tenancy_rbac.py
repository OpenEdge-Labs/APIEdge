# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""auth, multi-tenancy and RBAC core (T-003)

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-01

The permission catalog and built-in roles below are a frozen copy of
``apiedge.security.rbac`` at this revision. Later catalog changes need a new migration;
``tests/integration/test_rbac_catalog.py`` detects drift.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PERMISSIONS = [
    ("tenant:create", "Create tenants"),
    ("tenant:delete", "Delete tenants"),
    ("settings:update", "Change system settings"),
    ("tenant:read", "View the tenant"),
    ("tenant:update", "Change the tenant's name and status"),
    ("user:read", "View users"),
    ("user:create", "Create users"),
    ("user:update", "Change, disable, unlock users and reset passwords"),
    ("user:delete", "Delete users"),
    ("role:read", "View roles and role assignments"),
    ("role:create", "Create custom roles"),
    ("role:update", "Change custom roles"),
    ("role:delete", "Delete custom roles"),
    ("role:assign", "Grant and revoke roles"),
    ("audit:read", "View the audit log"),
    ("settings:read", "View system settings"),
    ("product:read", "View products"),
    ("product:create", "Create products"),
    ("product:update", "Change products"),
    ("product:delete", "Delete products"),
    ("product:publish", "Change a product's lifecycle state"),
    ("api:read", "View APIs"),
    ("api:create", "Create APIs"),
    ("api:update", "Change APIs and routes"),
    ("api:delete", "Delete APIs"),
    ("api:publish", "Change an API's lifecycle state"),
    ("policy:read", "View policy chains"),
    ("policy:update", "Change policy chains"),
    ("script:update", "Write low-code script policies"),
    ("inspector:view", "View captured traffic (masked)"),
    ("inspector:capture", "Start and stop traffic capture"),
    ("inspector:unmask", "View captured traffic unmasked"),
    ("analytics:view", "View analytics"),
    ("plan:read", "View plans"),
    ("plan:update", "Create and change plans"),
    ("consumer:read", "View consumers and applications"),
    ("consumer:update", "Create and change consumers and applications"),
    ("subscription:read", "View subscriptions"),
    ("subscription:update", "Approve and change subscriptions"),
]
_PLATFORM = {"tenant:create", "tenant:delete", "settings:update"}
_ALL = [p for p, _ in PERMISSIONS]
_TENANT = [p for p in _ALL if p not in _PLATFORM]
ROLES: dict[str, tuple[str, list[str]]] = {
    "SuperAdmin": ("Full access to the platform and every tenant", _ALL),
    "TenantAdmin": ("Full access within a tenant", _TENANT),
    "ProductOwner": (
        "Owns products: APIs, policies, plans, subscriptions and debugging",
        [
            "analytics:view", "api:create", "api:delete", "api:publish", "api:read",
            "api:update", "consumer:read", "inspector:capture", "inspector:view", "plan:read",
            "plan:update", "policy:read", "policy:update", "product:publish", "product:read",
            "product:update", "script:update", "subscription:read", "subscription:update",
        ],
    ),
    "APIDeveloper": (
        "Builds APIs and policies",
        [
            "analytics:view", "api:create", "api:read", "api:update", "inspector:capture",
            "inspector:view", "plan:read", "policy:read", "policy:update", "product:read",
            "script:update",
        ],
    ),
    "Viewer": (
        "Read-only access",
        [
            "analytics:view", "api:read", "audit:read", "consumer:read", "inspector:view",
            "plan:read", "policy:read", "product:read", "role:read", "settings:read",
            "subscription:read", "tenant:read", "user:read",
        ],
    ),
    "Consumer": (
        "Discovers APIs and manages own subscriptions",
        ["api:read", "plan:read", "product:read", "subscription:read"],
    ),
}  # fmt: skip


def _ts() -> sa.Column[datetime]:
    return sa.Column("created_at", sa.DateTime(timezone=True), nullable=False)


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("slug", sa.String(length=63), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        _ts(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tenants")),
        sa.UniqueConstraint("slug", name=op.f("uq_tenants_slug")),
    )
    with op.batch_alter_table("users") as b:
        b.add_column(sa.Column("tenant_id", sa.Integer(), nullable=True))
        b.add_column(sa.Column("email", sa.String(length=320), nullable=True))
        b.add_column(
            sa.Column("failed_login_count", sa.Integer(), nullable=False, server_default="0")
        )
        b.add_column(sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True))
        b.add_column(sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True))
        b.add_column(sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True))
        b.add_column(sa.Column("token_version", sa.Integer(), nullable=False, server_default="0"))
        b.add_column(
            sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.false())
        )
        b.add_column(sa.Column("mfa_secret_enc", sa.String(length=255), nullable=True))
        b.add_column(sa.Column("mfa_last_step", sa.Integer(), nullable=True))
        b.create_index(op.f("ix_users_tenant_id"), ["tenant_id"])
        b.create_foreign_key(
            op.f("fk_users_tenant_id_tenants"), "tenants", ["tenant_id"], ["id"],
            ondelete="CASCADE",
        )  # fmt: skip

    perms = op.create_table(
        "permissions",
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("description", sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint("name", name=op.f("pk_permissions")),
    )
    roles = op.create_table(
        "roles",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=True),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=False),
        sa.Column("is_builtin", sa.Boolean(), nullable=False),
        _ts(),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_roles_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_roles")),
        sa.UniqueConstraint("tenant_id", "name", name="uq_roles_tenant_id_name"),
    )
    op.create_index(op.f("ix_roles_tenant_id"), "roles", ["tenant_id"])
    role_perms = op.create_table(
        "role_permissions",
        sa.Column("role_id", sa.Integer(), nullable=False),
        sa.Column("permission", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(
            ["permission"],
            ["permissions.name"],
            name=op.f("fk_role_permissions_permission_permissions"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name=op.f("fk_role_permissions_role_id_roles"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("role_id", "permission", name=op.f("pk_role_permissions")),
    )
    op.create_table(
        "role_assignments",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("role_id", sa.Integer(), nullable=False),
        sa.Column("product_id", sa.Integer(), nullable=True),
        _ts(),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name=op.f("fk_role_assignments_role_id_roles"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_role_assignments_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_role_assignments_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_role_assignments")),
        sa.UniqueConstraint(
            "user_id", "role_id", "tenant_id", "product_id", name="uq_role_assignments_scope"
        ),
    )
    op.create_index(op.f("ix_role_assignments_tenant_id"), "role_assignments", ["tenant_id"])
    op.create_index(op.f("ix_role_assignments_user_id"), "role_assignments", ["user_id"])
    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("family_id", sa.String(length=32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        _ts(),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_refresh_tokens_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_refresh_tokens")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_refresh_tokens_token_hash")),
    )
    op.create_index(op.f("ix_refresh_tokens_user_id"), "refresh_tokens", ["user_id"])
    op.create_index(op.f("ix_refresh_tokens_family_id"), "refresh_tokens", ["family_id"])
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=True),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("actor_username", sa.String(length=150), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=True),
        sa.Column("resource_id", sa.String(length=64), nullable=True),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("client_ip", sa.String(length=64), nullable=True),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.Column("details", sa.Text(), nullable=True),
        _ts(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_log")),
    )
    op.create_index(op.f("ix_audit_log_tenant_id"), "audit_log", ["tenant_id"])
    op.create_index(op.f("ix_audit_log_action"), "audit_log", ["action"])
    op.create_index(op.f("ix_audit_log_created_at"), "audit_log", ["created_at"])

    # Seed the catalog and the built-in (global, read-only) roles.
    now = datetime.now(timezone.utc)
    op.bulk_insert(perms, [{"name": n, "description": d} for n, d in PERMISSIONS])
    op.bulk_insert(
        roles,
        [
            {
                "id": i,
                "tenant_id": None,
                "name": name,
                "description": desc,
                "is_builtin": True,
                "created_at": now,
            }
            for i, (name, (desc, _)) in enumerate(ROLES.items(), start=1)
        ],
    )
    op.bulk_insert(
        role_perms,
        [
            {"role_id": i, "permission": p}
            for i, (_, (_, ps)) in enumerate(ROLES.items(), start=1)
            for p in ps
        ],
    )


def downgrade() -> None:
    op.drop_table("audit_log")
    op.drop_table("refresh_tokens")
    op.drop_table("role_assignments")
    op.drop_table("role_permissions")
    op.drop_table("roles")
    op.drop_table("permissions")
    with op.batch_alter_table("users") as b:
        b.drop_constraint(op.f("fk_users_tenant_id_tenants"), type_="foreignkey")
        b.drop_index(op.f("ix_users_tenant_id"))
        for col in (
            "mfa_last_step", "mfa_secret_enc", "mfa_enabled", "token_version",
            "password_changed_at", "last_login_at", "locked_until", "failed_login_count",
            "email", "tenant_id",
        ):  # fmt: skip
            b.drop_column(col)
    op.drop_table("tenants")
