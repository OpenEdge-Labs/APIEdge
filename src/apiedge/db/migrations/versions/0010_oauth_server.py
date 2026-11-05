# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""OAuth 2.0 / OIDC authorization server tables and the oauth permissions (T-023)

Revision ID: 0010
Revises: 0009
Create Date: 2026-11-05
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Frozen copy of the catalog additions in apiedge.security.rbac.
PERMISSIONS = [
    ("oauth:read", "View OAuth clients, signing keys and the authorization server"),
    ("oauth:manage", "Create, change and delete OAuth clients and rotate signing keys"),
]
GRANTS = {
    "SuperAdmin": ["oauth:read", "oauth:manage"],
    "TenantAdmin": ["oauth:read", "oauth:manage"],
    "ProductOwner": ["oauth:read"],
    "APIDeveloper": ["oauth:read"],
    "Viewer": ["oauth:read"],
}


def _tenant_fk(table: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["tenant_id"],
        ["tenants.id"],
        name=op.f(f"fk_{table}_tenant_id_tenants"),
        ondelete="CASCADE",
    )


def _fk(table: str, column: str, target: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        [column], [f"{target}.id"], name=op.f(f"fk_{table}_{column}_{target}"), ondelete="CASCADE"
    )


def upgrade() -> None:
    op.create_table(
        "oauth_signing_keys",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("kid", sa.String(length=64), nullable=False),
        sa.Column("algorithm", sa.String(length=16), nullable=False),
        sa.Column("private_key", sa.Text(), nullable=False),
        sa.Column("public_jwk", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('active', 'retired')", name=op.f("ck_oauth_signing_keys_status")
        ),
        _tenant_fk("oauth_signing_keys"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_oauth_signing_keys")),
        sa.UniqueConstraint("kid", name=op.f("uq_oauth_signing_keys_kid")),
    )
    op.create_index(op.f("ix_oauth_signing_keys_tenant_id"), "oauth_signing_keys", ["tenant_id"])

    op.create_table(
        "oauth_clients",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("client_type", sa.String(length=16), nullable=False),
        sa.Column("secret_hash", sa.String(length=64), nullable=True),
        sa.Column("secret_prefix", sa.String(length=16), nullable=True),
        sa.Column("redirect_uris", sa.Text(), nullable=False),
        sa.Column("grant_types", sa.Text(), nullable=False),
        sa.Column("scopes", sa.Text(), nullable=False),
        sa.Column("audiences", sa.Text(), nullable=False),
        sa.Column("access_token_ttl", sa.Integer(), nullable=False),
        sa.Column("refresh_token_ttl", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "client_type IN ('confidential', 'public')", name=op.f("ck_oauth_clients_client_type")
        ),
        _tenant_fk("oauth_clients"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_oauth_clients")),
        sa.UniqueConstraint("client_id", name=op.f("uq_oauth_clients_client_id")),
        sa.UniqueConstraint("tenant_id", "name", name="uq_oauth_clients_tenant_id_name"),
    )
    op.create_index(op.f("ix_oauth_clients_tenant_id"), "oauth_clients", ["tenant_id"])

    op.create_table(
        "oauth_codes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("client_pk", sa.Integer(), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("redirect_uri", sa.Text(), nullable=False),
        sa.Column("scope", sa.Text(), nullable=False),
        sa.Column("code_challenge", sa.String(length=64), nullable=False),
        sa.Column("nonce", sa.String(length=255), nullable=True),
        sa.Column("family_id", sa.String(length=32), nullable=False),
        sa.Column("auth_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        _tenant_fk("oauth_codes"),
        _fk("oauth_codes", "client_pk", "oauth_clients"),
        _fk("oauth_codes", "user_id", "users"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_oauth_codes")),
        sa.UniqueConstraint("code_hash", name=op.f("uq_oauth_codes_code_hash")),
    )
    op.create_index(op.f("ix_oauth_codes_tenant_id"), "oauth_codes", ["tenant_id"])
    op.create_index(op.f("ix_oauth_codes_client_pk"), "oauth_codes", ["client_pk"])

    op.create_table(
        "oauth_refresh_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("client_pk", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("family_id", sa.String(length=32), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("scope", sa.Text(), nullable=False),
        sa.Column("auth_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        _tenant_fk("oauth_refresh_tokens"),
        _fk("oauth_refresh_tokens", "client_pk", "oauth_clients"),
        _fk("oauth_refresh_tokens", "user_id", "users"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_oauth_refresh_tokens")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_oauth_refresh_tokens_token_hash")),
    )
    for col in ("tenant_id", "client_pk", "family_id"):
        op.create_index(op.f(f"ix_oauth_refresh_tokens_{col}"), "oauth_refresh_tokens", [col])

    op.create_table(
        "oauth_revoked_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("jti", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        _tenant_fk("oauth_revoked_tokens"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_oauth_revoked_tokens")),
        sa.UniqueConstraint("jti", name=op.f("uq_oauth_revoked_tokens_jti")),
    )
    op.create_index(
        op.f("ix_oauth_revoked_tokens_tenant_id"), "oauth_revoked_tokens", ["tenant_id"]
    )

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
    op.drop_index(op.f("ix_oauth_revoked_tokens_tenant_id"), table_name="oauth_revoked_tokens")
    op.drop_table("oauth_revoked_tokens")
    for col in ("tenant_id", "client_pk", "family_id"):
        op.drop_index(op.f(f"ix_oauth_refresh_tokens_{col}"), table_name="oauth_refresh_tokens")
    op.drop_table("oauth_refresh_tokens")
    op.drop_index(op.f("ix_oauth_codes_client_pk"), table_name="oauth_codes")
    op.drop_index(op.f("ix_oauth_codes_tenant_id"), table_name="oauth_codes")
    op.drop_table("oauth_codes")
    op.drop_index(op.f("ix_oauth_clients_tenant_id"), table_name="oauth_clients")
    op.drop_table("oauth_clients")
    op.drop_index(op.f("ix_oauth_signing_keys_tenant_id"), table_name="oauth_signing_keys")
    op.drop_table("oauth_signing_keys")
