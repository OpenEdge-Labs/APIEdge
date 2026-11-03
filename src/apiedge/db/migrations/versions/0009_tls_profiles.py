# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""TLS profiles for upstream connections (T-023)

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-03
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "tls_profiles",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("min_version", sa.String(length=8), nullable=False),
        sa.Column("ciphers", sa.String(length=2000), nullable=True),
        sa.Column("truststore_id", sa.Integer(), nullable=True),
        sa.Column("keystore_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "min_version IN ('1.2', '1.3')", name=op.f("ck_tls_profiles_min_version")
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_tls_profiles_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["truststore_id"],
            ["truststores.id"],
            name=op.f("fk_tls_profiles_truststore_id_truststores"),
        ),
        sa.ForeignKeyConstraint(
            ["keystore_id"], ["keystores.id"], name=op.f("fk_tls_profiles_keystore_id_keystores")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tls_profiles")),
        sa.UniqueConstraint("tenant_id", "name", name="uq_tls_profiles_tenant_id_name"),
    )
    op.create_index(op.f("ix_tls_profiles_tenant_id"), "tls_profiles", ["tenant_id"])
    with op.batch_alter_table("apis") as batch:
        batch.add_column(sa.Column("tls_profile_id", sa.Integer(), nullable=True))
        batch.create_index(batch.f("ix_apis_tls_profile_id"), ["tls_profile_id"])
        batch.create_foreign_key(
            batch.f("fk_apis_tls_profile_id_tls_profiles"),
            "tls_profiles",
            ["tls_profile_id"],
            ["id"],
        )


def downgrade() -> None:
    with op.batch_alter_table("apis") as batch:
        batch.drop_constraint(batch.f("fk_apis_tls_profile_id_tls_profiles"), type_="foreignkey")
        batch.drop_index(batch.f("ix_apis_tls_profile_id"))
        batch.drop_column("tls_profile_id")
    op.drop_index(op.f("ix_tls_profiles_tenant_id"), table_name="tls_profiles")
    op.drop_table("tls_profiles")
