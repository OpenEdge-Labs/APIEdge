# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Packet inspector: capture sessions and captured exchanges (T-012)

The inspector permissions were already seeded by 0002.

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "capture_sessions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("product_id", sa.Integer(), nullable=False),
        sa.Column("api_id", sa.Integer(), nullable=False),
        sa.Column("route", sa.String(length=500), nullable=True),
        sa.Column("consumer", sa.String(length=128), nullable=True),
        sa.Column("max_exchanges", sa.Integer(), nullable=False),
        sa.Column("max_body_bytes", sa.Integer(), nullable=False),
        sa.Column("mask_fields", sa.Text(), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("created_by_name", sa.String(length=150), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("stopped_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("captured", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_capture_sessions_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["product_id"],
            ["products.id"],
            name=op.f("fk_capture_sessions_product_id_products"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["api_id"],
            ["apis.id"],
            name=op.f("fk_capture_sessions_api_id_apis"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            name=op.f("fk_capture_sessions_created_by_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_capture_sessions")),
    )
    for col in ("tenant_id", "product_id", "api_id"):
        op.create_index(op.f(f"ix_capture_sessions_{col}"), "capture_sessions", [col])
    op.create_table(
        "captured_exchanges",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("session_id", sa.Integer(), nullable=False),
        sa.Column("product_id", sa.Integer(), nullable=False),
        sa.Column("api_id", sa.Integer(), nullable=False),
        sa.Column("request_id", sa.String(length=128), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("method", sa.String(length=10), nullable=False),
        sa.Column("path", sa.String(length=2048), nullable=False),
        sa.Column("route", sa.String(length=500), nullable=False),
        sa.Column("status", sa.Integer(), nullable=False),
        sa.Column("consumer", sa.String(length=128), nullable=False),
        sa.Column("duration_ms", sa.Float(), nullable=False),
        sa.Column("upstream", sa.String(length=2048), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("data", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_captured_exchanges_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["capture_sessions.id"],
            name=op.f("fk_captured_exchanges_session_id_capture_sessions"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_captured_exchanges")),
    )
    op.create_index(op.f("ix_captured_exchanges_session_id"), "captured_exchanges", ["session_id"])
    op.create_index(
        "ix_captured_exchanges_tenant_session", "captured_exchanges", ["tenant_id", "session_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_captured_exchanges_tenant_session", table_name="captured_exchanges")
    op.drop_index(op.f("ix_captured_exchanges_session_id"), table_name="captured_exchanges")
    op.drop_table("captured_exchanges")
    for col in ("api_id", "product_id", "tenant_id"):
        op.drop_index(op.f(f"ix_capture_sessions_{col}"), table_name="capture_sessions")
    op.drop_table("capture_sessions")
