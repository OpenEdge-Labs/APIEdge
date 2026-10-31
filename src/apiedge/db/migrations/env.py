# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""Alembic environment. Invoked via ``apiedge migrate`` (see apiedge.db.base)."""

from __future__ import annotations

from alembic import context

from apiedge.db import models  # noqa: F401  (registers tables on Base.metadata)
from apiedge.db.base import Base, make_engine

config = context.config
target_metadata = Base.metadata


def run_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_online() -> None:
    url = config.get_main_option("sqlalchemy.url")
    if url is None:  # set by apiedge.db.base.alembic_config()
        raise RuntimeError("sqlalchemy.url is not configured")
    engine = make_engine(url)
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,  # SQLite-safe ALTER TABLE
        )
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_offline()
else:
    run_online()
