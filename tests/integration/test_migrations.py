# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path

from alembic import command
from sqlalchemy import inspect

from apiedge.db.base import alembic_config, make_engine, run_migrations


def test_upgrade_downgrade_roundtrip(tmp_path: Path) -> None:
    url = f"sqlite:///{(tmp_path / 'm.db').as_posix()}"
    run_migrations(url)
    engine = make_engine(url)
    assert "users" in inspect(engine).get_table_names()
    command.downgrade(alembic_config(url), "base")
    assert "users" not in inspect(engine).get_table_names()
    run_migrations(url)
    assert "users" in inspect(engine).get_table_names()
    engine.dispose()
