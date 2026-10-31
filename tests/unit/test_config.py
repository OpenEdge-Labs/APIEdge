# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from apiedge.config import Settings, default_data_dir


def test_default_database_is_sqlite_in_data_dir(tmp_path: Path) -> None:
    s = Settings(data_dir=tmp_path)
    assert s.effective_database_url == f"sqlite:///{(tmp_path.resolve() / 'apiedge.db').as_posix()}"


def test_database_url_override() -> None:
    s = Settings(database_url="postgresql+psycopg://u:p@db/apiedge")
    assert s.effective_database_url.startswith("postgresql+psycopg://")


def test_env_prefix(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("APIEDGE_PORT", "9091")
    monkeypatch.setenv("APIEDGE_DATA_DIR", str(tmp_path))
    s = Settings()
    assert s.port == 9091
    assert s.data_dir == tmp_path.resolve()


def test_defaults_are_secure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APIEDGE_HOST", raising=False)
    monkeypatch.delenv("APIEDGE_ENV", raising=False)
    s = Settings()
    assert s.host == "127.0.0.1"
    assert s.is_production


def test_invalid_port_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(port=70000)


def test_default_data_dir_is_os_conventional() -> None:
    assert "APIEdge" in default_data_dir().parts
