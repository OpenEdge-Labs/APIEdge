# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import io
from pathlib import Path

import pytest
from sqlalchemy import inspect, select

from apiedge.cli import _redact, main
from apiedge.db.base import make_engine, make_session_factory
from apiedge.db.models import User
from apiedge.security.passwords import verify_password


def _db(data_dir: Path) -> str:
    return f"sqlite:///{(data_dir.resolve() / 'apiedge.db').as_posix()}"


def test_init_creates_db_and_is_idempotent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["init", "--data-dir", str(tmp_path)]) == 0
    assert "database is up to date" in capsys.readouterr().out
    engine = make_engine(_db(tmp_path))
    assert "users" in inspect(engine).get_table_names()
    engine.dispose()
    assert main(["migrate", "--data-dir", str(tmp_path)]) == 0


def test_create_admin_generated_password(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["create-admin", "--data-dir", str(tmp_path), "--generate-password"]) == 0
    out = capsys.readouterr().out
    password = out.split("store it safely):")[1].split()[0]
    engine = make_engine(_db(tmp_path))
    with make_session_factory(engine)() as s:
        user = s.scalars(select(User).where(User.username == "admin")).one()
        assert user.is_superadmin
        assert user.must_change_password
        assert verify_password(user.password_hash, password)
        assert password not in user.password_hash
    engine.dispose()


def test_create_admin_if_missing_is_idempotent(tmp_path: Path) -> None:
    args = ["create-admin", "--data-dir", str(tmp_path), "--generate-password"]
    assert main(args) == 0
    assert main(args) == 1  # duplicate without --if-missing is an error
    assert main([*args, "--if-missing"]) == 0


def test_create_admin_password_stdin_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("short\n"))
    assert main(["create-admin", "--data-dir", str(tmp_path), "--password-stdin"]) == 1
    monkeypatch.setattr("sys.stdin", io.StringIO("a-long-enough-pass\n"))
    assert main(["create-admin", "--data-dir", str(tmp_path), "--password-stdin"]) == 0


def test_create_admin_refuses_without_tty_or_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert main(["create-admin", "--data-dir", str(tmp_path)]) == 2


def test_database_password_is_redacted() -> None:
    assert _redact("postgresql://bob:s3cret@db:5432/x") == "postgresql://bob:***@db:5432/x"
    assert _redact("sqlite:///C:/x.db") == "sqlite:///C:/x.db"


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["version"]) == 0
    assert capsys.readouterr().out.strip()
