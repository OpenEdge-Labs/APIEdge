# Copyright 2026 OpenEdge Labs
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
    s = Settings(database_url="postgresql+pg8000://u:p@db/apiedge")
    assert s.effective_database_url == "postgresql+pg8000://u:p@db/apiedge"
    for alias in ("postgresql", "postgres", "postgresql+psycopg", "PostgreSQL"):
        s = Settings(database_url=f"{alias}://u:p@db/apiedge")
        assert s.effective_database_url == "postgresql+pg8000://u:p@db/apiedge", alias
    other = Settings(database_url="sqlite:////srv/apiedge.db")
    assert other.effective_database_url == "sqlite:////srv/apiedge.db"


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


def test_security_lists_from_env_csv(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("APIEDGE_CORS_ALLOW_ORIGINS", "https://a.example, https://b.example:8443/")
    monkeypatch.setenv("APIEDGE_SSRF_ALLOW_CIDRS", "10.0.0.0/8,fd00::/8")
    monkeypatch.setenv("APIEDGE_SECRET_KEY_PREVIOUS", "k1,k2")
    s = Settings(data_dir=tmp_path)
    assert s.cors_allow_origins == ["https://a.example", "https://b.example:8443"]
    assert s.ssrf_allow_cidrs == ["10.0.0.0/8", "fd00::/8"]
    assert [k.get_secret_value() for k in s.secret_key_previous] == ["k1", "k2"]
    assert s.effective_secret_key_file == tmp_path.resolve() / "secret.key"


def test_security_defaults_are_closed(tmp_path: Path) -> None:
    s = Settings(data_dir=tmp_path)
    assert s.cors_allow_origins == []
    assert s.ssrf_allow_private is False
    assert s.log_format == "json"
    assert s.max_request_body_bytes == 2 * 1024 * 1024
    assert "topsecret" not in repr(Settings(data_dir=tmp_path, secret_key="topsecret"))


@pytest.mark.parametrize(
    "origin", ["*", "null", "ftp://x.example", "https://x.example/path", "https://u@x.example"]
)
def test_invalid_cors_origin_rejected(origin: str) -> None:
    with pytest.raises(ValidationError):
        Settings(cors_allow_origins=[origin])


def test_invalid_cidr_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(ssrf_deny_cidrs=["not-a-cidr"])
