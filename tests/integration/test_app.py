# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from apiedge.app import STATIC_DIR, create_app
from apiedge.config import Settings
from apiedge.db.base import run_migrations


def test_healthz_is_public_and_minimal(settings: Settings) -> None:
    with TestClient(create_app(settings)) as client:
        r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}  # no version or internals disclosed


def test_readyz_ok_after_migrations(settings: Settings) -> None:
    run_migrations(settings.effective_database_url)
    with TestClient(create_app(settings)) as client:
        assert client.get("/readyz").json() == {"status": "ok"}


def test_readyz_unavailable_when_db_unreachable(settings: Settings, tmp_path: Path) -> None:
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")
    app = create_app(settings)
    app.state.engine = create_engine(f"sqlite:///{(blocker / 'db.sqlite').as_posix()}")
    with TestClient(app) as client:
        r = client.get("/readyz")
    assert r.status_code == 503
    assert r.json() == {"status": "unavailable"}  # no exception details leaked


def test_docs_only_in_development(tmp_path: Path) -> None:
    with TestClient(create_app(Settings(data_dir=tmp_path, env="production"))) as c:
        assert c.get("/api/docs").status_code != 200
        assert c.get("/api/v1/openapi.json").status_code == 200
    with TestClient(create_app(Settings(data_dir=tmp_path, env="development"))) as c:
        assert c.get("/api/docs").status_code == 200


def test_console_is_served(settings: Settings) -> None:
    assert (STATIC_DIR / "index.html").is_file(), "prebuilt console must be committed"
    with TestClient(create_app(settings)) as client:
        r = client.get("/")
    assert r.status_code == 200
    assert "APIEdge" in r.text
