# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""Fixtures for admin API tests: a migrated database with two tenants and users in each."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from apiedge.app import create_app
from apiedge.config import Settings
from apiedge.db.base import make_engine, make_session_factory, run_migrations
from apiedge.db.models import Role, RoleAssignment, Tenant, User
from apiedge.security.crypto import ensure_key_file
from apiedge.security.passwords import hash_password

PASSWORD = "Correct-Horse-42!"


@dataclass
class World:
    client: TestClient
    settings: Settings
    tenant_a: int
    tenant_b: int
    users: dict[str, int]

    def login(self, username: str, password: str = PASSWORD, **extra: str) -> dict[str, str]:
        """Bearer headers for ``username`` (cookies are dropped so CSRF does not apply)."""
        r = self.client.post(
            "/api/v1/auth/login", json={"username": username, "password": password, **extra}
        )
        assert r.status_code == 200, r.text
        self.client.cookies.clear()
        return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def api_settings(tmp_path: Path) -> Settings:
    settings = Settings(
        data_dir=tmp_path / "data",
        env="production",
        login_rate_limit_per_minute=1000,
    )
    run_migrations(settings.effective_database_url)
    ensure_key_file(settings.effective_secret_key_file)
    return settings


def _seed(settings: Settings) -> tuple[int, int, dict[str, int]]:
    engine = make_engine(settings.effective_database_url)
    factory = make_session_factory(engine)
    pw = hash_password(PASSWORD)
    users: dict[str, int] = {}
    with factory() as s:
        roles = {r.name: r.id for r in s.scalars(select(Role))}
        a, b = Tenant(slug="acme", name="Acme"), Tenant(slug="globex", name="Globex")
        s.add_all([a, b])
        s.flush()
        spec = [
            ("root", None, None),
            ("alice", a.id, "TenantAdmin"),
            ("victor", a.id, "Viewer"),
            ("dev", a.id, "APIDeveloper"),
            ("bob", b.id, "TenantAdmin"),
        ]
        for name, tid, role in spec:
            u = User(
                username=name,
                tenant_id=tid,
                password_hash=pw,
                is_superadmin=tid is None,
                must_change_password=False,
            )
            s.add(u)
            s.flush()
            users[name] = u.id
            if role:
                s.add(RoleAssignment(tenant_id=tid, user_id=u.id, role_id=roles[role]))
        s.commit()
        ids = (a.id, b.id)
    engine.dispose()
    return ids[0], ids[1], users


@pytest.fixture
def world(api_settings: Settings) -> Iterator[World]:
    tenant_a, tenant_b, users = _seed(api_settings)
    with TestClient(create_app(api_settings)) as client:
        yield World(client, api_settings, tenant_a, tenant_b, users)
