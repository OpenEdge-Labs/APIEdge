# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""T-004: the system settings API behind the console and the shipped console bundle."""

from __future__ import annotations

import re

from pydantic import SecretStr

from apiedge.admin.system import settings_view
from apiedge.app import STATIC_DIR
from apiedge.config import Settings
from tests.integration.conftest import World

SETTINGS = "/api/v1/system/settings"


def test_superadmin_reads_settings(world: World) -> None:
    r = world.client.get(SETTINGS, headers=world.login("root"))
    assert r.status_code == 200, r.text
    names = {row["name"]: row for row in r.json()}
    assert names["env"]["value"] == "production"
    assert names["database"]["value"] == "sqlite"
    assert {"name", "value", "group"} == set(names["port"])


def test_settings_denied_without_platform_permission(world: World) -> None:
    # TenantAdmins and a Viewer hold settings:read only inside their tenant.
    for user in ("alice", "victor", "bob"):
        r = world.client.get(SETTINGS, headers=world.login(user))
        assert r.status_code == 403, (user, r.text)
        assert r.json()["detail"] == "permission_denied"


def test_settings_require_authentication(world: World) -> None:
    assert world.client.get(SETTINGS).status_code == 401


def test_settings_view_never_contains_secrets() -> None:
    s = Settings(
        database_url="postgresql+psycopg://apiedge:db-pass-123@db/apiedge",
        secret_key=SecretStr("master-key-value"),
        secret_key_previous=[SecretStr("old-key-value")],
        jwt_secret=SecretStr("jwt-signing-value"),
    )
    text = repr([row.model_dump() for row in settings_view(s)])
    for secret in ("db-pass-123", "master-key-value", "old-key-value", "jwt-signing-value"):
        assert secret not in text
    rows = {r.name: r.value for r in settings_view(s)}
    assert rows["database"] == "postgresql"
    assert rows["secret_key"] == "configured"


def test_console_bundle_is_csp_compatible(world: World) -> None:
    r = world.client.get("/")
    assert r.status_code == 200
    assert "script-src 'self'" in r.headers["content-security-policy"]
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    # No inline scripts or styles: every <script> has a src, and no style attributes or blocks.
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html)
    assert "<style" not in html and "style=" not in html
    for ref in re.findall(r'(?:src|href)="/(assets/[^"]+)"', html):
        assert (STATIC_DIR / ref).is_file(), ref
        assert world.client.get(f"/{ref}").status_code == 200
