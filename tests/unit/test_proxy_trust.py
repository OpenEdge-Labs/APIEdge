# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Forwarded headers are only trusted from configured proxies (T-018 finding F-01)."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
from typing import Any

import pytest
import uvicorn

from apiedge import cli
from apiedge.config import Settings

Scope = dict[str, Any]


def _client_seen(options: dict[str, Any], peer: str, forwarded_for: str) -> tuple[str, str]:
    """(client host, scheme) the application sees behind uvicorn's proxy handling."""
    seen: dict[str, Any] = {}

    async def app(scope: Scope, receive: Any, send: Any) -> None:
        seen.update(scope)

    config = uvicorn.Config(app, lifespan="off", interface="asgi3", **options)
    config.load()
    scope: Scope = {
        "type": "http",
        "scheme": "http",
        "client": (peer, 50000),
        "headers": [(b"x-forwarded-for", forwarded_for.encode()), (b"x-forwarded-proto", b"https")],
    }

    async def noop(*_: Any) -> Any:
        return {}

    asyncio.run(config.loaded_app(scope, noop, noop))
    return str(seen["client"][0]), str(seen["scheme"])


def test_no_trusted_proxies_ignores_forwarded_headers() -> None:
    assert cli.proxy_options([]) == {"proxy_headers": False}
    assert _client_seen(cli.proxy_options([]), "127.0.0.1", "203.0.113.9") == ("127.0.0.1", "http")


def test_only_listed_proxies_may_forward() -> None:
    options = cli.proxy_options(["10.0.0.0/8"])
    assert _client_seen(options, "10.1.2.3", "203.0.113.9") == ("203.0.113.9", "https")
    # A local process is no longer implicitly trusted (it was uvicorn's default).
    assert _client_seen(options, "127.0.0.1", "203.0.113.9") == ("127.0.0.1", "http")
    # Client-controlled entries left of the proxy's own entry are ignored.
    assert _client_seen(options, "10.1.2.3", "198.51.100.1, 203.0.113.9")[0] == "203.0.113.9"


def test_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    assert Settings(data_dir=tmp_path).trusted_proxies == ["127.0.0.1"]
    assert Settings(data_dir=tmp_path).gateway_trusted_proxies == []
    monkeypatch.setenv("APIEDGE_TRUSTED_PROXIES", "")
    assert Settings(data_dir=tmp_path).trusted_proxies == []
    monkeypatch.setenv("APIEDGE_TRUSTED_PROXIES", "10.0.0.0/8, 192.0.2.1")
    assert Settings(data_dir=tmp_path).trusted_proxies == ["10.0.0.0/8", "192.0.2.1"]
    monkeypatch.setenv("APIEDGE_TRUSTED_PROXIES", "not-an-ip")
    with pytest.raises(ValueError):
        Settings(data_dir=tmp_path)


def test_run_applies_each_servers_own_proxy_list(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("APIEDGE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APIEDGE_TRUSTED_PROXIES", "192.0.2.10")
    monkeypatch.delenv("APIEDGE_GATEWAY_TRUSTED_PROXIES", raising=False)
    captured: list[uvicorn.Config] = []
    monkeypatch.setattr(cli, "_serve_all", lambda configs: captured.extend(configs))
    args = argparse.Namespace(
        host=None, port=None, no_migrate=False, open=False, data_dir=None, database_url=None
    )
    assert cli.cmd_run(args) == cli.EXIT_OK
    console, gateway = captured
    assert console.proxy_headers is True
    assert console.forwarded_allow_ips == "192.0.2.10"
    assert gateway.proxy_headers is False
