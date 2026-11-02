# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""T-002: HTTP hardening of the console / admin API."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi import Body, FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel
from starlette.routing import BaseRoute

from apiedge.app import create_app
from apiedge.config import Settings
from apiedge.security.middleware import CSRF_COOKIE_NAME


class Login(BaseModel):
    username: str
    password: str


def _app(settings: Settings) -> FastAPI:
    app = create_app(settings)

    async def echo(payload: dict[str, object] = Body(...)) -> dict[str, object]:  # noqa: B008
        return payload

    async def boom() -> None:
        raise RuntimeError("database password=hunter2 exploded")

    async def login(body: Login) -> dict[str, str]:
        return {"user": body.username}

    app.add_api_route("/api/v1/_t/echo", echo, methods=["POST"])
    app.add_api_route("/api/v1/_t/boom", boom, methods=["GET"])
    app.add_api_route("/api/v1/_t/login", login, methods=["POST"])
    # The console is mounted at "/" and would shadow routes added later: move ours first.
    routes: list[BaseRoute] = app.router.routes
    ours = [r for r in routes if getattr(r, "path", "").startswith("/api/v1/_t/")]
    app.router.routes[:] = ours + [r for r in routes if r not in ours]
    return app


@pytest.fixture
def client(settings: Settings) -> TestClient:
    return TestClient(_app(settings), raise_server_exceptions=False)


def test_security_headers_on_console_and_api(client: TestClient) -> None:
    for path in ("/", "/healthz", "/api/v1/openapi.json"):
        h = client.get(path).headers
        assert h["x-content-type-options"] == "nosniff"
        assert h["cross-origin-embedder-policy"] == "require-corp"
        assert h["x-frame-options"] == "DENY"
        assert h["referrer-policy"] == "no-referrer"
        csp = h["content-security-policy"]
        assert "frame-ancestors 'none'" in csp and "script-src 'self'" in csp
        assert "unsafe-inline" not in csp
        assert "x-request-id" in h
        assert "server" not in h or "uvicorn" not in h["server"].lower()
        assert "strict-transport-security" not in h  # plain HTTP: no HSTS
    assert client.get("/healthz").headers["cache-control"] == "no-store"


def test_hsts_over_https(settings: Settings) -> None:
    with TestClient(_app(settings), base_url="https://testserver") as c:
        assert c.get("/healthz").headers["strict-transport-security"].startswith("max-age=31536000")


def test_request_id_propagation(client: TestClient) -> None:
    assert (
        client.get("/healthz", headers={"X-Request-ID": "abc-123"}).headers["x-request-id"]
        == "abc-123"
    )
    forged = client.get("/healthz", headers={"X-Request-ID": "bad\r\nid<script>"})
    assert forged.headers["x-request-id"] != "bad\r\nid<script>"
    assert len(forged.headers["x-request-id"]) == 32


def test_errors_never_leak_stack_traces_in_production(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.ERROR, logger="apiedge.security"):
        r = client.get("/api/v1/_t/boom")
    assert r.status_code == 500
    body = r.json()
    assert body == {"detail": "Internal server error", "request_id": r.headers["x-request-id"]}
    assert "Traceback" not in r.text and "hunter2" not in r.text and "RuntimeError" not in r.text
    assert r.headers["x-content-type-options"] == "nosniff"  # headers even on 500
    assert any(rec.exc_info for rec in caplog.records)  # logged server-side


def test_development_shows_error_type_but_no_traceback(tmp_path: Path) -> None:
    s = Settings(data_dir=tmp_path, env="development")
    with TestClient(_app(s), raise_server_exceptions=False) as c:
        body = c.get("/api/v1/_t/boom").json()
    assert body["error"].startswith("RuntimeError")
    assert "Traceback" not in json.dumps(body)


def test_validation_errors_do_not_echo_input(client: TestClient) -> None:
    r = client.post("/api/v1/_t/login", json={"password": "hunter2"})
    assert r.status_code == 422
    assert "hunter2" not in r.text
    assert r.json()["detail"][0]["loc"] == ["body", "username"]


def test_body_size_limit(tmp_path: Path) -> None:
    s = Settings(data_dir=tmp_path, max_request_body_bytes=1024)
    with TestClient(_app(s)) as c:
        assert c.post("/api/v1/_t/echo", json={"a": "x" * 100}).status_code == 200
        r = c.post("/api/v1/_t/echo", json={"a": "x" * 2000})
        assert r.status_code == 413
        assert r.headers["x-frame-options"] == "DENY"

        # Chunked upload without Content-Length is counted while streaming.
        def chunks() -> Iterator[bytes]:
            yield b'{"a": "'
            for _ in range(10):
                yield b"x" * 200
            yield b'"}'

        r = c.post(
            "/api/v1/_t/echo", content=chunks(), headers={"Content-Type": "application/json"}
        )
        assert r.status_code == 413
        assert (
            c.post("/api/v1/_t/echo", content=b"{}", headers={"Content-Length": "abc"}).status_code
            == 400
        )


def test_csrf_cookie_issued(client: TestClient) -> None:
    r = client.get("/healthz")
    cookie = r.headers["set-cookie"]
    assert cookie.startswith(f"{CSRF_COOKIE_NAME}=")
    assert "SameSite=Strict" in cookie and "HttpOnly" not in cookie
    # Not re-issued once the client has it.
    assert "set-cookie" not in client.get("/healthz").headers


def test_csrf_enforced_for_cookie_authenticated_requests(settings: Settings) -> None:
    with TestClient(_app(settings)) as c:
        c.get("/healthz")  # obtain CSRF cookie
        token = c.cookies[CSRF_COOKIE_NAME]
        c.cookies.set("apiedge_session", "s")
        assert c.post("/api/v1/_t/echo", json={}).status_code == 403  # no header
        bad = c.post("/api/v1/_t/echo", json={}, headers={"X-CSRF-Token": "nope"})
        assert bad.status_code == 403
        ok = c.post("/api/v1/_t/echo", json={"a": 1}, headers={"X-CSRF-Token": token})
        assert ok.status_code == 200
        evil = c.post(
            "/api/v1/_t/echo",
            json={},
            headers={"X-CSRF-Token": token, "Origin": "https://evil.example"},
        )
        assert evil.status_code == 403
        same = c.post(
            "/api/v1/_t/echo",
            json={},
            headers={"X-CSRF-Token": token, "Origin": "http://testserver"},
        )
        assert same.status_code == 200


def test_bearer_clients_without_cookies_are_not_csrf_checked(settings: Settings) -> None:
    with TestClient(_app(settings)) as c:
        r = c.post("/api/v1/_t/echo", json={"a": 1}, headers={"Authorization": "Bearer x"})
    assert r.status_code == 200


def test_cors_closed_by_default(client: TestClient) -> None:
    r = client.options(
        "/api/v1/_t/echo",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
    )
    assert "access-control-allow-origin" not in r.headers


def test_cors_allow_list(tmp_path: Path) -> None:
    s = Settings(data_dir=tmp_path, cors_allow_origins=["https://portal.example.com"])
    with TestClient(_app(s)) as c:
        pre = {"Access-Control-Request-Method": "POST"}
        ok = c.options("/api/v1/_t/echo", headers={"Origin": "https://portal.example.com", **pre})
        assert ok.headers["access-control-allow-origin"] == "https://portal.example.com"
        assert ok.headers["access-control-allow-credentials"] == "true"
        bad = c.options("/api/v1/_t/echo", headers={"Origin": "https://evil.example", **pre})
        assert "access-control-allow-origin" not in bad.headers
        # Allow-listed origins also pass the CSRF origin check.
        c.get("/healthz")
        c.cookies.set("apiedge_session", "s")
        r = c.post(
            "/api/v1/_t/echo",
            json={},
            headers={
                "Origin": "https://portal.example.com",
                "X-CSRF-Token": c.cookies[CSRF_COOKIE_NAME],
            },
        )
        assert r.status_code == 200


def test_docs_csp_relaxed_only_in_development(tmp_path: Path) -> None:
    with TestClient(create_app(Settings(data_dir=tmp_path, env="development"))) as c:
        assert "cdn.jsdelivr.net" in c.get("/api/docs").headers["content-security-policy"]
        assert "cdn.jsdelivr.net" not in c.get("/").headers["content-security-policy"]
