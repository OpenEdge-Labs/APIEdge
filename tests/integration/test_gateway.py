# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""Gateway runtime (T-007): routing, path parameters and wildcards, lifecycle gating, tenant
separation, hot reload through the admin API, timeouts, retries, weighted load balancing,
header handling, body limits and the connect-time SSRF guard (DNS rebinding).

Upstreams are real HTTP servers on 127.0.0.1; only these tests allow that address in the SSRF
policy (``APIEDGE_SSRF_ALLOW_CIDRS=127.0.0.1/32``).
"""

from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from fastapi.testclient import TestClient
from sqlalchemy import select

from apiedge.app import create_app
from apiedge.config import Settings
from apiedge.db.base import make_engine, make_session_factory, run_migrations
from apiedge.db.models import Api, ApiRoute, ApiUpstream, Product, Tenant
from apiedge.gateway.app import create_gateway_app
from apiedge.gateway.bus import ConfigBus
from apiedge.security.crypto import ensure_key_file
from tests.integration.conftest import PASSWORD, _seed

GENERIC_502 = {"error": "bad_gateway", "message": "The upstream service could not be reached."}

# --------------------------------------------------------------------------- test upstreams


@dataclass
class Upstream:
    name: str
    fail_status: int | None = None
    port: int = 0
    hits: list[dict[str, Any]] = field(default_factory=list)
    server: uvicorn.Server | None = None
    thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    async def app(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        body = b""
        while True:
            msg = await receive()
            body += msg.get("body", b"")
            if not msg.get("more_body"):
                break
        path = scope["path"]
        headers = [(k.decode(), v.decode()) for k, v in scope["headers"]]
        self.hits.append({"path": path, "method": scope["method"], "headers": headers})
        if path.endswith("/slow"):
            await asyncio.sleep(1.0)
        status = self.fail_status or 200
        out = [(b"content-type", b"application/json"), (b"x-upstream", self.name.encode())]
        if path.endswith("/hop"):
            out += [
                (b"connection", b"x-internal"),
                (b"x-internal", b"secret"),
                (b"keep-alive", b"timeout=5"),
                (b"set-cookie", b"a=1"),
                (b"set-cookie", b"b=2"),
            ]
        if path.endswith("/redirect"):
            status = 302
            out.append((b"location", b"http://169.254.169.254/latest/meta-data/"))
        payload = {
            "upstream": self.name,
            "method": scope["method"],
            "path": path,
            "query": scope["query_string"].decode(),
            "headers": headers,
            "body": body.decode("latin-1"),
        }
        await send({"type": "http.response.start", "status": status, "headers": out})
        await send({"type": "http.response.body", "body": json.dumps(payload).encode()})

    def start(self) -> Upstream:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        self.port = sock.getsockname()[1]
        config = uvicorn.Config(self.app, lifespan="off", log_level="warning", interface="asgi3")
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(
            target=self.server.run, kwargs={"sockets": [sock]}, daemon=True
        )
        self.thread.start()
        deadline = time.monotonic() + 10
        while not self.server.started:
            assert time.monotonic() < deadline, "test upstream did not start"
            time.sleep(0.02)
        return self

    def stop(self) -> None:
        assert self.server is not None and self.thread is not None
        self.server.should_exit = True
        self.thread.join(timeout=10)


@pytest.fixture(scope="module")
def upstreams() -> Iterator[dict[str, Upstream]]:
    ups = {
        "a": Upstream("a").start(),
        "b": Upstream("b").start(),
        "failing": Upstream("failing", fail_status=503).start(),
    }
    yield ups
    for u in ups.values():
        u.stop()


@pytest.fixture(autouse=True)
def _clear_hits(upstreams: dict[str, Upstream]) -> None:
    for u in upstreams.values():
        u.hits.clear()


# Connect-time DNS answers (the database rows were "saved" when the names resolved elsewhere).
DNS = {
    "good.test": ["127.0.0.1"],
    "rebind.test": ["169.254.169.254"],  # now points at the cloud metadata endpoint
    "mixed.test": ["127.0.0.1", "10.0.0.7"],  # one private answer is enough to refuse
}


async def fake_resolver(host: str, port: int) -> Sequence[str]:
    return DNS.get(host, [])


# --------------------------------------------------------------------------- setup helpers


def _settings(tmp_path: Path, **extra: Any) -> Settings:
    settings = Settings(
        data_dir=tmp_path / "data",
        env="production",
        login_rate_limit_per_minute=1000,
        ssrf_allow_cidrs=["127.0.0.1/32"],
        gateway_reload_interval_seconds=0,
        **extra,
    )
    run_migrations(settings.effective_database_url)
    ensure_key_file(settings.effective_secret_key_file)
    return settings


@dataclass
class Env:
    settings: Settings
    tenant_a: int
    tenant_b: int

    def add_api(
        self,
        base_path: str,
        upstreams: Sequence[tuple[str, int] | str],
        routes: Sequence[tuple[str, str]] = (("GET,POST,PUT,DELETE", "/*"),),
        *,
        tenant: int | None = None,
        lifecycle: str = "published",
        product_lifecycle: str = "published",
        timeout_ms: int = 5000,
    ) -> int:
        engine = make_engine(self.settings.effective_database_url)
        tid = tenant or self.tenant_a
        with make_session_factory(engine)() as s:
            product = Product(tenant_id=tid, name=f"P{base_path}", lifecycle=product_lifecycle)
            s.add(product)
            s.flush()
            api = Api(
                tenant_id=tid,
                product_id=product.id,
                name=f"API{base_path}",
                version="v1",
                base_path=base_path,
                timeout_ms=timeout_ms,
                lifecycle=lifecycle,
            )
            s.add(api)
            s.flush()
            for i, up in enumerate(upstreams):
                url, weight = (up, 1) if isinstance(up, str) else up
                s.add(ApiUpstream(tenant_id=tid, api_id=api.id, position=i, url=url, weight=weight))
            for i, (methods, path) in enumerate(routes):
                s.add(
                    ApiRoute(tenant_id=tid, api_id=api.id, position=i, methods=methods, path=path)
                )
            s.commit()
            api_id = api.id
        engine.dispose()
        return api_id

    def gateway(self, bus: ConfigBus | None = None) -> TestClient:
        return TestClient(create_gateway_app(self.settings, bus, resolver=fake_resolver))


@pytest.fixture
def env(tmp_path: Path) -> Env:
    settings = _settings(tmp_path)
    a, b, _users = _seed(settings)
    return Env(settings, a, b)


def _wait_for(client: TestClient, path: str, status: int) -> Any:
    deadline = time.monotonic() + 10
    while True:
        r = client.get(path)
        if r.status_code == status:
            return r
        assert time.monotonic() < deadline, f"{path}: still {r.status_code}, wanted {status}"
        time.sleep(0.05)


# --------------------------------------------------------------------------- routing


def test_routes_to_upstream_with_base_path_and_query(
    env: Env, upstreams: dict[str, Upstream]
) -> None:
    env.add_api("/orders", [upstreams["a"].url + "/svc/"], [("GET", "/items/{id}")])
    with env.gateway() as gw:
        r = gw.get("/acme/orders/items/42?x=1&y=%20z")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["path"] == "/svc/items/42"
        assert body["query"] == "x=1&y=%20z"
        assert r.headers["x-upstream"] == "a"
        assert len(r.headers["x-request-id"]) == 32
        assert gw.get("/-/healthz").json() == {"status": "ok"}
        assert gw.get("/-/readyz").status_code == 200


def test_path_params_wildcards_and_methods(env: Env, upstreams: dict[str, Upstream]) -> None:
    env.add_api(
        "/shop",
        [upstreams["a"].url],
        [("GET", "/orders/{id}"), ("PUT,DELETE", "/orders/{id}"), ("GET", "/files/*")],
    )
    with env.gateway() as gw:
        assert gw.get("/acme/shop/orders/7").json()["path"] == "/orders/7"
        assert gw.delete("/acme/shop/orders/7").status_code == 200
        assert gw.get("/acme/shop/files").json()["path"] == "/files"
        assert gw.get("/acme/shop/files/a/b.txt").json()["path"] == "/files/a/b.txt"
        assert gw.get("/acme/shop/orders/7/extra").status_code == 404
        assert gw.get("/acme/shop/filesX").status_code == 404
        r = gw.post("/acme/shop/orders/7")
        assert r.status_code == 405
        assert r.headers["allow"] == "DELETE, GET, PUT"
        assert gw.get("/acme/other").status_code == 404
        assert gw.get("/acme/shopping/orders/7").status_code == 404  # segment-wise prefix


def test_longest_base_path_wins(env: Env, upstreams: dict[str, Upstream]) -> None:
    env.add_api("/v", [upstreams["a"].url])
    env.add_api("/v/inner", [upstreams["b"].url])
    with env.gateway() as gw:
        assert gw.get("/acme/v/inner/x").headers["x-upstream"] == "b"
        assert gw.get("/acme/v/other").headers["x-upstream"] == "a"


def test_dot_segments_are_refused(env: Env, upstreams: dict[str, Upstream]) -> None:
    env.add_api("/orders", [upstreams["a"].url + "/svc"])
    with env.gateway() as gw:
        r = gw.get("/acme/orders/%2e%2e/admin")
        assert r.status_code == 400
        assert gw.get("/acme/orders/x/%2E/y").status_code == 400
    assert upstreams["a"].hits == []


def test_redirects_are_passed_through_not_followed(
    env: Env, upstreams: dict[str, Upstream]
) -> None:
    env.add_api("/r", [upstreams["a"].url])
    with env.gateway() as gw:
        r = gw.get("/acme/r/redirect", follow_redirects=False)
        assert r.status_code == 302
        assert len(upstreams["a"].hits) == 1


# --------------------------------------------------------------------------- lifecycle


def test_lifecycle_gating(env: Env, upstreams: dict[str, Upstream]) -> None:
    url = upstreams["a"].url
    env.add_api("/draft", [url], lifecycle="draft")
    env.add_api("/pub", [url])
    env.add_api("/dep", [url], lifecycle="deprecated")
    env.add_api("/depprod", [url], product_lifecycle="deprecated")
    env.add_api("/ret", [url], lifecycle="retired")
    env.add_api("/retprod", [url], product_lifecycle="retired")
    env.add_api("/draftprod", [url], product_lifecycle="draft")
    with env.gateway() as gw:
        assert gw.get("/acme/draft/x").status_code == 404
        r = gw.get("/acme/pub/x")
        assert r.status_code == 200 and "deprecation" not in r.headers
        for path in ("/acme/dep/x", "/acme/depprod/x"):
            r = gw.get(path)
            assert r.status_code == 200 and r.headers["deprecation"] == "true"
        for path in ("/acme/ret/x", "/acme/retprod/x"):
            r = gw.get(path)
            assert r.status_code == 410
            assert r.json()["error"] == "api_retired"
        assert gw.get("/acme/draftprod/x").status_code == 200
    assert {h["path"] for h in upstreams["a"].hits} == {"/x"}
    assert len(upstreams["a"].hits) == 4


# --------------------------------------------------------------------------- tenants


def test_tenant_separation(env: Env, upstreams: dict[str, Upstream]) -> None:
    env.add_api("/orders", [upstreams["a"].url])
    env.add_api("/orders", [upstreams["b"].url], tenant=env.tenant_b)
    env.add_api("/only-b", [upstreams["b"].url], tenant=env.tenant_b)
    with env.gateway() as gw:
        assert gw.get("/acme/orders/1").headers["x-upstream"] == "a"
        assert gw.get("/globex/orders/1").headers["x-upstream"] == "b"
        assert gw.get("/acme/only-b/1").status_code == 404
        assert gw.get("/nobody/orders/1").status_code == 404
        assert gw.get("/").status_code == 404


def test_inactive_tenant_is_not_served(env: Env, upstreams: dict[str, Upstream]) -> None:
    env.add_api("/orders", [upstreams["a"].url])
    engine = make_engine(env.settings.effective_database_url)
    with make_session_factory(engine)() as s:
        s.scalars(select(Tenant).where(Tenant.id == env.tenant_a)).one().is_active = False
        s.commit()
    engine.dispose()
    with env.gateway() as gw:
        assert gw.get("/acme/orders/1").status_code == 404


# --------------------------------------------------------------------------- hot reload


def test_hot_reload_through_admin_api(env: Env, upstreams: dict[str, Upstream]) -> None:
    bus = ConfigBus()
    with TestClient(create_app(env.settings, bus)) as admin, env.gateway(bus) as gw:
        r = admin.post("/api/v1/auth/login", json={"username": "alice", "password": PASSWORD})
        h = {"Authorization": f"Bearer {r.json()['access_token']}"}
        admin.cookies.clear()
        base = f"/api/v1/tenants/{env.tenant_a}/products"
        pid = admin.post(base, json={"name": "Shop"}, headers=h).json()["id"]
        r = admin.post(
            f"{base}/{pid}/apis",
            json={
                "name": "Live",
                "base_path": "/live",
                "upstreams": [{"url": upstreams["a"].url}],
                "routes": [{"methods": ["GET"], "path": "/*"}],
            },
            headers=h,
        )
        assert r.status_code == 201, r.text
        api = r.json()["id"]
        assert gw.get("/acme/live/x").status_code == 404  # draft
        lifecycle = f"{base}/{pid}/apis/{api}/lifecycle"
        assert admin.post(lifecycle, json={"lifecycle": "published"}, headers=h).status_code == 200
        _wait_for(gw, "/acme/live/x", 200)
        r = admin.patch(
            f"{base}/{pid}/apis/{api}", json={"upstreams": [{"url": upstreams["b"].url}]}, headers=h
        )
        assert r.status_code == 200, r.text
        deadline = time.monotonic() + 10
        while gw.get("/acme/live/x").headers.get("x-upstream") != "b":
            assert time.monotonic() < deadline
            time.sleep(0.05)
        assert admin.post(lifecycle, json={"lifecycle": "deprecated"}, headers=h).status_code == 200
        deadline = time.monotonic() + 10
        while "deprecation" not in gw.get("/acme/live/x").headers:
            assert time.monotonic() < deadline
            time.sleep(0.05)
        assert admin.post(lifecycle, json={"lifecycle": "retired"}, headers=h).status_code == 200
        _wait_for(gw, "/acme/live/x", 410)


def test_reload_failure_keeps_previous_config(env: Env, upstreams: dict[str, Upstream]) -> None:
    env.add_api("/orders", [upstreams["a"].url])
    bus = ConfigBus()
    app = create_gateway_app(env.settings, bus, resolver=fake_resolver)
    runtime = app.state.runtime
    with TestClient(app) as gw:
        version = runtime.version
        runtime._factory = None  # every reload now fails
        bus.publish()
        time.sleep(0.2)
        assert runtime.version == version
        assert gw.get("/acme/orders/1").status_code == 200


# --------------------------------------------------------------------------- timeouts, retries


def test_timeout_answers_504_without_details(
    tmp_path: Path, upstreams: dict[str, Upstream]
) -> None:
    settings = _settings(tmp_path, gateway_retries=0)
    a, b, _ = _seed(settings)
    env = Env(settings, a, b)
    env.add_api("/slow", [upstreams["a"].url], timeout_ms=200)
    with env.gateway() as gw:
        start = time.monotonic()
        r = gw.get("/acme/slow/slow")
        assert time.monotonic() - start < 0.95  # the upstream would take 1 s
        assert r.status_code == 504
        body = r.json()
        assert body["error"] == "gateway_timeout"
        assert set(body) == {"error", "message", "request_id"}
        assert "Timeout" not in r.text and "127.0.0.1" not in r.text


def test_idempotent_requests_retry_another_upstream(
    env: Env, upstreams: dict[str, Upstream]
) -> None:
    env.add_api("/svc", [(upstreams["failing"].url, 5), (upstreams["a"].url, 1)])
    with env.gateway() as gw:
        r = gw.get("/acme/svc/x")
        assert r.status_code == 200 and r.headers["x-upstream"] == "a"
        # POST is not idempotent: the 503 from the first upstream is returned as is.
        r = gw.post("/acme/svc/x", content=b"once")
        assert r.status_code == 503 and r.headers["x-upstream"] == "failing"
    assert [h["method"] for h in upstreams["failing"].hits] == ["GET", "POST"]


def test_connection_failures_retry_for_every_method(
    env: Env, upstreams: dict[str, Upstream]
) -> None:
    port = upstreams["a"].port
    env.add_api("/svc", [(f"http://rebind.test:{port}", 5), (upstreams["a"].url, 1)])
    with env.gateway() as gw:
        r = gw.post("/acme/svc/x", content=b"payload")
        assert r.status_code == 200
        assert r.json()["body"] == "payload"
    assert len(upstreams["a"].hits) == 1


def test_no_retry_when_disabled(tmp_path: Path, upstreams: dict[str, Upstream]) -> None:
    settings = _settings(tmp_path, gateway_retries=0)
    a, b, _ = _seed(settings)
    env = Env(settings, a, b)
    env.add_api("/svc", [(upstreams["failing"].url, 5), (upstreams["a"].url, 1)])
    with env.gateway() as gw:
        assert gw.get("/acme/svc/x").status_code == 503
    assert upstreams["a"].hits == []


def test_weighted_load_balancing(env: Env, upstreams: dict[str, Upstream]) -> None:
    env.add_api("/lb", [(upstreams["a"].url, 3), (upstreams["b"].url, 1)])
    with env.gateway() as gw:
        seen = [gw.get("/acme/lb/x").headers["x-upstream"] for _ in range(8)]
    assert seen.count("a") == 6 and seen.count("b") == 2
    assert seen[:4].count("b") == 1  # spread out, not bunched


# --------------------------------------------------------------------------- headers, body


def test_header_handling(env: Env, upstreams: dict[str, Upstream]) -> None:
    env.add_api("/orders", [upstreams["a"].url])
    with env.gateway() as gw:
        r = gw.get(
            "/acme/orders/hop",
            headers={
                "Connection": "x-drop-me",
                "X-Drop-Me": "1",
                "Keep-Alive": "timeout=5",
                "TE": "trailers",
                "Proxy-Authorization": "Basic Zm9vOmJhcg==",
                "X-Forwarded-For": "1.2.3.4",
                "X-Forwarded-Host": "evil.example",
                "X-Request-ID": "trace-123",
                "Authorization": "Bearer end-to-end",
            },
        )
    assert r.status_code == 200
    sent = {k: v for k, v in r.json()["headers"]}
    for name in ("x-drop-me", "keep-alive", "te", "proxy-authorization"):
        assert name not in sent
    assert sent["authorization"] == "Bearer end-to-end"
    assert sent["x-forwarded-for"] == "1.2.3.4, testclient"
    assert sent["x-forwarded-host"] == "testserver"
    assert sent["x-forwarded-proto"] == "http"
    assert sent["x-forwarded-prefix"] == "/acme/orders"
    assert sent["x-request-id"] == "trace-123"
    assert sent["host"] == f"127.0.0.1:{upstreams['a'].port}"
    assert r.headers["x-request-id"] == "trace-123"
    for name in ("x-internal", "keep-alive"):
        assert name not in r.headers
    assert r.headers.get_list("set-cookie") == ["a=1", "b=2"]


def test_invalid_request_id_is_replaced(env: Env, upstreams: dict[str, Upstream]) -> None:
    env.add_api("/orders", [upstreams["a"].url])
    with env.gateway() as gw:
        r = gw.get("/acme/orders/x", headers={"X-Request-ID": "bad id\twith junk"})
    assert len(r.headers["x-request-id"]) == 32


def test_body_size_limit(tmp_path: Path, upstreams: dict[str, Upstream]) -> None:
    settings = _settings(tmp_path, gateway_max_request_body_bytes=1024)
    a, b, _ = _seed(settings)
    env = Env(settings, a, b)
    env.add_api("/up", [upstreams["a"].url])
    with env.gateway() as gw:
        assert gw.post("/acme/up/x", content=b"x" * 1024).status_code == 200
        r = gw.post("/acme/up/x", content=b"x" * 1025)
        assert r.status_code == 413

        def chunks() -> Iterator[bytes]:  # no Content-Length: counted while streaming
            for _ in range(3):
                yield b"y" * 512

        assert gw.post("/acme/up/x", content=chunks()).status_code == 413
    assert len(upstreams["a"].hits) == 1


# --------------------------------------------------------------------------- SSRF at connect time


@pytest.mark.parametrize(
    "upstream",
    [
        "http://rebind.test:{port}",  # DNS now answers the metadata address
        "http://mixed.test:{port}",  # one of the answers is private
        "http://10.0.0.5:{port}",  # saved under an older, looser policy
        "http://unresolvable.test:{port}",
    ],
)
def test_connect_time_ssrf_guard(env: Env, upstreams: dict[str, Upstream], upstream: str) -> None:
    env.add_api("/x", [upstream.format(port=upstreams["a"].port)])
    with env.gateway() as gw:
        r = gw.get("/acme/x/y")
    assert r.status_code == 502
    body = r.json()
    assert {k: body[k] for k in ("error", "message")} == GENERIC_502
    assert "test" not in r.text and "10.0.0" not in r.text
    assert upstreams["a"].hits == []


def test_host_name_is_kept_when_connecting_to_the_checked_address(
    env: Env, upstreams: dict[str, Upstream]
) -> None:
    port = upstreams["a"].port
    env.add_api("/named", [f"http://good.test:{port}/base"])
    with env.gateway() as gw:
        r = gw.get("/acme/named/x")
    assert r.status_code == 200
    sent = {k: v for k, v in r.json()["headers"]}
    assert sent["host"] == f"good.test:{port}"
    assert r.json()["path"] == "/base/x"
