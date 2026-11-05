# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Packet inspector (T-012): capture through the real gateway, masking and unmasking, the ring
buffer and body caps, time boxes and filters, HAR export, replay through the SSRF guard, the
live stream, retention, and RBAC / tenant-isolation denials of every route.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from apiedge.app import create_app
from apiedge.db.base import make_engine, make_session_factory
from apiedge.db.models import (
    Api,
    ApiUpstream,
    AuditEvent,
    CapturedExchange,
    CaptureSession,
    Role,
    RoleAssignment,
    User,
)
from apiedge.gateway.app import create_gateway_app
from apiedge.security.passwords import hash_password
from tests.integration.conftest import PASSWORD, _seed
from tests.integration.test_gateway import Env as GatewayEnv
from tests.integration.test_gateway import (  # noqa: F401 - shared fixtures
    Upstream,
    _clear_hits,
    _settings,
    fake_resolver,
    upstreams,
)
from tests.integration.test_policies_gateway import set_policies

TOKEN = "Bearer sk-live-0123456789abcdef"  # nosec B105 - test value


@dataclass
class World:
    env: GatewayEnv
    admin: TestClient
    users: dict[str, int]

    @property
    def a(self) -> int:
        return self.env.tenant_a

    @property
    def b(self) -> int:
        return self.env.tenant_b

    def login(self, username: str) -> dict[str, str]:
        r = self.admin.post("/api/v1/auth/login", json={"username": username, "password": PASSWORD})
        assert r.status_code == 200, r.text
        self.admin.cookies.clear()
        return {"Authorization": f"Bearer {r.json()['access_token']}"}

    def base(self, tenant: int | None = None) -> str:
        return f"/api/v1/tenants/{tenant or self.a}/inspector"

    def session(self) -> Any:
        return make_session_factory(make_engine(self.env.settings.effective_database_url))()

    def gateway(self) -> TestClient:
        app = create_gateway_app(self.env.settings, resolver=fake_resolver)
        return TestClient(app, client=("203.0.113.9", 50000))


def flush(gw: TestClient) -> None:
    """Write the gateway's queued exchanges now (instead of waiting for the next tick)."""
    runtime = gw.app.state.runtime  # type: ignore[attr-defined]
    runtime.inspector.flush(runtime.session_factory, runtime.secret_box)


def reload_sessions(gw: TestClient) -> None:
    runtime = gw.app.state.runtime  # type: ignore[attr-defined]
    runtime.inspector.load(runtime.session_factory)


@pytest.fixture
def world(tmp_path: Path) -> Iterator[World]:
    settings = _settings(tmp_path, inspector_poll_interval_seconds=60)
    a, b, users = _seed(settings)
    env = GatewayEnv(settings, a, b)
    # A user of tenant A without any inspector permission.
    with make_session_factory(make_engine(settings.effective_database_url))() as s:
        consumer_role = s.scalars(select(Role).where(Role.name == "Consumer")).one()
        u = User(
            username="carol",
            tenant_id=a,
            password_hash=hash_password(PASSWORD),
            must_change_password=False,
        )
        s.add(u)
        s.flush()
        s.add(RoleAssignment(tenant_id=a, user_id=u.id, role_id=consumer_role.id))
        s.commit()
        users["carol"] = u.id
    with TestClient(create_app(settings)) as admin:
        yield World(env, admin, users)


def start(w: World, who: dict[str, str], api_id: int, **extra: Any) -> dict[str, Any]:
    r = w.admin.post(f"{w.base()}/sessions", json={"api_id": api_id, **extra}, headers=who)
    assert r.status_code == 201, r.text
    body: dict[str, Any] = r.json()
    return body


def exchanges(w: World, who: dict[str, str], query: str = "") -> list[dict[str, Any]]:
    r = w.admin.get(f"{w.base()}/exchanges?{query}", headers=who)
    assert r.status_code == 200, r.text
    out: list[dict[str, Any]] = r.json()
    return out


# --------------------------------------------------------------------------- capture + masking


def test_capture_mask_and_unmask(world: World, upstreams: dict[str, Upstream]) -> None:
    w = world
    api = w.env.add_api("/orders", [upstreams["a"].url])
    dev, alice = w.login("dev"), w.login("alice")
    cap = start(w, dev, api, mask_fields=["ssn"], duration_minutes=5)
    assert cap["state"] == "active" and cap["mask_fields"] == ["ssn"]

    with w.gateway() as gw:
        r = gw.post(
            "/acme/orders/items/7?apikey=k-secret-1&page=2",
            headers={"authorization": TOKEN, "cookie": "session=abc123", "x-trace": "t1"},
            json={"user": "jo", "password": "hunter2", "ssn": "123-45-6789"},
        )
        assert r.status_code == 200
        flush(gw)

    rows = exchanges(w, dev)
    assert len(rows) == 1
    row = rows[0]
    assert row["method"] == "POST" and row["path"] == "/acme/orders/items/7"
    assert row["status"] == 200 and row["upstream"] == upstreams["a"].url
    assert "apikey" not in json.dumps(row)  # summaries never carry the query string

    masked = w.admin.get(f"{w.base()}/exchanges/{row['id']}", headers=dev).json()
    assert masked["masked"] is True
    text = json.dumps(masked["exchange"])
    for secret in ("sk-live-0123456789abcdef", "abc123", "hunter2", "123-45-6789", "k-secret-1"):
        assert secret not in text, secret
    ex = masked["exchange"]
    headers = dict(ex["request"]["headers"])
    assert headers["authorization"] == "***" and headers["cookie"] == "***"
    assert headers["x-trace"] == "t1"
    assert json.loads(ex["request"]["body"]["text"]) == {
        "user": "jo",
        "password": "***",
        "ssn": "***",
    }
    assert "page=2" in ex["request"]["query"]
    assert ex["response"]["status"] == 200 and ex["response"]["source"] == "upstream"
    assert ex["timings"]["total_ms"] >= ex["timings"]["upstream_ms"] >= 0
    assert ex["upstream"] == upstreams["a"].url and ex["upstream_attempts"] == 1

    # The stored row is encrypted.
    with w.session() as s:
        stored = s.scalars(select(CapturedExchange.data)).one()
    assert "hunter2" not in stored and "sk-live" not in stored

    # Unmasked: needs inspector:unmask (APIDeveloper does not have it) and is audited.
    r = w.admin.get(f"{w.base()}/exchanges/{row['id']}?unmasked=true", headers=dev)
    assert r.status_code == 403
    r = w.admin.get(f"{w.base()}/exchanges/{row['id']}?unmasked=true", headers=alice)
    assert r.status_code == 200 and r.json()["masked"] is False
    raw = r.json()["exchange"]
    assert dict(raw["request"]["headers"])["authorization"] == TOKEN
    assert json.loads(raw["request"]["body"]["text"])["password"] == "hunter2"
    with w.session() as s:
        actions = list(s.scalars(select(AuditEvent.action)))
    assert "inspector.capture.start" in actions and "inspector.exchange.unmask" in actions


def test_policy_trace_is_recorded(world: World, upstreams: dict[str, Upstream]) -> None:
    w = world
    api = w.env.add_api("/orders", [upstreams["a"].url])
    set_policies(
        w.env,
        api,
        [
            {
                "id": "mock1",
                "type": "mock",
                "routes": ["/*"],
                "config": {"status": 201, "body": '{"ok":true}'},
            }
        ],
    )
    dev = w.login("dev")
    start(w, dev, api)
    with w.gateway() as gw:
        assert gw.get("/acme/orders/x").status_code == 201
        flush(gw)
    row = exchanges(w, dev)[0]
    ex = w.admin.get(f"{w.base()}/exchanges/{row['id']}", headers=dev).json()["exchange"]
    assert ex["response"]["source"] == "policy"
    assert [(t["policy_id"], t["outcome"]) for t in ex["trace"]] == [("mock1", "respond")]
    assert ex["request"]["upstream_headers"] is None and ex["upstream"] == ""
    # A request answered inside the gateway cannot be replayed.
    r = w.admin.post(f"{w.base()}/exchanges/{row['id']}/replay", headers=dev)
    assert r.status_code == 409


# --------------------------------------------------------------------------- limits


def test_ring_buffer_and_body_cap(world: World, upstreams: dict[str, Upstream]) -> None:
    w = world
    api = w.env.add_api("/orders", [upstreams["a"].url])
    dev = w.login("dev")
    cap = start(w, dev, api, max_exchanges=3, max_body_bytes=10)
    with w.gateway() as gw:
        for i in range(5):
            assert gw.post(f"/acme/orders/{i}", content=b"x" * 50).status_code == 200
        flush(gw)
    rows = exchanges(w, dev)
    assert [r["path"] for r in rows] == ["/acme/orders/4", "/acme/orders/3", "/acme/orders/2"]
    sessions = w.admin.get(f"{w.base()}/sessions", headers=dev).json()
    assert sessions[0]["id"] == cap["id"]
    assert sessions[0]["captured"] == 5 and sessions[0]["stored"] == 3
    ex = w.admin.get(f"{w.base()}/exchanges/{rows[0]['id']}", headers=dev).json()["exchange"]
    body = ex["request"]["body"]
    assert body["truncated"] is True and body["size"] == 50 and len(body["text"]) == 10
    assert ex["response"]["body"]["truncated"] is True
    # A partly captured body cannot be replayed.
    r = w.admin.post(f"{w.base()}/exchanges/{rows[0]['id']}/replay", headers=dev)
    assert r.status_code == 409


def test_limits_on_start(world: World, upstreams: dict[str, Upstream]) -> None:
    w = world
    api = w.env.add_api("/orders", [upstreams["a"].url])
    dev = w.login("dev")
    for bad in (
        {"duration_minutes": 61},
        {"max_exchanges": 1001},
        {"max_body_bytes": 64 * 1024 + 1},
        {"route": "/nope"},
        {"mask_fields": ["bad name"]},
        {"unknown": 1},
    ):
        r = w.admin.post(f"{w.base()}/sessions", json={"api_id": api, **bad}, headers=dev)
        assert r.status_code == 422, bad
    for _ in range(10):
        start(w, dev, api)
    r = w.admin.post(f"{w.base()}/sessions", json={"api_id": api}, headers=dev)
    assert r.status_code == 409


def test_route_consumer_stop_and_expiry(world: World, upstreams: dict[str, Upstream]) -> None:
    w = world
    api = w.env.add_api(
        "/orders", [upstreams["a"].url], [("GET", "/items/{id}"), ("GET", "/other")]
    )
    dev = w.login("dev")
    by_route = start(w, dev, api, route="/items/{id}")
    by_consumer = start(w, dev, api, consumer="key:mobile")
    with w.gateway() as gw:
        gw.get("/acme/orders/items/1")
        gw.get("/acme/orders/other")
        flush(gw)
        rows = exchanges(w, dev)
        assert [(r["session_id"], r["path"]) for r in rows] == [
            (by_route["id"], "/acme/orders/items/1")
        ]
        assert by_consumer["id"] not in {r["session_id"] for r in rows}

        r = w.admin.post(f"{w.base()}/sessions/{by_route['id']}/stop", headers=dev)
        assert r.status_code == 200 and r.json()["state"] == "stopped"
        reload_sessions(gw)
        gw.get("/acme/orders/items/2")
        flush(gw)
        assert len(exchanges(w, dev)) == 1

        # An expired session is no longer loaded, and a loaded one stops matching on expiry.
        timed = start(w, dev, api)
        reload_sessions(gw)
        runtime = gw.app.state.runtime  # type: ignore[attr-defined]
        loaded = [c for c in runtime.inspector.active if c.id == timed["id"]]
        assert loaded
        with w.session() as s:
            s.get(CaptureSession, timed["id"]).expires_at = datetime.now(UTC) - timedelta(seconds=1)
            s.commit()
        reload_sessions(gw)
        assert not any(c.id == timed["id"] for c in runtime.inspector.active)
        gw.get("/acme/orders/items/3")
        flush(gw)
    assert len(exchanges(w, dev)) == 1
    states = {s["id"]: s["state"] for s in w.admin.get(f"{w.base()}/sessions", headers=dev).json()}
    assert states[timed["id"]] == "expired"


def test_retention_and_delete(world: World, upstreams: dict[str, Upstream]) -> None:
    w = world
    api = w.env.add_api("/orders", [upstreams["a"].url])
    dev = w.login("dev")
    old = start(w, dev, api)
    keep = start(w, dev, api)
    with w.gateway() as gw:
        gw.get("/acme/orders/1")
        flush(gw)
        assert len(exchanges(w, dev)) == 2
        with w.session() as s:
            s.get(CaptureSession, old["id"]).stopped_at = datetime.now(UTC) - timedelta(hours=25)
            s.commit()
        runtime = gw.app.state.runtime  # type: ignore[attr-defined]
        assert runtime.inspector.purge(runtime.session_factory, 24) == 1
    rows = exchanges(w, dev)
    assert [r["session_id"] for r in rows] == [keep["id"]]
    r = w.admin.delete(f"{w.base()}/sessions/{keep['id']}", headers=dev)
    assert r.status_code == 204
    assert exchanges(w, dev) == []
    with w.session() as s:
        assert s.scalars(select(CapturedExchange)).all() == []


# --------------------------------------------------------------------------- HAR, replay, stream


def test_har_export(world: World, upstreams: dict[str, Upstream]) -> None:
    w = world
    api = w.env.add_api("/orders", [upstreams["a"].url])
    dev, alice = w.login("dev"), w.login("alice")
    cap = start(w, dev, api)
    with w.gateway() as gw:
        gw.get("/acme/orders/1?token=t-123", headers={"authorization": TOKEN})
        flush(gw)
    r = w.admin.get(f"{w.base()}/sessions/{cap['id']}/har", headers=dev)
    assert r.status_code == 200
    assert "attachment" in r.headers["content-disposition"]
    doc = r.json()
    assert doc["log"]["version"] == "1.2" and len(doc["log"]["entries"]) == 1
    e = doc["log"]["entries"][0]
    assert e["request"]["method"] == "GET" and e["response"]["status"] == 200
    assert "sk-live" not in r.text and "t-123" not in r.text
    assert e["_apiedge"]["upstream"] == upstreams["a"].url
    assert (
        w.admin.get(f"{w.base()}/sessions/{cap['id']}/har?unmasked=true", headers=dev).status_code
        == 403
    )
    r = w.admin.get(f"{w.base()}/sessions/{cap['id']}/har?unmasked=true", headers=alice)
    assert r.status_code == 200 and "sk-live" in r.text


def test_replay_goes_to_the_api_upstream_through_the_ssrf_guard(
    world: World, upstreams: dict[str, Upstream]
) -> None:
    w = world
    api = w.env.add_api("/orders", [upstreams["a"].url])
    dev, victor = w.login("dev"), w.login("victor")
    start(w, dev, api)
    with w.gateway() as gw:
        gw.post("/acme/orders/items/9?q=1", json={"n": 1}, headers={"authorization": TOKEN})
        flush(gw)
    row = exchanges(w, dev)[0]
    upstreams["a"].hits.clear()
    url = f"{w.base()}/exchanges/{row['id']}/replay"
    assert w.admin.post(url, headers=victor).status_code == 403  # Viewer: no inspector:capture
    r = w.admin.post(url, headers=dev)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["status"] == 200 and out["error"] is None and out["masked"] is True
    assert "sk-live" not in json.dumps(out)
    hit = upstreams["a"].hits[0]
    assert hit["method"] == "POST" and hit["path"] == "/items/9"
    sent = dict(hit["headers"])
    assert sent["x-apiedge-replay-of"] == row["request_id"]
    assert sent["authorization"] == TOKEN  # replayed as captured, never shown
    assert w.admin.post(url + "?unmasked=true", headers=dev).status_code == 403

    # The upstream now points at the cloud metadata service: refused by the SSRF guard.
    with w.session() as s:
        s.scalars(
            select(ApiUpstream).where(ApiUpstream.api_id == api)
        ).one().url = "http://169.254.169.254"
        s.commit()
    upstreams["a"].hits.clear()
    r = w.admin.post(url, headers=dev)
    assert r.status_code == 200 and r.json()["status"] is None
    assert "SSRF" in r.json()["error"]
    with w.session() as s:
        actions = list(s.scalars(select(AuditEvent.action)))
    assert actions.count("inspector.exchange.replay") == 2


def test_live_stream(world: World, upstreams: dict[str, Upstream]) -> None:
    w = world
    api = w.env.add_api("/orders", [upstreams["a"].url])
    dev = w.login("dev")
    start(w, dev, api)
    with w.gateway() as gw:
        gw.get("/acme/orders/1")
        gw.get("/acme/orders/2")
        flush(gw)
    first = exchanges(w, dev)[-1]["id"]
    r = w.admin.get(f"{w.base()}/exchanges/stream?timeout=1&after_id={first}", headers=dev)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    events = [e for e in r.text.split("\n\n") if e.startswith("id: ")]
    assert len(events) == 1 and "/acme/orders/2" in events[0]
    assert "event: end" in r.text


# --------------------------------------------------------------------------- RBAC + tenancy


def test_rbac_and_tenant_isolation(world: World, upstreams: dict[str, Upstream]) -> None:
    w = world
    api = w.env.add_api("/orders", [upstreams["a"].url])
    foreign_api = w.env.add_api("/foreign", [upstreams["a"].url], tenant=w.b)
    dev, victor, carol, bob = (w.login(u) for u in ("dev", "victor", "carol", "bob"))
    cap = start(w, dev, api)
    with w.gateway() as gw:
        gw.get("/acme/orders/1")
        flush(gw)
    ex_id = exchanges(w, dev)[0]["id"]
    sid = cap["id"]

    # No inspector permission at all: every route is denied.
    for method, path in (
        ("GET", "/sessions"),
        ("POST", "/sessions"),
        ("POST", f"/sessions/{sid}/stop"),
        ("DELETE", f"/sessions/{sid}"),
        ("GET", f"/sessions/{sid}/har"),
        ("GET", "/exchanges"),
        ("GET", "/exchanges/stream?timeout=1"),
        ("GET", f"/exchanges/{ex_id}"),
        ("POST", f"/exchanges/{ex_id}/replay"),
    ):
        body = {"api_id": api} if path == "/sessions" and method == "POST" else None
        r = w.admin.request(method, w.base() + path, json=body, headers=carol)
        assert r.status_code == 403, (method, path, r.status_code)

    # Viewer: may look, may not capture, stop, delete or unmask.
    assert w.admin.get(f"{w.base()}/sessions", headers=victor).status_code == 200
    assert w.admin.get(f"{w.base()}/exchanges/{ex_id}", headers=victor).status_code == 200
    assert (
        w.admin.post(f"{w.base()}/sessions", json={"api_id": api}, headers=victor).status_code
        == 403
    )
    assert w.admin.post(f"{w.base()}/sessions/{sid}/stop", headers=victor).status_code == 403
    assert w.admin.delete(f"{w.base()}/sessions/{sid}", headers=victor).status_code == 403
    r = w.admin.get(f"{w.base()}/exchanges/{ex_id}?unmasked=true", headers=victor)
    assert r.status_code == 403

    # Another tenant's admin: tenant A is invisible, A's objects do not exist in tenant B.
    assert w.admin.get(f"{w.base()}/sessions", headers=bob).status_code == 404
    b = w.base(w.b)
    assert w.admin.get(f"{b}/sessions", headers=bob).json() == []
    assert w.admin.get(f"{b}/exchanges", headers=bob).json() == []
    assert w.admin.get(f"{b}/exchanges/{ex_id}", headers=bob).status_code == 404
    assert w.admin.get(f"{b}/exchanges/{ex_id}?unmasked=true", headers=bob).status_code == 404
    assert w.admin.post(f"{b}/exchanges/{ex_id}/replay", headers=bob).status_code == 404
    assert w.admin.post(f"{b}/sessions/{sid}/stop", headers=bob).status_code == 404
    assert w.admin.delete(f"{b}/sessions/{sid}", headers=bob).status_code == 404
    assert w.admin.get(f"{b}/sessions/{sid}/har", headers=bob).status_code == 404
    r = w.admin.get(f"{b}/exchanges/stream?timeout=1", headers=bob)
    assert r.status_code == 200 and "id: " not in r.text
    # Tenant A cannot capture tenant B's API (it does not exist for A).
    r = w.admin.post(f"{w.base()}/sessions", json={"api_id": foreign_api}, headers=dev)
    assert r.status_code == 404
    # ... and a stored exchange moved to another session does not decrypt (bound by AAD).
    other = start(w, dev, api)
    with w.session() as s:
        s.get(CapturedExchange, ex_id).session_id = other["id"]
        s.commit()
    assert w.admin.get(f"{w.base()}/exchanges/{ex_id}", headers=dev).status_code == 409


def test_product_scoped_inspector_grant(world: World, upstreams: dict[str, Upstream]) -> None:
    """A user holding inspector:view for one product sees only that product's captures."""
    w = world
    mine = w.env.add_api("/mine", [upstreams["a"].url])
    other = w.env.add_api("/other", [upstreams["a"].url])
    dev = w.login("dev")
    start(w, dev, mine)
    start(w, dev, other)
    with w.gateway() as gw:
        gw.get("/acme/mine/1")
        gw.get("/acme/other/1")
        flush(gw)
    with w.session() as s:
        product = s.get(Api, mine).product_id
        viewer = s.scalars(select(Role).where(Role.name == "Viewer")).one()
        carol = w.users["carol"]
        s.add(RoleAssignment(tenant_id=w.a, user_id=carol, role_id=viewer.id, product_id=product))
        s.commit()
    carol_h = w.login("carol")
    rows = exchanges(w, carol_h)
    assert [r["path"] for r in rows] == ["/acme/mine/1"]
    other_ex = next(r for r in exchanges(w, dev) if r["path"] == "/acme/other/1")
    assert w.admin.get(f"{w.base()}/exchanges/{other_ex['id']}", headers=carol_h).status_code == 404
    assert len(w.admin.get(f"{w.base()}/sessions", headers=carol_h).json()) == 1
