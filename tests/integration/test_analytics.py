# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Analytics (T-013): gateway traffic is measured, flushed to the analytics tables and read back
through the admin API (summary and CSV export) with RBAC, product scoping and tenant isolation;
the Prometheus endpoint is token-protected.
"""

# ruff: noqa: F811 - pytest fixtures imported from test_gateway are parameters here

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import select

from apiedge.analytics.metrics import MetricsCollector
from apiedge.app import create_app
from apiedge.config import Settings
from apiedge.db.base import make_engine, make_session_factory
from apiedge.db.models import AnalyticsBucket, Api, Role, RoleAssignment, User
from apiedge.gateway.app import create_gateway_app
from apiedge.security.passwords import hash_password
from tests.integration.conftest import PASSWORD
from tests.integration.test_gateway import (  # noqa: F401 - fixtures
    Env,
    Upstream,
    _clear_hits,
    env,
    fake_resolver,
    upstreams,
)

TOKEN = "prometheus-scrape-token-0123456789"


def _window() -> dict[str, str]:
    """An explicit range that cannot miss the traffic just sent.

    The default range ends at "now" truncated to the second and is end-exclusive on minute
    buckets, so a query in the first second of the minute the traffic landed in would miss it.
    Ending the window two minutes ahead (still a 60-second step) makes the tests independent of
    where the clock is within the minute.
    """
    now = datetime.now(UTC)
    return {
        "start": (now - timedelta(minutes=58)).isoformat(),
        "end": (now + timedelta(minutes=2)).isoformat(),
    }


def _user(
    settings: Settings, name: str, tenant: int, role: str, product: int | None = None
) -> None:
    engine = make_engine(settings.effective_database_url)
    with make_session_factory(engine)() as s:
        role_id = s.scalars(select(Role.id).where(Role.name == role)).one()
        u = User(
            username=name,
            tenant_id=tenant,
            password_hash=hash_password(PASSWORD),
            must_change_password=False,
        )
        s.add(u)
        s.flush()
        s.add(RoleAssignment(tenant_id=tenant, user_id=u.id, role_id=role_id, product_id=product))
        s.commit()
    engine.dispose()


def _product_of(settings: Settings, api_id: int) -> int:
    engine = make_engine(settings.effective_database_url)
    with make_session_factory(engine)() as s:
        product_id = s.get(Api, api_id).product_id  # type: ignore[union-attr]
    engine.dispose()
    return int(product_id)


def _login(client: TestClient, username: str) -> dict[str, str]:
    r = client.post("/api/v1/auth/login", json={"username": username, "password": PASSWORD})
    assert r.status_code == 200, r.text
    client.cookies.clear()
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _traffic(env: Env, ups: dict[str, Upstream]) -> tuple[int, int, int]:
    """Two tenant-A APIs and one tenant-B API with known traffic; returns their ids."""
    orders = env.add_api("/orders", [ups["a"].url], [("GET", "/items/{id}")])
    billing = env.add_api("/billing", [ups["failing"].url], [("GET", "/*")])
    other = env.add_api("/orders", [ups["b"].url], [("GET", "/*")], tenant=env.tenant_b)
    with env.gateway() as gw:  # leaving the block flushes the collector
        for i in range(3):
            assert gw.get(f"/acme/orders/items/{i}").status_code == 200
        assert gw.post("/acme/orders/items/1").status_code == 405
        assert gw.get("/acme/orders/nope").status_code == 404
        assert gw.get("/acme/billing/x").status_code == 503
        assert gw.get("/globex/orders/x").status_code == 200
        assert gw.get("/acme/unknown").status_code == 404  # no API: not attributed
    return orders, billing, other


def test_traffic_is_recorded_and_summarized(env: Env, upstreams: dict[str, Upstream]) -> None:
    orders, billing, _other = _traffic(env, upstreams)
    with TestClient(create_app(env.settings)) as client:
        h = _login(client, "alice")
        win = _window()
        r = client.get(f"/api/v1/tenants/{env.tenant_a}/analytics/summary", params=win, headers=h)
        assert r.status_code == 200, r.text
        data = r.json()
        totals = data["totals"]
        assert totals["requests"] == 6
        assert totals["client_errors"] == 2 and totals["server_errors"] == 1
        assert totals["errors"] == 3 and totals["error_rate"] == 0.5
        assert totals["latency_p50_ms"] is not None
        assert totals["latency_p50_ms"] <= totals["latency_p95_ms"] <= totals["latency_p99_ms"]
        assert totals["latency_p99_ms"] <= totals["latency_max_ms"]
        assert totals["bytes_out"] > 0
        assert data["step_seconds"] == 60
        assert sum(p["requests"] for p in data["series"]) == 6
        assert {s["status"]: s["requests"] for s in data["status_codes"]} == {
            200: 3,
            404: 1,
            405: 1,
            503: 1,
        }
        top = {a["api_id"]: a for a in data["top_apis"]}
        assert set(top) == {orders, billing}
        assert top[orders]["requests"] == 5 and top[orders]["name"] == "API/orders v1"
        assert data["top_apis"][0]["api_id"] == orders  # sorted by traffic
        assert data["top_consumers"] == [
            {
                "consumer": "",
                "requests": 6,
                "errors": 3,
                "error_rate": 0.5,
                "latency_p50_ms": totals["latency_p50_ms"],
                "latency_p95_ms": totals["latency_p95_ms"],
                "latency_p99_ms": totals["latency_p99_ms"],
            }
        ]

        # filters
        base = f"/api/v1/tenants/{env.tenant_a}/analytics/summary"
        only = client.get(base, params={**win, "api_id": billing}, headers=h).json()
        assert only["totals"]["requests"] == 1 and only["totals"]["server_errors"] == 1
        nobody = client.get(base, params={**win, "consumer": "nobody"}, headers=h).json()
        assert nobody["totals"]["requests"] == 0
        anonymous = client.get(base, params={**win, "consumer": ""}, headers=h).json()
        assert anonymous["totals"]["requests"] == 6
        past = (datetime.now(UTC) - timedelta(days=2)).isoformat()
        r = client.get(base, params={"end": past}, headers=h)
        assert r.json()["totals"]["requests"] == 0

    engine = make_engine(env.settings.effective_database_url)
    with make_session_factory(engine)() as s:
        routes = set(s.scalars(select(AnalyticsBucket.route)))
    engine.dispose()
    assert routes == {"/items/{id}", "", "/*"}  # configured route, unmatched path, wildcard


def test_rbac_product_scope_and_tenant_isolation(env: Env, upstreams: dict[str, Upstream]) -> None:
    orders, billing, _other = _traffic(env, upstreams)
    _user(env.settings, "carl", env.tenant_a, "Consumer")  # no analytics:view
    _user(env.settings, "pat", env.tenant_a, "Viewer", product=_product_of(env.settings, billing))
    url = f"/api/v1/tenants/{env.tenant_a}/analytics"
    with TestClient(create_app(env.settings)) as client:
        for path in ("/summary", "/export.csv"):
            assert client.get(url + path).status_code == 401
            assert client.get(url + path, headers=_login(client, "carl")).status_code == 403
            # another tenant's admin cannot learn the tenant exists
            assert client.get(url + path, headers=_login(client, "bob")).status_code == 404

        # tenant B sees only its own traffic
        bob = _login(client, "bob")
        win = _window()
        r = client.get(f"/api/v1/tenants/{env.tenant_b}/analytics/summary", params=win, headers=bob)
        assert r.json()["totals"]["requests"] == 1

        # Viewer (tenant-wide) and a product-scoped Viewer
        victor = _login(client, "victor")
        assert client.get(url + "/summary", params=win, headers=victor).status_code == 200
        pat = _login(client, "pat")
        data = client.get(url + "/summary", params=win, headers=pat).json()
        assert data["totals"]["requests"] == 1
        assert [a["api_id"] for a in data["top_apis"]] == [billing]
        orders_product = _product_of(env.settings, orders)
        scoped = client.get(
            f"{url}/summary", params={**win, "product_id": orders_product}, headers=pat
        ).json()
        assert scoped["totals"]["requests"] == 0  # outside the grant: nothing disclosed
        by_api = client.get(f"{url}/summary", params={**win, "api_id": orders}, headers=pat)
        assert by_api.json()["top_apis"] == []
        text = client.get(url + "/export.csv", params=win, headers=pat).text
        assert len(list(csv.reader(io.StringIO(text)))) == 2  # header + the billing row


def test_csv_export_and_audit(env: Env, upstreams: dict[str, Upstream]) -> None:
    orders, _billing, _other = _traffic(env, upstreams)
    with TestClient(create_app(env.settings)) as client:
        h = _login(client, "alice")
        url = f"/api/v1/tenants/{env.tenant_a}/analytics/export.csv"
        r = client.get(url, params={**_window(), "api_id": orders}, headers=h)
        assert r.status_code == 200, r.text
        assert r.headers["content-type"].startswith("text/csv")
        assert r.headers["content-disposition"].startswith("attachment;")
        assert r.headers["cache-control"] == "no-store"
        rows = list(csv.DictReader(io.StringIO(r.text)))
        assert sum(int(row["requests"]) for row in rows) == 5
        assert {row["status"] for row in rows} == {"200", "404", "405"}
        assert {row["api"] for row in rows} == {"API/orders v1"}
        assert all(row["time_utc"].endswith("Z") for row in rows)
        events = client.get(f"/api/v1/tenants/{env.tenant_a}/audit?limit=20", headers=h).json()
        items = events["items"] if isinstance(events, dict) else events
        assert any(e["action"] == "analytics.export" for e in items)


def test_time_range_validation(env: Env) -> None:
    with TestClient(create_app(env.settings)) as client:
        h = _login(client, "alice")
        url = f"/api/v1/tenants/{env.tenant_a}/analytics/summary"
        now = datetime.now(UTC)
        bad = [
            {"start": now.isoformat(), "end": (now - timedelta(minutes=1)).isoformat()},
            {"start": (now - timedelta(days=32)).isoformat(), "end": now.isoformat()},
            {"start": "yesterday"},
            {"api_id": "0"},
            {"consumer": "x" * 129},
        ]
        for params in bad:
            assert client.get(url, params=params, headers=h).status_code == 422, params
        week = client.get(
            url, params={"start": (now - timedelta(days=7)).isoformat()}, headers=h
        ).json()
        assert week["step_seconds"] == 10800 and week["series"] == []


def test_prometheus_metrics_endpoint(env: Env, upstreams: dict[str, Upstream]) -> None:
    env.add_api("/orders", [upstreams["a"].url], [("GET", "/*")])
    metrics = MetricsCollector()
    gateway = create_gateway_app(env.settings, resolver=fake_resolver, metrics=metrics)
    with TestClient(gateway) as gw:
        assert gw.get("/acme/orders/1").status_code == 200
        assert gw.get("/nobody/x").status_code == 404

    with TestClient(create_app(env.settings, metrics=metrics)) as client:
        assert client.get("/metrics").status_code == 404  # off without a token

    settings = env.settings.model_copy(update={"metrics_token": SecretStr(TOKEN)})
    with TestClient(create_app(settings, metrics=metrics)) as client:
        assert client.get("/metrics").status_code == 401
        wrong = {"Authorization": "Bearer " + "x" * len(TOKEN)}
        assert client.get("/metrics", headers=wrong).status_code == 401
        r = client.get("/metrics", headers={"Authorization": f"Bearer {TOKEN}"})
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/plain; version=0.0.4")
        body = r.text
        assert 'apiedge_gateway_requests_total{tenant="acme",api_id="' in body
        assert 'method="GET",status="200"} 1' in body
        assert "apiedge_gateway_unmatched_requests_total 1" in body
        assert 'le="+Inf"} 1' in body
        assert "/metrics" not in client.get("/api/v1/openapi.json").text
