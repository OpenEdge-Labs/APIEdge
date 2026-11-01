# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""APIs in products (T-006): CRUD, validation, SSRF guard, lifecycle, RBAC denial, product scope,
BOLA, cross-tenant isolation and the product-delete guard."""

from __future__ import annotations

import json
from typing import Any

import pytest

from tests.integration.conftest import PASSWORD, World

PUBLIC = "http://93.184.216.34/"  # an IP literal: no DNS lookup needed in tests
ROUTES = [
    {"methods": ["GET"], "path": "/orders"},
    {"methods": ["GET", "PUT"], "path": "/orders/{id}"},
]


def _products(world: World, tenant: int | None = None) -> str:
    return f"/api/v1/tenants/{tenant or world.tenant_a}/products"


def _apis(world: World, product: int, suffix: str = "", tenant: int | None = None) -> str:
    return f"{_products(world, tenant)}/{product}/apis{suffix}"


def _product(world: World, h: dict[str, str], name: str, tenant: int | None = None) -> int:
    r = world.client.post(_products(world, tenant), json={"name": name}, headers=h)
    assert r.status_code == 201, r.text
    return int(r.json()["id"])


def _api_body(base_path: str = "/orders", **extra: object) -> dict[str, Any]:
    return {
        "name": "Orders",
        "base_path": base_path,
        "upstreams": [{"url": PUBLIC}],
        "routes": ROUTES,
        **extra,
    }


def _create(
    world: World, h: dict[str, str], product: int, tenant: int | None = None, **extra: Any
) -> dict[str, Any]:
    r = world.client.post(_apis(world, product, tenant=tenant), json=_api_body(**extra), headers=h)
    assert r.status_code == 201, r.text
    body: dict[str, Any] = r.json()
    return body


def _move(world: World, h: dict[str, str], product: int, api: int, to: str) -> int:
    r = world.client.post(
        _apis(world, product, f"/{api}/lifecycle"), json={"lifecycle": to}, headers=h
    )
    return int(r.status_code)


def _user(world: World, admin: dict[str, str], name: str, role: str, product: int | None) -> None:
    base = f"/api/v1/tenants/{world.tenant_a}/users"
    r = world.client.post(
        base,
        json={"username": name, "password": PASSWORD, "must_change_password": False},
        headers=admin,
    )
    assert r.status_code == 201, r.text
    roles = world.client.get(f"/api/v1/tenants/{world.tenant_a}/roles", headers=admin).json()
    role_id = next(r["id"] for r in roles if r["name"] == role)
    g = world.client.post(
        f"{base}/{r.json()['id']}/roles",
        json={"role_id": role_id, "product_id": product},
        headers=admin,
    )
    assert g.status_code == 201, g.text


# ------------------------------------------------------------------------------ CRUD


def test_crud_lifecycle_and_audit(world: World) -> None:
    h = world.login("alice")
    pid = _product(world, h, "Commerce")
    api = _create(world, h, pid, version="2.0", description="Order API", timeout_ms=5000)
    aid = api["id"]
    assert api["lifecycle"] == "draft" and api["product_id"] == pid
    assert api["upstreams"] == [{"url": PUBLIC, "weight": 1}]
    assert [r["methods"] for r in api["routes"]] == [["GET"], ["GET", "PUT"]]

    listed = world.client.get(_apis(world, pid), headers=h).json()
    assert [a["id"] for a in listed] == [aid]
    assert world.client.get(_apis(world, pid, f"/{aid}"), headers=h).json()["timeout_ms"] == 5000

    r = world.client.patch(
        _apis(world, pid, f"/{aid}"),
        json={
            "base_path": "/shop/orders",
            "upstreams": [{"url": PUBLIC, "weight": 3}, {"url": "https://93.184.216.35:8443/v1"}],
            "routes": [{"methods": ["PUT", "GET", "GET"], "path": "/*"}],
        },
        headers=h,
    )
    assert r.status_code == 200, r.text
    got = r.json()
    assert got["base_path"] == "/shop/orders"
    assert got["gateway_path"] == "/acme/shop/orders"
    assert [u["weight"] for u in got["upstreams"]] == [3, 1]
    assert got["routes"] == [{"methods": ["GET", "PUT"], "path": "/*", "description": ""}]

    assert _move(world, h, pid, aid, "published") == 200
    # A published API keeps its base path and cannot lose its upstreams or routes.
    bodies: list[dict[str, Any]] = [{"base_path": "/elsewhere"}, {"upstreams": []}, {"routes": []}]
    for body in bodies:
        r = world.client.patch(_apis(world, pid, f"/{aid}"), json=body, headers=h)
        assert r.status_code == 409, body
    assert world.client.delete(_apis(world, pid, f"/{aid}"), headers=h).status_code == 409
    for state in ("deprecated", "published", "deprecated", "retired"):
        assert _move(world, h, pid, aid, state) == 200, state
    assert _move(world, h, pid, aid, "draft") == 409
    r = world.client.patch(_apis(world, pid, f"/{aid}"), json={"name": "X"}, headers=h)
    assert r.status_code == 409  # retired is read-only
    assert world.client.delete(_apis(world, pid, f"/{aid}"), headers=h).status_code == 204
    assert world.client.get(_apis(world, pid, f"/{aid}"), headers=h).status_code == 404

    events = world.client.get(f"/api/v1/tenants/{world.tenant_a}/audit?limit=100", headers=h).json()
    actions = [e["action"] for e in events]
    for a in ("api.create", "api.update", "api.lifecycle", "api.delete"):
        assert a in actions, a
    update = next(e for e in events if e["action"] == "api.update")
    assert update["resource_type"] == "api"
    assert json.loads(update["details"])["changed"] == ["base_path", "routes", "upstreams"]


def test_publish_needs_upstream_and_route(world: World) -> None:
    h = world.login("alice")
    pid = _product(world, h, "Empty")
    aid = _create(world, h, pid, upstreams=[], routes=[])["id"]
    assert _move(world, h, pid, aid, "published") == 409
    world.client.patch(
        _apis(world, pid, f"/{aid}"), json={"upstreams": [{"url": PUBLIC}]}, headers=h
    )
    assert _move(world, h, pid, aid, "published") == 409
    world.client.patch(_apis(world, pid, f"/{aid}"), json={"routes": ROUTES}, headers=h)
    assert _move(world, h, pid, aid, "published") == 200


@pytest.mark.parametrize(
    "body",
    [
        {"base_path": "orders"},
        {"base_path": "/"},
        {"base_path": "/a/../b"},
        {"base_path": "/api/v1/things"},
        {"base_path": "/healthz"},
        {"base_path": "/a b"},
        {"version": "-1"},
        {"timeout_ms": 50},
        {"routes": [{"methods": [], "path": "/a"}]},
        {"routes": [{"methods": ["TRACE"], "path": "/a"}]},
        {"routes": [{"methods": ["GET"], "path": "a"}]},
        {"routes": [{"methods": ["GET"], "path": "/a/*/b"}]},
        {"routes": [{"methods": ["GET"], "path": "/{id}/{id}"}]},
        {
            "routes": [
                {"methods": ["GET"], "path": "/a/{id}"},
                {"methods": ["GET"], "path": "/a/{x}"},
            ]
        },
        {"upstreams": [{"url": PUBLIC, "weight": 0}]},
        {"lifecycle": "published"},
    ],
)
def test_validation(world: World, body: dict[str, Any]) -> None:
    h = world.login("alice")
    pid = _product(world, h, "Validated")
    r = world.client.post(_apis(world, pid), json=_api_body(**body), headers=h)
    assert r.status_code == 422, (body, r.text)


def test_conflicts(world: World) -> None:
    h = world.login("alice")
    p1, p2 = _product(world, h, "One"), _product(world, h, "Two")
    _create(world, h, p1)
    # The base path is unique in the tenant, across products.
    r = world.client.post(_apis(world, p2), json=_api_body(name="Other"), headers=h)
    assert r.status_code == 409
    # Name + version is unique in the product.
    r = world.client.post(_apis(world, p1), json=_api_body("/orders2"), headers=h)
    assert r.status_code == 409
    assert (
        world.client.post(
            _apis(world, p1), json=_api_body("/orders3", version="v2"), headers=h
        ).status_code
        == 201
    )
    # Another tenant may use the same base path.
    bob = world.login("bob")
    pb = _product(world, bob, "Globex", tenant=world.tenant_b)
    r = world.client.post(_apis(world, pb, tenant=world.tenant_b), json=_api_body(), headers=bob)
    assert r.status_code == 201


# ------------------------------------------------------------------------- SSRF guard


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:9000/",
        "http://localhost/",
        "http://10.0.0.5/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://2130706433/",
        "http://user:pw@93.184.216.34/",
        "file:///etc/passwd",
        "gopher://93.184.216.34/",
    ],
)
def test_upstreams_go_through_the_ssrf_guard(world: World, url: str) -> None:
    h = world.login("alice")
    pid = _product(world, h, "Guarded")
    body = _api_body(upstreams=[{"url": PUBLIC}, {"url": url}])
    r = world.client.post(_apis(world, pid), json=body, headers=h)
    assert r.status_code == 400, (url, r.text)
    assert r.json()["detail"]["upstreams"][0].startswith("upstream 2:")
    aid = _create(world, h, pid)["id"]
    r = world.client.patch(
        _apis(world, pid, f"/{aid}"), json={"upstreams": [{"url": url}]}, headers=h
    )
    assert r.status_code == 400, url
    assert (
        world.client.get(_apis(world, pid, f"/{aid}"), headers=h).json()["upstreams"][0]["url"]
        == PUBLIC
    )


def test_ssrf_policy_comes_from_settings(world: World) -> None:
    h = world.login("alice")
    pid = _product(world, h, "On-prem")
    app: Any = world.client.app
    app.state.settings = world.settings.model_copy(update={"ssrf_allow_private": True})
    r = world.client.post(
        _apis(world, pid), json=_api_body(upstreams=[{"url": "http://10.0.0.5:8080"}]), headers=h
    )
    assert r.status_code == 201, r.text
    # Cloud metadata stays blocked even when private addresses are allowed.
    r = world.client.post(
        _apis(world, pid),
        json=_api_body("/meta", name="Meta", upstreams=[{"url": "http://169.254.169.254/"}]),
        headers=h,
    )
    assert r.status_code == 400


# ------------------------------------------------------------------- RBAC denial (403)


def test_viewer_reads_but_cannot_change(world: World) -> None:
    admin = world.login("alice")
    pid = _product(world, admin, "Catalog")
    aid = _create(world, admin, pid)["id"]
    h = world.login("victor")
    assert world.client.get(_apis(world, pid), headers=h).status_code == 200
    assert world.client.get(_apis(world, pid, f"/{aid}"), headers=h).status_code == 200
    for method, url, body in [
        ("POST", _apis(world, pid), _api_body("/new")),
        ("PATCH", _apis(world, pid, f"/{aid}"), {"name": "Renamed"}),
        ("POST", _apis(world, pid, f"/{aid}/lifecycle"), {"lifecycle": "published"}),
        ("DELETE", _apis(world, pid, f"/{aid}"), None),
    ]:
        r = world.client.request(method, url, json=body, headers=h)
        assert r.status_code == 403, (method, url, r.text)


def test_developer_builds_but_cannot_publish_or_delete(world: World) -> None:
    admin = world.login("alice")
    pid = _product(world, admin, "Dev")
    h = world.login("dev")
    aid = _create(world, h, pid)["id"]
    r = world.client.patch(_apis(world, pid, f"/{aid}"), json={"description": "x"}, headers=h)
    assert r.status_code == 200
    assert _move(world, h, pid, aid, "published") == 403
    assert world.client.delete(_apis(world, pid, f"/{aid}"), headers=h).status_code == 403


def test_user_without_api_permissions_is_denied(world: World) -> None:
    admin = world.login("alice")
    pid = _product(world, admin, "Hidden")
    r = world.client.post(
        f"/api/v1/tenants/{world.tenant_a}/users",
        json={"username": "norole", "password": PASSWORD, "must_change_password": False},
        headers=admin,
    )
    assert r.status_code == 201
    h = world.login("norole")
    assert world.client.get(_apis(world, pid), headers=h).status_code == 403
    assert world.client.post(_apis(world, pid), json=_api_body(), headers=h).status_code == 403


def test_unauthenticated(world: World) -> None:
    assert world.client.get(_apis(world, 1)).status_code == 401


# --------------------------------------------------- product-scoped grants and BOLA


def test_product_scoped_developer_and_bola(world: World) -> None:
    admin = world.login("alice")
    mine, other = _product(world, admin, "Mine"), _product(world, admin, "Other")
    foreign_api = _create(world, admin, other, base_path="/other")["id"]
    _user(world, admin, "pat", "APIDeveloper", mine)
    h = world.login("pat")

    aid = _create(world, h, mine)["id"]
    assert world.client.get(_apis(world, mine), headers=h).status_code == 200
    # Another product of the tenant is invisible.
    for method, url, body in [
        ("GET", _apis(world, other), None),
        ("POST", _apis(world, other), _api_body("/sneaky")),
        ("GET", _apis(world, other, f"/{foreign_api}"), None),
        ("PATCH", _apis(world, other, f"/{foreign_api}"), {"name": "Taken"}),
        # BOLA: another product's API through the product the caller may use.
        ("GET", _apis(world, mine, f"/{foreign_api}"), None),
        ("PATCH", _apis(world, mine, f"/{foreign_api}"), {"name": "Taken"}),
    ]:
        r = world.client.request(method, url, json=body, headers=h)
        assert r.status_code == 404, (method, url, r.text)
    # The tenant-wide base path check still applies, without naming the other API.
    r = world.client.post(_apis(world, mine), json=_api_body("/other", name="Clash"), headers=h)
    assert r.status_code == 409 and "Other" not in r.text
    assert _move(world, h, mine, aid, "published") == 403
    got = world.client.get(_apis(world, other, f"/{foreign_api}"), headers=admin).json()
    assert got["name"] == "Orders"


def test_cross_tenant_access_is_not_found(world: World) -> None:
    alice = world.login("alice")
    pid = _product(world, alice, "Acme")
    aid = _create(world, alice, pid)["id"]
    bob = world.login("bob")
    pb = _product(world, bob, "Globex", tenant=world.tenant_b)
    bob_api = _create(world, bob, pb, tenant=world.tenant_b, base_path="/globex")["id"]
    # Tenant A's routes are invisible to bob.
    assert world.client.get(_apis(world, pid), headers=bob).status_code == 404
    assert world.client.get(_apis(world, pid, f"/{aid}"), headers=bob).status_code == 404
    # Tenant B's routes with tenant A's ids: the tenant filter hides them.
    for method, url, body in [
        ("GET", _apis(world, pid, tenant=world.tenant_b), None),
        ("POST", _apis(world, pid, tenant=world.tenant_b), _api_body("/x")),
        ("GET", _apis(world, pb, f"/{aid}", tenant=world.tenant_b), None),
        ("PATCH", _apis(world, pb, f"/{aid}", tenant=world.tenant_b), {"name": "Stolen"}),
        (
            "POST",
            _apis(world, pb, f"/{aid}/lifecycle", tenant=world.tenant_b),
            {"lifecycle": "published"},
        ),
        ("DELETE", _apis(world, pb, f"/{aid}", tenant=world.tenant_b), None),
    ]:
        r = world.client.request(method, url, json=body, headers=bob)
        assert r.status_code == 404, (method, url)
    # Alice cannot reach bob's API through her own product either.
    assert world.client.get(_apis(world, pid, f"/{bob_api}"), headers=alice).status_code == 404
    got = world.client.get(_apis(world, pid, f"/{aid}"), headers=alice).json()
    assert got["name"] == "Orders" and got["lifecycle"] == "draft"


# ----------------------------------------------------------- product interplay


def test_product_with_apis_cannot_be_deleted(world: World) -> None:
    h = world.login("alice")
    pid = _product(world, h, "Container")
    aid = _create(world, h, pid)["id"]
    r = world.client.delete(_products(world) + f"/{pid}", headers=h)
    assert r.status_code == 409 and "APIs" in r.text
    assert world.client.delete(_apis(world, pid, f"/{aid}"), headers=h).status_code == 204
    assert world.client.delete(_products(world) + f"/{pid}", headers=h).status_code == 204


def test_retired_product_apis_can_only_wind_down(world: World) -> None:
    h = world.login("alice")
    pid = _product(world, h, "Sunset")
    aid = _create(world, h, pid)["id"]
    assert _move(world, h, pid, aid, "published") == 200
    for state in ("published", "deprecated", "retired"):
        r = world.client.post(
            _products(world) + f"/{pid}/lifecycle", json={"lifecycle": state}, headers=h
        )
        assert r.status_code == 200, state
    assert (
        world.client.post(_apis(world, pid), json=_api_body("/new"), headers=h).status_code == 409
    )
    r = world.client.patch(_apis(world, pid, f"/{aid}"), json={"name": "X"}, headers=h)
    assert r.status_code == 409
    assert _move(world, h, pid, aid, "deprecated") == 200
    assert _move(world, h, pid, aid, "published") == 409
    assert _move(world, h, pid, aid, "retired") == 200
    assert world.client.delete(_apis(world, pid, f"/{aid}"), headers=h).status_code == 204
    assert world.client.delete(_products(world) + f"/{pid}", headers=h).status_code == 204
