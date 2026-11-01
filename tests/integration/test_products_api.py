# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""Products admin API (T-005): CRUD, lifecycle, RBAC denial, product scope, BOLA, cross-tenant."""

from __future__ import annotations

import json

import pytest

from tests.integration.conftest import PASSWORD, World


def _url(world: World, suffix: str = "", tenant: int | None = None) -> str:
    return f"/api/v1/tenants/{tenant or world.tenant_a}/products{suffix}"


def _create(world: World, h: dict[str, str], name: str, **extra: object) -> dict[str, object]:
    r = world.client.post(_url(world), json={"name": name, **extra}, headers=h)
    assert r.status_code == 201, r.text
    body: dict[str, object] = r.json()
    return body


def _role_id(world: World, h: dict[str, str], name: str) -> int:
    roles = world.client.get(f"/api/v1/tenants/{world.tenant_a}/roles", headers=h).json()
    return int(next(r["id"] for r in roles if r["name"] == name))


def _scoped_user(world: World, admin: dict[str, str], name: str, role: str, product: int) -> int:
    base = f"/api/v1/tenants/{world.tenant_a}/users"
    r = world.client.post(
        base,
        json={"username": name, "password": PASSWORD, "must_change_password": False},
        headers=admin,
    )
    assert r.status_code == 201, r.text
    uid = int(r.json()["id"])
    g = world.client.post(
        f"{base}/{uid}/roles",
        json={"role_id": _role_id(world, admin, role), "product_id": product},
        headers=admin,
    )
    assert g.status_code == 201, g.text
    return uid


# ------------------------------------------------------------------------------ CRUD


def test_crud_lifecycle_and_audit(world: World) -> None:
    h = world.login("alice")
    p = _create(world, h, "Payments", description="Card payments")
    assert p["lifecycle"] == "draft"
    assert [o["username"] for o in p["owners"]] == ["alice"]  # type: ignore[union-attr,index]
    pid = p["id"]

    r = world.client.patch(
        _url(world, f"/{pid}"),
        json={"description": "Cards and wallets", "owners": ["dev", "victor"]},
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert [o["username"] for o in r.json()["owners"]] == ["dev", "victor"]
    assert r.json()["description"] == "Cards and wallets"

    listed = world.client.get(_url(world), headers=h).json()
    assert [x["name"] for x in listed] == ["Payments"]
    assert world.client.get(_url(world) + "?lifecycle=published", headers=h).json() == []

    for state in ("published", "deprecated", "published", "deprecated", "retired"):
        r = world.client.post(
            _url(world, f"/{pid}/lifecycle"), json={"lifecycle": state}, headers=h
        )
        assert r.status_code == 200, (state, r.text)
        assert r.json()["lifecycle"] == state

    # Retired is final and read-only.
    r = world.client.post(_url(world, f"/{pid}/lifecycle"), json={"lifecycle": "draft"}, headers=h)
    assert r.status_code == 409
    r = world.client.patch(_url(world, f"/{pid}"), json={"name": "X"}, headers=h)
    assert r.status_code == 409

    assert world.client.delete(_url(world, f"/{pid}"), headers=h).status_code == 204
    assert world.client.get(_url(world, f"/{pid}"), headers=h).status_code == 404

    events = world.client.get(f"/api/v1/tenants/{world.tenant_a}/audit?limit=100", headers=h).json()
    actions = [e["action"] for e in events]
    for a in ("product.create", "product.update", "product.lifecycle", "product.delete"):
        assert a in actions
    lifecycle = next(e for e in events if e["action"] == "product.lifecycle")
    assert lifecycle["resource_type"] == "product"
    assert json.loads(lifecycle["details"])["after"] in {"published", "deprecated", "retired"}


def test_invalid_transitions_and_delete_rules(world: World) -> None:
    h = world.login("alice")
    pid = _create(world, h, "Orders")["id"]
    for bad in ("deprecated", "draft"):
        r = world.client.post(_url(world, f"/{pid}/lifecycle"), json={"lifecycle": bad}, headers=h)
        assert r.status_code == 409, bad
    r = world.client.post(_url(world, f"/{pid}/lifecycle"), json={"lifecycle": "bogus"}, headers=h)
    assert r.status_code == 422
    world.client.post(_url(world, f"/{pid}/lifecycle"), json={"lifecycle": "published"}, headers=h)
    assert world.client.delete(_url(world, f"/{pid}"), headers=h).status_code == 409


def test_validation_and_conflicts(world: World) -> None:
    h = world.login("alice")
    _create(world, h, "Shipping")
    r = world.client.post(_url(world), json={"name": "Shipping"}, headers=h)
    assert r.status_code == 409
    r = world.client.post(_url(world), json={"name": "  "}, headers=h)
    assert r.status_code == 422
    r = world.client.post(_url(world), json={"name": "A", "lifecycle": "published"}, headers=h)
    assert r.status_code == 422  # unknown fields are rejected; lifecycle has its own route
    r = world.client.post(_url(world), json={"name": "B", "description": "x" * 2001}, headers=h)
    assert r.status_code == 422
    r = world.client.post(_url(world), json={"name": "C", "owners": ["nobody"]}, headers=h)
    assert r.status_code == 400
    # A user of another tenant (bob) or a platform user (root) cannot own this tenant's product.
    for foreign in ("bob", "root"):
        r = world.client.post(_url(world), json={"name": "D", "owners": [foreign]}, headers=h)
        assert r.status_code == 400, foreign


def test_superadmin_creates_without_default_owner(world: World) -> None:
    h = world.login("root")
    p = _create(world, h, "Platform-made")
    assert p["owners"] == []
    assert p["tenant_id"] == world.tenant_a


# ------------------------------------------------------------------- RBAC denial (403)


@pytest.mark.parametrize("user", ["victor", "dev"])
def test_read_only_roles_cannot_mutate(world: World, user: str) -> None:
    pid = _create(world, world.login("alice"), "Catalog")["id"]
    h = world.login(user)
    assert world.client.get(_url(world), headers=h).status_code == 200
    assert world.client.get(_url(world, f"/{pid}"), headers=h).status_code == 200
    calls = [
        ("POST", _url(world), {"name": "New"}),
        ("PATCH", _url(world, f"/{pid}"), {"name": "Renamed"}),
        ("POST", _url(world, f"/{pid}/lifecycle"), {"lifecycle": "published"}),
        ("DELETE", _url(world, f"/{pid}"), None),
    ]
    for method, url, body in calls:
        r = world.client.request(method, url, json=body, headers=h)
        assert r.status_code == 403, (user, method, url, r.text)


def test_user_without_product_permissions_is_denied(world: World) -> None:
    admin = world.login("alice")
    r = world.client.post(
        f"/api/v1/tenants/{world.tenant_a}/users",
        json={"username": "norole", "password": PASSWORD, "must_change_password": False},
        headers=admin,
    )
    assert r.status_code == 201
    h = world.login("norole")
    assert world.client.get(_url(world), headers=h).status_code == 403
    pid = _create(world, admin, "Hidden")["id"]
    assert world.client.get(_url(world, f"/{pid}"), headers=h).status_code == 403


def test_unauthenticated(world: World) -> None:
    assert world.client.get(_url(world)).status_code == 401


# --------------------------------------------------- product-scoped grants and BOLA


def test_product_scoped_owner(world: World) -> None:
    admin = world.login("alice")
    mine = _create(world, admin, "Mine")["id"]
    other = _create(world, admin, "Other")["id"]
    _scoped_user(world, admin, "polly", "ProductOwner", int(str(mine)))
    h = world.login("polly")

    assert [p["id"] for p in world.client.get(_url(world), headers=h).json()] == [mine]
    assert world.client.get(_url(world, f"/{mine}"), headers=h).status_code == 200
    r = world.client.patch(_url(world, f"/{mine}"), json={"description": "ok"}, headers=h)
    assert r.status_code == 200
    r = world.client.post(
        _url(world, f"/{mine}/lifecycle"), json={"lifecycle": "published"}, headers=h
    )
    assert r.status_code == 200
    # ProductOwner cannot create or delete products.
    assert world.client.post(_url(world), json={"name": "X"}, headers=h).status_code == 403
    assert world.client.delete(_url(world, f"/{mine}"), headers=h).status_code == 403

    # BOLA: another product of the same tenant is invisible (404).
    for method, suffix, body in [
        ("GET", f"/{other}", None),
        ("PATCH", f"/{other}", {"name": "Taken"}),
        ("POST", f"/{other}/lifecycle", {"lifecycle": "published"}),
    ]:
        r = world.client.request(method, _url(world, suffix), json=body, headers=h)
        assert r.status_code == 404, (method, suffix, r.text)
    # No product:delete anywhere: the same 403 for every id, so nothing is disclosed.
    assert world.client.delete(_url(world, f"/{other}"), headers=h).status_code == 403
    assert world.client.get(_url(world, "/999999"), headers=h).status_code == 404


def test_deleting_a_product_removes_its_scoped_grants(world: World) -> None:
    admin = world.login("alice")
    pid = int(str(_create(world, admin, "Temp")["id"]))
    uid = _scoped_user(world, admin, "temp-owner", "Viewer", pid)
    assert world.client.delete(_url(world, f"/{pid}"), headers=admin).status_code == 204
    grants = world.client.get(
        f"/api/v1/tenants/{world.tenant_a}/users/{uid}/roles", headers=admin
    ).json()
    assert grants == []
    h = world.login("temp-owner")
    assert world.client.get(_url(world), headers=h).status_code == 403


def test_grant_needs_a_product_of_the_tenant(world: World) -> None:
    admin_b = world.login("bob")
    r = world.client.post(
        _url(world, tenant=world.tenant_b), json={"name": "Globex"}, headers=admin_b
    )
    assert r.status_code == 201
    foreign = int(r.json()["id"])
    admin = world.login("alice")
    base = f"/api/v1/tenants/{world.tenant_a}/users/{world.users['victor']}/roles"
    role = _role_id(world, admin, "Viewer")
    for product in (foreign, 999999):
        r = world.client.post(base, json={"role_id": role, "product_id": product}, headers=admin)
        assert r.status_code == 404, product


# ----------------------------------------------------------------------- cross-tenant


def test_cross_tenant_access_is_not_found(world: World) -> None:
    pid = _create(world, world.login("alice"), "Acme only")["id"]
    bob = world.login("bob")
    # Tenant A's routes: the tenant itself is invisible to bob.
    assert world.client.get(_url(world), headers=bob).status_code == 404
    assert world.client.get(_url(world, f"/{pid}"), headers=bob).status_code == 404
    # Tenant B's routes with tenant A's product id: the tenant filter hides it.
    for method, suffix, body in [
        ("GET", f"/{pid}", None),
        ("PATCH", f"/{pid}", {"name": "Stolen"}),
        ("POST", f"/{pid}/lifecycle", {"lifecycle": "published"}),
        ("DELETE", f"/{pid}", None),
    ]:
        r = world.client.request(
            method, _url(world, suffix, tenant=world.tenant_b), json=body, headers=bob
        )
        assert r.status_code == 404, (method, suffix)
    assert world.client.get(_url(world, tenant=world.tenant_b), headers=bob).json() == []
    # The product is unchanged.
    got = world.client.get(_url(world, f"/{pid}"), headers=world.login("alice")).json()
    assert got["name"] == "Acme only" and got["lifecycle"] == "draft"
