# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""RBAC denial, BOLA and cross-tenant denial for the admin API (T-003)."""

from __future__ import annotations

import pytest

from tests.integration.conftest import World

NEW_USER = {"username": "carol", "password": "Another-Secret-55"}


def _role_id(world: World, headers: dict[str, str], tenant: int, name: str) -> int:
    roles = world.client.get(f"/api/v1/tenants/{tenant}/roles", headers=headers).json()
    return int(next(r["id"] for r in roles if r["name"] == name))


# ----------------------------------------------------------------- RBAC denial (403)


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("post", "/tenants/{a}/users", NEW_USER),
        ("patch", "/tenants/{a}/users/{dev}", {"is_active": False}),
        ("delete", "/tenants/{a}/users/{dev}", None),
        ("post", "/tenants/{a}/users/{dev}/reset-password", {"new_password": "Xyzzy-Plugh-123"}),
        ("post", "/tenants/{a}/users/{dev}/roles", {"role_id": 1}),
        ("post", "/tenants/{a}/roles", {"name": "R", "permissions": []}),
        ("patch", "/tenants/{a}", {"name": "Renamed"}),
    ],
)
def test_viewer_cannot_mutate(world: World, method: str, path: str, body: object) -> None:
    h = world.login("victor")
    url = "/api/v1" + path.format(a=world.tenant_a, dev=world.users["dev"])
    r = world.client.request(method.upper(), url, json=body, headers=h)
    assert r.status_code == 403, (url, r.text)


def test_viewer_can_read(world: World) -> None:
    h = world.login("victor")
    a = world.tenant_a
    for path in (
        f"/tenants/{a}",
        f"/tenants/{a}/users",
        f"/tenants/{a}/roles",
        f"/tenants/{a}/audit",
    ):
        assert world.client.get("/api/v1" + path, headers=h).status_code == 200, path


def test_developer_lacks_user_and_audit_read(world: World) -> None:
    h = world.login("dev")
    assert world.client.get(f"/api/v1/tenants/{world.tenant_a}/users", headers=h).status_code == 403
    assert world.client.get(f"/api/v1/tenants/{world.tenant_a}/audit", headers=h).status_code == 403


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("post", "/tenants", {"slug": "evil", "name": "Evil"}),
        ("delete", "/tenants/{a}", None),
        ("get", "/audit", None),
    ],
)
def test_tenant_admin_cannot_use_platform_routes(
    world: World, method: str, path: str, body: object
) -> None:
    h = world.login("alice")
    url = "/api/v1" + path.format(a=world.tenant_a)
    assert world.client.request(method.upper(), url, json=body, headers=h).status_code == 403


def test_tenant_admin_cannot_suspend_own_tenant(world: World) -> None:
    h = world.login("alice")
    r = world.client.patch(
        f"/api/v1/tenants/{world.tenant_a}", json={"is_active": False}, headers=h
    )
    assert r.status_code == 403


# ----------------------------------------------------------------- cross-tenant denial


@pytest.mark.parametrize(
    "path",
    [
        "/tenants/{b}",
        "/tenants/{b}/users",
        "/tenants/{b}/roles",
        "/tenants/{b}/audit",
        "/tenants/{b}/users/{bob}",
        "/tenants/{b}/users/{bob}/roles",
    ],
)
def test_tenant_admin_cannot_read_other_tenant(world: World, path: str) -> None:
    h = world.login("alice")
    url = "/api/v1" + path.format(b=world.tenant_b, bob=world.users["bob"])
    r = world.client.get(url, headers=h)
    assert r.status_code == 404  # existence of the other tenant is not disclosed


def test_cross_tenant_writes_denied(world: World) -> None:
    h = world.login("alice")
    b, bob = world.tenant_b, world.users["bob"]
    c = world.client
    assert c.post(f"/api/v1/tenants/{b}/users", json=NEW_USER, headers=h).status_code == 404
    assert c.patch(f"/api/v1/tenants/{b}/users/{bob}", json={}, headers=h).status_code == 404
    assert c.delete(f"/api/v1/tenants/{b}/users/{bob}", headers=h).status_code == 404


def test_tenant_list_shows_only_own_tenant(world: World) -> None:
    h = world.login("alice")
    assert [t["slug"] for t in world.client.get("/api/v1/tenants", headers=h).json()] == ["acme"]
    root = world.login("root")
    slugs = {t["slug"] for t in world.client.get("/api/v1/tenants", headers=root).json()}
    assert slugs == {"acme", "globex"}


def test_audit_log_is_tenant_scoped(world: World) -> None:
    world.login("alice")
    world.login("bob")
    h = world.login("alice")
    events = world.client.get(f"/api/v1/tenants/{world.tenant_a}/audit", headers=h).json()
    assert events and all(e["tenant_id"] == world.tenant_a for e in events)
    assert "bob" not in {e["actor_username"] for e in events}
    root = world.login("root")
    all_events = world.client.get("/api/v1/audit", headers=root).json()
    assert {"alice", "bob", "root"} <= {e["actor_username"] for e in all_events}


# ----------------------------------------------------------------- BOLA (object ids)


def test_bola_user_of_other_tenant_through_own_tenant_path(world: World) -> None:
    """Own tenant in the path, another tenant's object id: must not be reachable."""
    h = world.login("alice")
    a, bob, root = world.tenant_a, world.users["bob"], world.users["root"]
    c = world.client
    for uid in (bob, root):
        assert c.get(f"/api/v1/tenants/{a}/users/{uid}", headers=h).status_code == 404
        r = c.patch(f"/api/v1/tenants/{a}/users/{uid}", json={"is_active": False}, headers=h)
        assert r.status_code == 404
        r = c.post(
            f"/api/v1/tenants/{a}/users/{uid}/reset-password",
            json={"new_password": "Hijack-Attempt-123"},
            headers=h,
        )
        assert r.status_code == 404
        assert c.get(f"/api/v1/tenants/{a}/users/{uid}/roles", headers=h).status_code == 404
    listed = {u["username"] for u in c.get(f"/api/v1/tenants/{a}/users", headers=h).json()}
    assert listed == {"alice", "victor", "dev"}


def test_bola_custom_role_of_other_tenant(world: World) -> None:
    bob = world.login("bob")
    b = world.tenant_b
    r = world.client.post(
        f"/api/v1/tenants/{b}/roles",
        json={"name": "Auditors", "permissions": ["audit:read"]},
        headers=bob,
    )
    assert r.status_code == 201
    foreign_role = r.json()["id"]
    h = world.login("alice")
    a, dev = world.tenant_a, world.users["dev"]
    c = world.client
    assert c.get(f"/api/v1/tenants/{a}/roles/{foreign_role}", headers=h).status_code == 404
    assert c.delete(f"/api/v1/tenants/{a}/roles/{foreign_role}", headers=h).status_code == 404
    r = c.post(f"/api/v1/tenants/{a}/users/{dev}/roles", json={"role_id": foreign_role}, headers=h)
    assert r.status_code == 404
    assert "Auditors" not in {
        x["name"] for x in c.get(f"/api/v1/tenants/{a}/roles", headers=h).json()
    }


def test_bola_assignment_of_other_user(world: World) -> None:
    h = world.login("alice")
    a, dev, victor = world.tenant_a, world.users["dev"], world.users["victor"]
    grants = world.client.get(f"/api/v1/tenants/{a}/users/{victor}/roles", headers=h).json()
    r = world.client.delete(f"/api/v1/tenants/{a}/users/{dev}/roles/{grants[0]['id']}", headers=h)
    assert r.status_code == 404


# ----------------------------------------------------------------- privilege escalation


def test_cannot_grant_superadmin_role(world: World) -> None:
    h = world.login("alice")
    sa = _role_id(world, h, world.tenant_a, "SuperAdmin")
    r = world.client.post(
        f"/api/v1/tenants/{world.tenant_a}/users/{world.users['dev']}/roles",
        json={"role_id": sa},
        headers=h,
    )
    assert r.status_code == 400


def test_custom_role_cannot_contain_platform_permissions(world: World) -> None:
    h = world.login("alice")
    r = world.client.post(
        f"/api/v1/tenants/{world.tenant_a}/roles",
        json={"name": "Sneaky", "permissions": ["tenant:create"]},
        headers=h,
    )
    assert r.status_code == 422


def test_limited_assigner_cannot_escalate(world: World) -> None:
    """A user with role:assign but few permissions cannot grant TenantAdmin (or itself)."""
    admin = world.login("alice")
    a = world.tenant_a
    r = world.client.post(
        f"/api/v1/tenants/{a}/roles",
        json={"name": "Assigner", "permissions": ["role:assign", "role:read", "user:read"]},
        headers=admin,
    )
    assigner_role = r.json()["id"]
    dev = world.users["dev"]
    r = world.client.post(
        f"/api/v1/tenants/{a}/users/{dev}/roles", json={"role_id": assigner_role}, headers=admin
    )
    assert r.status_code == 201
    h = world.login("dev")
    tadmin = _role_id(world, h, a, "TenantAdmin")
    r = world.client.post(
        f"/api/v1/tenants/{a}/users/{dev}/roles", json={"role_id": tadmin}, headers=h
    )
    assert r.status_code == 403
    # Nor manage a more privileged user.
    alice = world.users["alice"]
    r = world.client.delete(f"/api/v1/tenants/{a}/users/{alice}/roles/1", headers=h)
    assert r.status_code in (403, 404)


# ----------------------------------------------------------------- happy paths


def test_tenant_admin_user_and_role_lifecycle(world: World) -> None:
    h = world.login("alice")
    a, c = world.tenant_a, world.client
    viewer = _role_id(world, h, a, "Viewer")
    r = c.post(f"/api/v1/tenants/{a}/users", json={**NEW_USER, "role_ids": [viewer]}, headers=h)
    assert r.status_code == 201, r.text
    carol = r.json()
    assert carol["tenant_id"] == a and carol["must_change_password"] is True
    assert c.post(f"/api/v1/tenants/{a}/users", json=NEW_USER, headers=h).status_code == 409
    weak = {**NEW_USER, "username": "dave", "password": "dave-is-great-1"}
    assert c.post(f"/api/v1/tenants/{a}/users", json=weak, headers=h).status_code == 400
    grants = c.get(f"/api/v1/tenants/{a}/users/{carol['id']}/roles", headers=h).json()
    assert [g["role_name"] for g in grants] == ["Viewer"]
    r = c.delete(f"/api/v1/tenants/{a}/users/{carol['id']}/roles/{grants[0]['id']}", headers=h)
    assert r.status_code == 204
    r = c.post(
        f"/api/v1/tenants/{a}/roles",
        json={"name": "Ops", "permissions": ["analytics:view", "inspector:view"]},
        headers=h,
    )
    assert r.status_code == 201
    role = r.json()
    r = c.patch(
        f"/api/v1/tenants/{a}/roles/{role['id']}",
        json={"permissions": ["analytics:view"]},
        headers=h,
    )
    assert r.json()["permissions"] == ["analytics:view"]
    r = c.patch(f"/api/v1/tenants/{a}/roles/{viewer}", json={"name": "X"}, headers=h)
    assert r.status_code == 400  # built-in roles are read-only
    assert c.delete(f"/api/v1/tenants/{a}/roles/{role['id']}", headers=h).status_code == 204
    assert c.delete(f"/api/v1/tenants/{a}/users/{carol['id']}", headers=h).status_code == 204
    actions = [e["action"] for e in c.get(f"/api/v1/tenants/{a}/audit", headers=h).json()]
    for expected in (
        "user.create",
        "role.revoke",
        "role.create",
        "role.update",
        "role.delete",
        "user.delete",
    ):
        assert expected in actions


def test_role_change_ends_sessions(world: World) -> None:
    dev = world.login("dev")
    h = world.login("alice")
    viewer = _role_id(world, h, world.tenant_a, "Viewer")
    r = world.client.post(
        f"/api/v1/tenants/{world.tenant_a}/users/{world.users['dev']}/roles",
        json={"role_id": viewer},
        headers=h,
    )
    assert r.status_code == 201
    assert world.client.get("/api/v1/auth/me", headers=dev).status_code == 401


def test_cannot_disable_or_delete_self(world: World) -> None:
    h = world.login("alice")
    url = f"/api/v1/tenants/{world.tenant_a}/users/{world.users['alice']}"
    assert world.client.patch(url, json={"is_active": False}, headers=h).status_code == 400
    assert world.client.delete(url, headers=h).status_code == 400


def test_superadmin_manages_tenants(world: World) -> None:
    root = world.login("root")
    c = world.client
    r = c.post("/api/v1/tenants", json={"slug": "initech", "name": "Initech"}, headers=root)
    assert r.status_code == 201
    tid = r.json()["id"]
    assert (
        c.post("/api/v1/tenants", json={"slug": "initech", "name": "X"}, headers=root).status_code
        == 409
    )
    assert (
        c.post("/api/v1/tenants", json={"slug": "Bad Slug", "name": "X"}, headers=root).status_code
        == 422
    )
    r = c.post(f"/api/v1/tenants/{tid}/users", json={**NEW_USER, "username": "ian"}, headers=root)
    assert r.status_code == 201
    assert c.delete(f"/api/v1/tenants/{tid}", headers=root).status_code == 204
    assert c.get(f"/api/v1/tenants/{tid}", headers=root).status_code == 404
    events = c.get("/api/v1/audit", params={"tenant_id": tid}, headers=root).json()
    assert {"tenant.create", "user.create", "tenant.delete"} <= {e["action"] for e in events}


def test_suspended_tenant_tokens_stop_working(world: World) -> None:
    bob = world.login("bob")
    root = world.login("root")
    world.client.patch(f"/api/v1/tenants/{world.tenant_b}", json={"is_active": False}, headers=root)
    assert world.client.get("/api/v1/auth/me", headers=bob).status_code == 401


def test_permission_catalog(world: World) -> None:
    h = world.login("victor")
    perms = {p["name"]: p for p in world.client.get("/api/v1/permissions", headers=h).json()}
    assert perms["tenant:create"]["platform_only"] is True
    assert perms["inspector:view"]["platform_only"] is False
