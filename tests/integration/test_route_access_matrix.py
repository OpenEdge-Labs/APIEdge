# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Access-control matrix over every admin route (T-018 security verification).

The feature tests check RBAC and tenant isolation route by route. This module checks the whole
surface at once, so a new route cannot ship without a declared permission and denial coverage:

* every operation's declared access (``x-apiedge-access``) must match :data:`EXPECTED`; adding
  a route without classifying it here fails the suite;
* only the routes in :data:`PUBLIC` may be reached without signing in;
* every non-public route answers 401 without credentials;
* every tenant or product route answers 403 to a tenant member without the permission and 404
  to an administrator of another tenant (no existence disclosure);
* every platform route answers 403 to a tenant administrator;
* every route under ``/products/{product_id}`` refuses a user whose grant is scoped to a
  different product of the same tenant (403 or 404), using real object ids so a missing check
  would show up as success or a validation error instead of a 404.
"""

from __future__ import annotations

import re
from typing import Any

import pytest
from fastapi.testclient import TestClient

from apiedge.security import x509

from .conftest import PASSWORD, World

PUBLIC = {
    ("POST", "/api/v1/auth/login"),
    ("POST", "/api/v1/auth/refresh"),
    ("POST", "/api/v1/auth/logout"),
    ("GET", "/healthz"),
    ("GET", "/readyz"),
}

T = "/api/v1/tenants/{tenant_id}"
P = T + "/products/{product_id}"
EXPECTED: dict[tuple[str, str], str] = {
    **{route: "public:" for route in PUBLIC},
    ("GET", "/api/v1/auth/me"): "signed-in:",
    ("POST", "/api/v1/auth/change-password"): "signed-in:",
    ("POST", "/api/v1/auth/mfa/setup"): "signed-in:",
    ("POST", "/api/v1/auth/mfa/enable"): "signed-in:",
    ("POST", "/api/v1/auth/mfa/disable"): "signed-in:",
    ("GET", "/api/v1/tenants"): "signed-in:",
    ("GET", "/api/v1/permissions"): "signed-in:",
    ("POST", "/api/v1/tenants"): "platform:tenant:create",
    ("DELETE", T): "platform:tenant:delete",
    ("GET", "/api/v1/audit"): "platform:audit:read",
    ("GET", "/api/v1/system/settings"): "platform:settings:read",
    ("GET", T): "tenant:tenant:read",
    ("PATCH", T): "tenant:tenant:update",
    ("GET", T + "/audit"): "tenant:audit:read",
    ("GET", T + "/users"): "tenant:user:read",
    ("POST", T + "/users"): "tenant:user:create",
    ("GET", T + "/users/{user_id}"): "tenant:user:read",
    ("PATCH", T + "/users/{user_id}"): "tenant:user:update",
    ("DELETE", T + "/users/{user_id}"): "tenant:user:delete",
    ("POST", T + "/users/{user_id}/reset-password"): "tenant:user:update",
    ("GET", T + "/users/{user_id}/roles"): "tenant:role:read",
    ("POST", T + "/users/{user_id}/roles"): "tenant:role:assign",
    ("DELETE", T + "/users/{user_id}/roles/{assignment_id}"): "tenant:role:assign",
    ("GET", T + "/roles"): "tenant:role:read",
    ("POST", T + "/roles"): "tenant:role:create",
    ("GET", T + "/roles/{role_id}"): "tenant:role:read",
    ("PATCH", T + "/roles/{role_id}"): "tenant:role:update",
    ("DELETE", T + "/roles/{role_id}"): "tenant:role:delete",
    ("GET", T + "/products"): "product:product:read",
    ("POST", T + "/products"): "tenant:product:create",
    ("GET", P): "product:product:read",
    ("PATCH", P): "product:product:update",
    ("DELETE", P): "product:product:delete",
    ("POST", P + "/lifecycle"): "product:product:publish",
    ("GET", P + "/apis"): "product:api:read",
    ("POST", P + "/apis"): "product:api:create",
    ("GET", P + "/apis/{api_id}"): "product:api:read",
    ("PATCH", P + "/apis/{api_id}"): "product:api:update",
    ("DELETE", P + "/apis/{api_id}"): "product:api:delete",
    ("POST", P + "/apis/{api_id}/lifecycle"): "product:api:publish",
    ("GET", P + "/apis/{api_id}/policies"): "product:policy:read",
    ("PUT", P + "/apis/{api_id}/policies"): "product:policy:update",
    ("GET", P + "/api-keys"): "product:apikey:read",
    ("POST", P + "/api-keys"): "product:apikey:manage",
    ("POST", P + "/api-keys/{key_id}/revoke"): "product:apikey:manage",
    ("GET", T + "/analytics/summary"): "product:analytics:view",
    ("GET", T + "/analytics/export.csv"): "product:analytics:view",
    ("GET", T + "/inspector/sessions"): "product:inspector:view",
    ("POST", T + "/inspector/sessions"): "product:inspector:capture",
    ("POST", T + "/inspector/sessions/{session_id}/stop"): "product:inspector:capture",
    ("DELETE", T + "/inspector/sessions/{session_id}"): "product:inspector:capture",
    ("GET", T + "/inspector/sessions/{session_id}/har"): "product:inspector:view",
    ("GET", T + "/inspector/exchanges"): "product:inspector:view",
    ("GET", T + "/inspector/exchanges/stream"): "product:inspector:view",
    ("GET", T + "/inspector/exchanges/{exchange_id}"): "product:inspector:view",
    ("POST", T + "/inspector/exchanges/{exchange_id}/replay"): "product:inspector:capture",
    ("GET", T + "/tls/truststores"): "tenant:tls:read",
    ("POST", T + "/tls/truststores"): "tenant:tls:manage",
    ("GET", T + "/tls/truststores/{truststore_id}"): "tenant:tls:read",
    ("PATCH", T + "/tls/truststores/{truststore_id}"): "tenant:tls:manage",
    ("DELETE", T + "/tls/truststores/{truststore_id}"): "tenant:tls:manage",
    ("GET", T + "/tls/keystores"): "tenant:tls:read",
    ("POST", T + "/tls/keystores"): "tenant:tls:manage",
    ("GET", T + "/tls/keystores/{keystore_id}"): "tenant:tls:read",
    ("DELETE", T + "/tls/keystores/{keystore_id}"): "tenant:tls:manage",
    ("GET", T + "/tls/profiles"): "tenant:tls:read",
    ("POST", T + "/tls/profiles"): "tenant:tls:manage",
    ("GET", T + "/tls/profiles/{profile_id}"): "tenant:tls:read",
    ("PATCH", T + "/tls/profiles/{profile_id}"): "tenant:tls:manage",
    ("DELETE", T + "/tls/profiles/{profile_id}"): "tenant:tls:manage",
}

PARAM = re.compile(r"\{(\w+)\}")
_CA_KEY = x509.generate_key()
_CA = x509.build_certificate(subject_key=_CA_KEY, common_name="Matrix CA", is_ca=True)

# Valid bodies, so an authorization gap would show as success rather than as a 422.
BODIES: dict[tuple[str, str], dict[str, Any]] = {
    ("PATCH", P): {"description": "changed"},
    ("POST", P + "/lifecycle"): {"lifecycle": "published"},
    ("POST", P + "/apis"): {"name": "Other", "base_path": "/other"},
    ("PATCH", P + "/apis/{api_id}"): {"description": "changed"},
    ("POST", P + "/apis/{api_id}/lifecycle"): {"lifecycle": "published"},
    ("PUT", P + "/apis/{api_id}/policies"): {"policies": []},
    ("POST", P + "/api-keys"): {"name": "other"},
    ("POST", T + "/tls/truststores"): {"name": "other", "certificates": _CA.pem()},
    ("PATCH", T + "/tls/truststores/{truststore_id}"): {"description": "changed"},
    ("POST", T + "/tls/profiles"): {"name": "other"},
    ("PATCH", T + "/tls/profiles/{profile_id}"): {"min_version": "1.3"},
    ("POST", T + "/tls/keystores"): {
        "name": "other",
        "certificate_chain": _CA.pem(),
        "private_key": x509.private_key_pem(_CA_KEY),
    },
}


def _operations(client: TestClient) -> dict[tuple[str, str], str]:
    spec: dict[str, Any] = client.app.openapi()  # type: ignore[attr-defined]
    found: dict[tuple[str, str], str] = {}
    for path, ops in spec["paths"].items():
        for method, op in ops.items():
            access = op.get("x-apiedge-access", {})
            found[(method.upper(), path)] = f"{access.get('scope')}:{access.get('permission', '')}"
    return found


def _fill(path: str, ids: dict[str, int]) -> str:
    return PARAM.sub(lambda m: str(ids.get(m.group(1), 999999)), path)


def _call(
    client: TestClient, method: str, url: str, headers: dict[str, str], path: str = ""
) -> int:
    body = None if method in ("GET", "DELETE") else BODIES.get((method, path), {})
    return int(client.request(method, url, json=body, headers=headers).status_code)


def test_every_route_is_classified(world: World) -> None:
    found = _operations(world.client)
    assert found == EXPECTED, (
        "admin routes changed: classify new routes in EXPECTED (and add denial tests)\n"
        f"unclassified: {sorted(set(found) - set(EXPECTED))}\n"
        f"missing: {sorted(set(EXPECTED) - set(found))}\n"
        f"changed: {sorted(k for k in found.keys() & EXPECTED.keys() if found[k] != EXPECTED[k])}"
    )
    assert {k for k, v in found.items() if v == "public:"} == PUBLIC


def _seed(world: World) -> dict[str, Any]:
    """Real objects in tenant A, a user without roles and a user scoped to product X."""
    c, tid = world.client, world.tenant_a
    admin = world.login("alice")
    base = f"/api/v1/tenants/{tid}"

    def post(url: str, body: dict[str, Any]) -> dict[str, Any]:
        r = c.post(base + url, json=body, headers=admin)
        assert r.status_code == 201, r.text
        out: dict[str, Any] = r.json()
        return out

    x = post("/products", {"name": "Product X"})["id"]
    y = post("/products", {"name": "Product Y"})["id"]
    api = post(f"/products/{y}/apis", {"name": "Orders", "base_path": "/orders"})["id"]
    key = post(f"/products/{y}/api-keys", {"name": "ci"})["id"]
    truststore = post("/tls/truststores", {"name": "ca", "certificates": _CA.pem()})["id"]
    keystore = post(
        "/tls/keystores",
        {
            "name": "ks",
            "certificate_chain": _CA.pem(),
            "private_key": x509.private_key_pem(_CA_KEY),
        },
    )["id"]
    role = post("/roles", {"name": "Custom", "permissions": ["product:read"]})["id"]
    roles = {r["name"]: r["id"] for r in c.get(base + "/roles", headers=admin).json()}
    nobody = post(
        "/users", {"username": "nobody", "password": PASSWORD, "must_change_password": False}
    )["id"]
    scoped = post(
        "/users", {"username": "scoped", "password": PASSWORD, "must_change_password": False}
    )["id"]
    grant = post(f"/users/{scoped}/roles", {"role_id": roles["ProductOwner"], "product_id": x})
    ids = {
        "tenant_id": tid,
        "product_id": y,
        "api_id": api,
        "key_id": key,
        "truststore_id": truststore,
        "keystore_id": keystore,
        "profile_id": post("/tls/profiles", {"name": "p"})["id"],
        "role_id": role,
        "user_id": nobody,
        "assignment_id": grant["id"],
    }
    return {"ids": ids, "x": x, "admin": admin}


@pytest.fixture
def matrix(world: World) -> dict[str, Any]:
    return _seed(world)


def test_unauthenticated_requests_are_refused(world: World, matrix: dict[str, Any]) -> None:
    for (method, path), _access in EXPECTED.items():
        if (method, path) in PUBLIC:
            continue
        status = _call(world.client, method, _fill(path, matrix["ids"]), {})
        assert status == 401, (method, path, status)


def test_missing_permission_and_foreign_tenant_are_refused(
    world: World, matrix: dict[str, Any]
) -> None:
    nobody = world.login("nobody")
    foreign = world.login("bob")  # TenantAdmin of tenant B
    tenant_admin = matrix["admin"]
    checked = 0
    for (method, path), access in EXPECTED.items():
        scope = access.split(":", 1)[0]
        url = _fill(path, matrix["ids"])
        if scope == "platform":
            assert _call(world.client, method, url, tenant_admin) == 403, (method, path)
            checked += 1
        elif scope in ("tenant", "product"):
            assert _call(world.client, method, url, nobody) == 403, (method, path)
            assert _call(world.client, method, url, foreign) == 404, (method, path)
            checked += 1
    assert checked == sum(1 for v in EXPECTED.values() if not v.startswith(("public", "signed")))


def test_product_scoped_grant_does_not_reach_other_products(
    world: World, matrix: dict[str, Any]
) -> None:
    scoped = world.login("scoped")
    ids, x = matrix["ids"], matrix["x"]
    # Control: the grant works for its own product, so the denials below are meaningful.
    own = world.client.get(f"/api/v1/tenants/{ids['tenant_id']}/products/{x}", headers=scoped)
    assert own.status_code == 200, own.text
    product_routes = [k for k in EXPECTED if "{product_id}" in k[1]]
    assert len(product_routes) >= 14
    for method, path in product_routes:
        url = _fill(path, ids)
        if method == "GET":
            control = world.client.get(url, headers=matrix["admin"])
            assert control.status_code == 200, (path, control.status_code)
        status = _call(world.client, method, url, scoped, path)
        assert status in (403, 404), (method, path, status)
